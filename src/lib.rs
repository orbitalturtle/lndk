mod clock;
#[allow(dead_code)]
pub mod lnd;
pub mod lndk_offers;
pub mod onion_messenger;
mod rate_limit;

use crate::lnd::{
    features_support_onion_messages, get_lnd_client, string_to_network, LndCfg, LndNodeSigner,
};
use crate::lndk_offers::{connect_to_peer, create_invoice_request, validate_amount, OfferError};
use crate::onion_messenger::{run_onion_messenger, MessengerUtilities};
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{Error as Secp256k1Error, PublicKey};
use home::home_dir;
use lightning::blinded_path::BlindedPath;
use lightning::ln::peer_handler::IgnoringMessageHandler;
use lightning::offers::offer::Offer;
use lightning::onion_message::{
    DefaultMessageRouter, Destination, OffersMessage, OffersMessageHandler, OnionMessenger,
    PendingOnionMessage,
};
use log::{error, info, LevelFilter};
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config as LogConfig, Root};
use log4rs::encode::pattern::PatternEncoder;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Once;
use std::sync::Mutex;
use tokio::time::{sleep, Duration};
use tonic_lnd::lnrpc::GetInfoRequest;
use tonic_lnd::Client;
use triggered::{Listener, Trigger};

static INIT: Once = Once::new();

#[derive(Clone)]
pub struct Cfg {
    pub lnd: LndCfg,
    pub log_dir: Option<String>,
    // Use to externally trigger shutdown.
    pub shutdown: Trigger,
    // Used to listen for the signal to shutdown.
    pub listener: Listener,
}

pub fn init_logger(config: LogConfig) {
    INIT.call_once(|| {
        log4rs::init_config(config).expect("failed to initialize logger");
    });
}

#[allow(dead_code)]
pub enum OfferState {
    OfferAdded,
    InvoiceRequestSent,
    InvoiceReceived,
    InvoicePaymentDispatched,
    InvoicePaid,
}

pub struct OfferHandler {
    active_offers: Mutex<HashMap<String, OfferState>>,
    pending_messages: Mutex<Vec<PendingOnionMessage<OffersMessage>>>,
}

impl OfferHandler {
    pub fn new() -> Self {
        OfferHandler {
            active_offers: Mutex::new(HashMap::new()),
            pending_messages: Mutex::new(Vec::new()),
        }
    }

    /// Adds an offer to be paid with the amount specified. May only be called once for a single offer.
    pub async fn pay_offer(
        &self,
        offer: Offer,
        amount: Option<u64>,
        network: Network,
        client: Client,
        blinded_path: BlindedPath,
        reply_path: Option<BlindedPath>,
    ) -> Result<(), OfferError<Secp256k1Error>> {
        sleep(Duration::from_secs(5)).await;

        validate_amount(&offer, amount).await?;

        // For now we connect directly to the introduction node of the blinded path so we don't need any
        // intermediate nodes here. In the future we'll query for a full path to the introduction node for
        // better sender privacy.
        connect_to_peer(
            client.clone(),
            blinded_path.introduction_node_id,
            String::from(""),
        )
        .await?;

        let offer_id = offer.clone().to_string();
        {
            let mut active_offers = self.active_offers.lock().unwrap();
            if active_offers.contains_key(&offer_id.clone()) {
                return Err(OfferError::AlreadyProcessing);
            }
            active_offers.insert(offer.to_string().clone(), OfferState::OfferAdded);
        }

        let invoice_request =
            create_invoice_request(client.clone(), offer, vec![], network, 20000).await?;

        let contents = OffersMessage::InvoiceRequest(invoice_request);
        let pending_message = PendingOnionMessage {
            contents,
            destination: Destination::BlindedPath(blinded_path.clone()),
            reply_path: reply_path,
        };

        let mut pending_messages = self.pending_messages.lock().unwrap();
        pending_messages.push(pending_message);
        std::mem::drop(pending_messages);

        sleep(Duration::from_secs(10)).await;

        let mut active_offers = self.active_offers.lock().unwrap();
        active_offers.insert(offer_id, OfferState::InvoiceRequestSent);

        Ok(())
    }

    pub async fn run(&self, args: Cfg) -> Result<(), ()> {
        let log_dir = args.log_dir.unwrap_or_else(|| {
            home_dir()
                .unwrap()
                .join(".lndk")
                .join("lndk.log")
                .as_path()
                .to_str()
                .unwrap()
                .to_string()
        });

        // Log both to stdout and a log file.
        let stdout = ConsoleAppender::builder().build();
        let lndk_logs = FileAppender::builder()
            .encoder(Box::new(PatternEncoder::new("{d} - {m}{n}")))
            .build(log_dir)
            .unwrap();

        let config = LogConfig::builder()
            .appender(Appender::builder().build("stdout", Box::new(stdout)))
            .appender(Appender::builder().build("lndk_logs", Box::new(lndk_logs)))
            .build(
                Root::builder()
                    .appender("stdout")
                    .appender("lndk_logs")
                    .build(LevelFilter::Info),
            )
            .unwrap();

        init_logger(config);

        let mut client = get_lnd_client(args.lnd).expect("failed to connect");

        let info = client
            .lightning()
            .get_info(GetInfoRequest {})
            .await
            .expect("failed to get info")
            .into_inner();

        let mut network_str = None;
        for chain in info.chains {
            if chain.chain == "bitcoin" {
                network_str = Some(chain.network.clone())
            }
        }

        if network_str.is_none() {
            error!("lnd node is not connected to bitcoin network as expected");
            return Err(());
        }
        let network = string_to_network(&network_str.unwrap());

        let pubkey = PublicKey::from_str(&info.identity_pubkey).unwrap();
        info!("Starting lndk for node: {pubkey}.");

        if !features_support_onion_messages(&info.features) {
            error!("LND must support onion messaging to run LNDK.");
            return Err(());
        }

        // On startup, we want to get a list of our currently online peers to notify the onion messenger that they are
        // connected. This sets up our "start state" for the messenger correctly.
        let current_peers = client
            .lightning()
            .list_peers(tonic_lnd::lnrpc::ListPeersRequest {
                latest_error: false,
            })
            .await
            .map_err(|e| {
                error!("Could not lookup current peers: {e}.");
            })?;

        let mut peer_support = HashMap::new();
        for peer in current_peers.into_inner().peers {
            let pubkey = PublicKey::from_str(&peer.pub_key).unwrap();
            let onion_support = features_support_onion_messages(&peer.features);
            peer_support.insert(pubkey, onion_support);
        }

        // Create an onion messenger that depends on LND's signer client and consume related events.
        let mut node_client = client.signer().clone();
        let node_signer = LndNodeSigner::new(pubkey, &mut node_client);
        let messenger_utils = MessengerUtilities::new();
        let onion_messenger = OnionMessenger::new(
            &messenger_utils,
            &node_signer,
            &messenger_utils,
            &DefaultMessageRouter {},
            self,
            IgnoringMessageHandler {},
        );

        let mut peers_client = client.lightning().clone();
        run_onion_messenger(
            peer_support,
            &mut peers_client,
            onion_messenger,
            network.unwrap(),
            args.shutdown,
            args.listener,
        )
        .await
    }
}

impl OffersMessageHandler for OfferHandler {
    fn handle_message(&self, message: OffersMessage) -> Option<OffersMessage> {
        match message {
            OffersMessage::InvoiceRequest(_) => {
                log::error!("Invoice request received, payment not yet supported.");
                None
            }
            OffersMessage::Invoice(invoice) => {
                println!("WE RECEIVED INVOICE RESPONSE!");

                // PUT THIS LOGIC IN LNDK_OFFERS... SO WE CAN TEST IT. MAYBE MOVE ENTIRE OFFERHANDLER THERE?
                
                // TODO: lookup corresponding invoice request / fail if not known
                // Validate invoice for invoice request
                // Progress state to invoice received
                // Dispatch payment and update state
                None
            }
            OffersMessage::InvoiceError(error) => { 
                log::error!("Invoice error received: {}", error);
		None
            }
        }
    }

    fn release_pending_messages(&self) -> Vec<PendingOnionMessage<OffersMessage>> {
        core::mem::take(&mut self.pending_messages.lock().unwrap())
    }
}

impl Default for OfferHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    pub mod test_utils;
}