mod clock;
#[allow(dead_code)]
pub mod lnd;
pub mod lndk_offers;
pub mod onion_messenger;
mod rate_limit;

use crate::lnd::{
    features_support_onion_messages, get_lnd_client, string_to_network, LndCfg, LndNodeSigner,
};
use crate::lndk_offers::{connect_to_peer, validate_amount, OfferError};
use crate::onion_messenger::MessengerUtilities;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{Error as Secp256k1Error, PublicKey, Secp256k1};
use home::home_dir;
use lightning::blinded_path::BlindedPath;
use lightning::ln::inbound_payment::ExpandedKey;
use lightning::ln::peer_handler::IgnoringMessageHandler;
use lightning::offers::invoice_error::InvoiceError;
use lightning::offers::offer::Offer;
use lightning::onion_message::{
    DefaultMessageRouter, Destination, OffersMessage, OffersMessageHandler, OnionMessenger,
    PendingOnionMessage,
};
use lightning::sign::{EntropySource, KeyMaterial};
use log::{error, info, LevelFilter};
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config as LogConfig, Root};
use log4rs::encode::pattern::PatternEncoder;
use std::cell::RefCell;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Mutex;
use tokio::time::{sleep, Duration};
use tonic_lnd::lnrpc::GetInfoRequest;
use tonic_lnd::Client;
use triggered::{Listener, Trigger};

#[derive(Clone)]
pub struct Cfg {
    pub lnd: LndCfg,
    pub log_dir: Option<String>,
    // Use to externally trigger shutdown.
    pub shutdown: Trigger,
    // Used to listen for the signal to shutdown.
    pub listener: Listener,
}

// MessengerState tells us whether our onion messenger is still starting up is ready to start
// forwarding messages.
#[derive(Debug)]
pub enum MessengerState {
    Starting,
    Ready,
}

pub struct LndkOnionMessenger {
    pub offer_handler: OfferHandler,
}

impl LndkOnionMessenger {
    pub fn new(offer_handler: OfferHandler) -> Self {
        LndkOnionMessenger { offer_handler }
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

        let _log_handle = log4rs::init_config(config);

        let mut client = get_lnd_client(args.lnd).expect("failed to connect");

        let info = client
            .lightning()
            .get_info(GetInfoRequest {})
            .await
            .expect("failed to get info")
            .into_inner();

        let mut network_str = None;
        #[allow(deprecated)]
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
            &self.offer_handler,
            IgnoringMessageHandler {},
        );

        let mut peers_client = client.lightning().clone();
        self.run_onion_messenger(
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
    messenger_utils: MessengerUtilities,
    messenger_state: RefCell<MessengerState>,
    expanded_key: ExpandedKey,
}

impl OfferHandler {
    pub fn new() -> Self {
        let messenger_utils = MessengerUtilities::new();
        let random_bytes = messenger_utils.get_secure_random_bytes();
        let expanded_key = ExpandedKey::new(&KeyMaterial(random_bytes));

        OfferHandler {
            active_offers: Mutex::new(HashMap::new()),
            pending_messages: Mutex::new(Vec::new()),
            messenger_utils: MessengerUtilities::new(),
            messenger_state: RefCell::new(MessengerState::Starting),
            expanded_key,
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
        self.wait_for_ready().await;

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

        let invoice_request = self
            .create_invoice_request(
                client.clone(),
                offer.clone(),
                vec![],
                network,
                amount.unwrap(),
            )
            .await?;

        let contents = OffersMessage::InvoiceRequest(invoice_request);
        let pending_message = PendingOnionMessage {
            contents,
            destination: Destination::BlindedPath(blinded_path.clone()),
            reply_path,
        };

        let mut pending_messages = self.pending_messages.lock().unwrap();
        pending_messages.push(pending_message);
        std::mem::drop(pending_messages);

        let mut active_offers = self.active_offers.lock().unwrap();
        active_offers.insert(offer.to_string().clone(), OfferState::InvoiceRequestSent);

        Ok(())
    }

    /// wait_for_ready waits for our onion messenger to finish starting up.
    pub(crate) async fn wait_for_ready(&self) {
        loop {
            sleep(Duration::from_secs(2)).await;

            match *self.messenger_state.borrow() {
                MessengerState::Starting => continue,
                MessengerState::Ready => break,
            };
        }
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
                let secp_ctx = &Secp256k1::new();
                match invoice.verify(&self.expanded_key, secp_ctx) {
                    // TODO: Eventually we can use the returned payment id below to check if this
                    // payment has been sent twice.
                    Ok(_payment_id) => Some(OffersMessage::Invoice(invoice)),
                    Err(()) => Some(OffersMessage::InvoiceError(InvoiceError::from_string(
                        String::from("invoice verification failure"),
                    ))),
                }
            }
            OffersMessage::InvoiceError(_error) => None,
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
