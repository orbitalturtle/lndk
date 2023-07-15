mod clock;
pub mod lnd;
mod onion_messenger;
mod rate_limit;

use crate::lnd::{features_support_onion_messages, get_lnd_client, LndCfg, LndNodeSigner};

use crate::onion_messenger::{run_onion_messenger, MessengerUtilities};
use bitcoin::secp256k1::PublicKey;
use lightning::ln::peer_handler::IgnoringMessageHandler;
use lightning::onion_message::OnionMessenger;
use log::{error, info};
use std::collections::HashMap;
use std::str::FromStr;
use tonic_lnd::lnrpc::GetInfoRequest;

pub async fn run(cfg: LndCfg) -> Result<(), ()> {
    let mut client = get_lnd_client(cfg).expect("failed to connect");

    let info = client
        .lightning()
        .get_info(GetInfoRequest {})
        .await
        .expect("failed to get info")
        .into_inner();

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
        IgnoringMessageHandler {},
    );

    let mut peers_client = client.lightning().clone();
    run_onion_messenger(peer_support, &mut peers_client, onion_messenger).await
}

#[cfg(test)]
mod tests {
    pub mod test_utils;
}