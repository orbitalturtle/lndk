use crate::common::ldk_node::disk::FilesystemLogger;
use crate::common::ldk_node::{
    BitcoindClient, ChainMonitor, ChannelManager, NetworkGraph, OnionMessenger, PeerManager,
};

use bitcoin::secp256k1::PublicKey;
use lightning::onion_message::{
    CustomOnionMessageContents, Destination, OnionMessageContents, OnionMessagePath,
};
use lightning::routing::router::DefaultRouter;
use lightning::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringFeeParameters};
use lightning::sign::KeysManager;
use lightning::util::ser::{Writeable, Writer};
use lightning_persister::FilesystemPersister;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub(crate) type Router = DefaultRouter<
    Arc<NetworkGraph>,
    Arc<FilesystemLogger>,
    Arc<Mutex<Scorer>>,
    ProbabilisticScoringFeeParameters,
    Scorer,
>;
pub(crate) type Scorer = ProbabilisticScorer<Arc<NetworkGraph>, Arc<FilesystemLogger>>;

pub(crate) type P2PGossipSyncType = lightning::routing::gossip::P2PGossipSync<
    Arc<NetworkGraph>,
    Arc<BitcoindClient>,
    Arc<FilesystemLogger>,
>;

struct UserOnionMessageContents {
    tlv_type: u64,
    data: Vec<u8>,
}

impl CustomOnionMessageContents for UserOnionMessageContents {
    fn tlv_type(&self) -> u64 {
        self.tlv_type
    }
}

impl Writeable for UserOnionMessageContents {
    fn write<W: Writer>(&self, w: &mut W) -> Result<(), std::io::Error> {
        w.write_all(&self.data)
    }
}

pub struct Node {
    pub(crate) logger: Arc<FilesystemLogger>,
    pub(crate) bitcoind_client: Arc<BitcoindClient>,
    pub(crate) persister: Arc<FilesystemPersister>,
    pub(crate) chain_monitor: Arc<ChainMonitor>,
    pub(crate) keys_manager: Arc<KeysManager>,
    pub(crate) network_graph: Arc<NetworkGraph>,
    pub(crate) router: Arc<Router>,
    pub(crate) scorer: Arc<Mutex<Scorer>>,
    pub(crate) channel_manager: Arc<ChannelManager>,
    pub(crate) gossip_sync: Arc<P2PGossipSyncType>,
    pub(crate) onion_messenger: Arc<OnionMessenger>,
    pub(crate) peer_manager: Arc<PeerManager>,

    // Config values
    pub(crate) listening_port: u16,
}

impl Node {
    // get_node_info retrieves node_id and listening address.
    pub fn get_node_info(&self) -> (PublicKey, SocketAddr) {
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), self.listening_port);
        (self.channel_manager.get_our_node_id(), socket)
    }

    pub async fn connect_to_peer(
        &self,
        pubkey: PublicKey,
        peer_addr: SocketAddr,
    ) -> Result<(), ()> {
        // If we're already connected to peer, then we're good to go.
        for (node_pubkey, _) in self.peer_manager.get_peer_node_ids() {
            if node_pubkey == pubkey {
                return Ok(());
            }
        }
        let res = match self.do_connect_peer(pubkey, peer_addr).await {
            Ok(_) => {
                println!("SUCCESS: connected to peer {}", pubkey);
                Ok(())
            }
            Err(e) => {
                println!("ERROR: failed to connect to peer: {e:?}");
                Err(())
            }
        };
        res
    }

    pub async fn do_connect_peer(
        &self,
        pubkey: PublicKey,
        peer_addr: SocketAddr,
    ) -> Result<(), ()> {
        match lightning_net_tokio::connect_outbound(
            Arc::clone(&self.peer_manager),
            pubkey,
            peer_addr,
        )
        .await
        {
            Some(connection_closed_future) => {
                let mut connection_closed_future = Box::pin(connection_closed_future);
                loop {
                    tokio::select! {
                        _ = &mut connection_closed_future => return Err(()),
                        _ = tokio::time::sleep(Duration::from_millis(10)) => {},
                    };
                    if self
                        .peer_manager
                        .get_peer_node_ids()
                        .iter()
                        .find(|(id, _)| *id == pubkey)
                        .is_some()
                    {
                        return Ok(());
                    }
                }
            }
            None => Err(()),
        }
    }

    pub async fn send_onion_message(
        &self,
        mut intermediate_nodes: Vec<PublicKey>,
        tlv_type: u64,
        data: Vec<u8>,
    ) -> Result<(), ()> {
        if intermediate_nodes.len() == 0 {
            println!("Need to provide pubkey to send onion message");
            return Err(());
        }
        if tlv_type <= 64 {
            println!("Need an integral message type above 64");
            return Err(());
        }
        let destination = Destination::Node(intermediate_nodes.pop().unwrap());
        let message_path = OnionMessagePath {
            intermediate_nodes,
            destination,
        };
        match self.onion_messenger.send_onion_message(
            message_path,
            OnionMessageContents::Custom(UserOnionMessageContents { tlv_type, data }),
            None,
        ) {
            Ok(()) => {
                println!("SUCCESS: forwarded onion message to first hop");
                Ok(())
            }
            Err(e) => {
                println!("ERROR: failed to send onion message: {:?}", e);
                Ok(())
            }
        }
    }
}
