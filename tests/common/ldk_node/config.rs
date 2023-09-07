use bitcoin::network::constants::Network;
use lightning::ln::msgs::NetAddress;

#[derive(Debug)]
pub struct LdkUserInfo {
    pub(crate) bitcoind_rpc_username: String,
    pub(crate) bitcoind_rpc_password: String,
    pub(crate) bitcoind_rpc_port: u16,
    pub(crate) bitcoind_rpc_host: String,
    pub(crate) ldk_storage_dir_path: String,
    pub(crate) ldk_peer_listening_port: u16,
    pub(crate) ldk_announced_listen_addr: Vec<NetAddress>,
    pub(crate) ldk_announced_node_name: [u8; 32],
    pub(crate) network: Network,
}
