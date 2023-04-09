use bitcoincore_rpc::{bitcoin::Network, json, RpcApi};
use bitcoind::{BitcoinD, Conf};
use std::env;
use std::path::PathBuf;

// setup_test_infrastructure spins up all of the infrastructure we need to test LNDK, including a bitcoind node and two
// LND nodes, which LNDK requires to run. 
pub fn setup_test_infrastructure() {
    let bitcoind_dir = env::temp_dir();

    let _bitcoind = setup_bitcoind(bitcoind_dir);
}

pub fn setup_bitcoind(bitcoind_dir: PathBuf) -> BitcoinD {
    let mut conf = Conf::default();
    conf.tmpdir = Some(bitcoind_dir);
    let bitcoind = BitcoinD::with_conf(bitcoind::downloaded_exe_path().unwrap(), &conf).unwrap();

    // Mine 101 blocks in our little regtest network so that the funds are spendable.
    // (See https://bitcoin.stackexchange.com/questions/1991/what-is-the-block-maturation-time)
    let address = bitcoind.client.get_new_address(None, Some(json::AddressType::Bech32)).unwrap();
    let address = address.require_network(Network::Regtest).unwrap(); 
    bitcoind
        .client
        .generate_to_address(101, &address)
        .unwrap();

    bitcoind
}
