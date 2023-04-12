use bitcoincore_rpc::{bitcoin::Network, json, RpcApi};
use bitcoind::{BitcoinD, Conf};
use flate2::read::GzDecoder;
use std::{env, env::temp_dir};
use std::path::{Path, PathBuf};
use std::process::Command;
use tar::Archive;

const LND_VERSION: &str = "0.16.0";

// setup_test_infrastructure spins up all of the infrastructure we need to test LNDK, including a bitcoind node and two
// LND nodes. LNDK can then use this test environment to run. 
pub async fn setup_test_infrastructure() {
    let bitcoind_dir = env::temp_dir();

    let _bitcoind = setup_bitcoind(bitcoind_dir).await;

    let _lnd = setup_lnd().await;
}

pub async fn setup_bitcoind(bitcoind_dir: PathBuf) -> BitcoinD {
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

pub async fn setup_lnd() {
    let lnd_exe_dir = download_lnd().await;
    println!("LND_DIR: {}", lnd_exe_dir.display());
    env::set_current_dir(lnd_exe_dir).expect("couldn't set current directory");

    let lnd_dir = temp_dir().join(".lnd");
    let datadir = lnd_dir.join("data");
    let logdir = lnd_dir.join("logs");
    let args = [
        format!("--datadir={}", datadir.display()),
        format!("--logdir={}", logdir.display()),
    ];

    let _output = Command::new("lnd")
        .args(args)
        .output()
        .expect("Failed to execute command");
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn lnd_download_filename() -> String {
    format!("lnd-linux-amd64-v{}-beta.tar.gz", &LND_VERSION)
}

// download_lnd downloads the lnd binary to tmp if it doesn't exist yet. Currently it only downloads binaries
// compatible with the linux os.  
pub async fn download_lnd() -> PathBuf {
    let lnd_dir_name = format!("lnd-linux-amd64-v{}-beta", LND_VERSION);
    let lnd_dir = temp_dir().join(lnd_dir_name);

    if !Path::new(&lnd_dir).is_dir() {
        let lnd_releases_endpoint = "https://github.com/lightningnetwork/lnd/releases/download/v0.16.0-beta";
        let lnd_download_endpoint = format!("{lnd_releases_endpoint}/{}", lnd_download_filename());

        let resp = minreq::get(&lnd_download_endpoint).send().unwrap();
        assert_eq!(resp.status_code, 200, "url {lnd_download_endpoint} didn't return 200");
        let content = resp.as_bytes();

        let decoder = GzDecoder::new(&content[..]);
        let mut archive = Archive::new(decoder);
        let temp_dir = temp_dir();
        archive.unpack(temp_dir.clone()).expect("unable to unpack lnd files");
    }

    lnd_dir
}
