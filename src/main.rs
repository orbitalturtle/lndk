use futures::executor::block_on;
use std::error::Error;
use std::fmt;
use tonic_lnd::{Client, ConnectError};

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(args) => panic!("Bad arguments: {}", args),
    };

    let client = get_lnd_client(args).expect("failed to connect");

    set_feature_bit(client).await
}

fn get_lnd_client(cfg: LndCfg) -> Result<Client, ConnectError> {
    block_on(tonic_lnd::connect(cfg.address, cfg.cert, cfg.macaroon))
}

#[derive(Debug)]
enum ArgsError {
    NoArgs,
    AddressRequired,
    CertRequired,
    MacaroonRequired,
}

impl Error for ArgsError {}

impl fmt::Display for ArgsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ArgsError::NoArgs => write!(f, "No command line arguments provided."),
            ArgsError::AddressRequired => write!(f, "LND's RPC server address is required."),
            ArgsError::CertRequired => write!(f, "Path to LND's tls certificate is required."),
            ArgsError::MacaroonRequired => write!(f, "Path to LND's macaroon is required."),
        }
    }
}

struct LndCfg {
    address: String,
    cert: String,
    macaroon: String,
}

impl LndCfg {
    fn new(address: String, cert: String, macaroon: String) -> LndCfg {
        LndCfg {
            address: address,
            cert: cert,
            macaroon: macaroon,
        }
    }
}

fn parse_args() -> Result<LndCfg, ArgsError> {
    let mut args = std::env::args_os();
    match args.next() {
        None => return Err(ArgsError::NoArgs),
        _ => {}
    };

    let address = match args.next() {
        Some(arg) => arg.into_string().expect("address is not UTF-8"),
        None => return Err(ArgsError::AddressRequired),
    };

    let cert_file = match args.next() {
        Some(arg) => arg.into_string().expect("cert is not UTF-8"),
        None => return Err(ArgsError::CertRequired),
    };

    let macaroon_file = match args.next() {
        Some(arg) => arg.into_string().expect("macaroon is not UTF-8"),
        None => return Err(ArgsError::MacaroonRequired),
    };

    Ok(LndCfg::new(address, cert_file, macaroon_file))
}

/// Sets the onion messaging feature bit (described in this PR: 
/// https://github.com/lightning/bolts/pull/759/), to signal that we support
/// onion messaging. This needs to be done every time we start up, because LND
/// does not currently persist the custom feature bits that are set via the RPC.
async fn set_feature_bit(mut client: Client) {
    let update = tonic_lnd::peersrpc::UpdateFeatureAction {
        action: 0,
        feature_bit: 38,
    };
    let feature_updates = vec![update];
    let address_updates = vec![];

    let resp = client
        .peers()
        .update_node_announcement(tonic_lnd::peersrpc::NodeAnnouncementUpdateRequest {
            feature_updates: feature_updates,
            color: String::from(""),
            alias: String::from(""),
            address_updates: address_updates,
        })
        .await;

    match resp {
        Ok(_) => {
	    println!("Now setting the onion messaging feature bit...");
	},
        Err(status) => {
            if !status.message().contains("invalid add action for bit 38, bit is already set") {
                panic!("error updating node announcement: {:#?}", status) 
	    }
	}
    }

    let info = client
        .lightning()
        .get_info(tonic_lnd::lnrpc::GetInfoRequest {})
        .await
        .expect("failed to get info");

    if !info.into_inner().features.contains_key(&38) {
         panic!("onion messaging feature bit failed to be set")
    }

    println!("Successfully set onion messaging bit");
}
