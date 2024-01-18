mod common;
use lndk;

use bitcoin::secp256k1::PublicKey;
use bitcoin::Network;
use chrono::Utc;
use ldk_sample::node_api::Node as LdkNode;
use lightning::offers::offer::Quantity;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::SystemTime;
use tokio::select;
use tokio::time::{sleep, timeout, Duration};

async fn wait_to_receive_onion_message(
    ldk1: LdkNode,
    ldk2: LdkNode,
    lnd_id: PublicKey,
) -> (LdkNode, LdkNode) {
    let data: Vec<u8> = vec![72, 101, 108, 108, 111];

    let res = ldk1
        .send_onion_message(vec![lnd_id, ldk2.get_node_info().0], 65, data)
        .await;
    assert!(res.is_ok());

    // We need to give lndk time to process the message and forward it to ldk2.
    let ldk2 = match timeout(Duration::from_secs(100), check_for_message(ldk2)).await {
        Err(_) => panic!("ldk2 did not receive onion message before timeout"),
        Ok(ldk2) => ldk2,
    };

    return (ldk1, ldk2);
}

async fn check_for_message(ldk: LdkNode) -> LdkNode {
    loop {
        if ldk.onion_message_handler.messages.lock().unwrap().len() == 1 {
            return ldk;
        }
        sleep(Duration::from_secs(2)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_lndk_forwards_onion_message() {
    let test_name = "lndk_forwards_onion_message";
    let (_bitcoind, mut lnd, ldk1, ldk2, lndk_dir) =
        common::setup_test_infrastructure(test_name).await;

    // Here we'll produce a little path of two channels. Both ldk nodes are connected to lnd like so:
    //
    // ldk1 <-> lnd <-> ldk2
    //
    // Notice that ldk1 and ldk2 are not connected directly to each other.
    let (pubkey, addr) = ldk1.get_node_info();
    let (pubkey_2, addr_2) = ldk2.get_node_info();
    lnd.connect_to_peer(pubkey, addr).await;
    lnd.connect_to_peer(pubkey_2, addr_2).await;
    let lnd_info = lnd.get_info().await;

    // Now we'll spin up lndk. Even though ldk1 and ldk2 are not directly connected, we'll show that lndk
    // successfully helps lnd forward the onion message from ldk1 to ldk2.
    let (shutdown, listener) = triggered::trigger();
    let lnd_cfg = lndk::lnd::LndCfg::new(
        lnd.address,
        PathBuf::from_str(&lnd.cert_path).unwrap(),
        PathBuf::from_str(&lnd.macaroon_path).unwrap(),
    );
    let now_timestamp = Utc::now();
    let timestamp = now_timestamp.format("%d-%m-%Y-%H%M");
    let lndk_cfg = lndk::Cfg {
        lnd: lnd_cfg,
        log_dir: Some(
            lndk_dir
                .join(format!("lndk-logs-{test_name}-{timestamp}"))
                .to_str()
                .unwrap()
                .to_string(),
        ),
        shutdown: shutdown.clone(),
        listener,
    };

    let handler = lndk::OfferHandler::new();
    select! {
        val = handler.run(lndk_cfg) => {
            panic!("lndk should not have completed first {:?}", val);
        },
        // We wait for ldk2 to receive the onion message.
        (ldk1, ldk2) = wait_to_receive_onion_message(ldk1, ldk2, PublicKey::from_str(&lnd_info.identity_pubkey).unwrap()) => {
            shutdown.trigger();
            ldk1.stop().await;
            ldk2.stop().await;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
// Here we test the beginning of the BOLT 12 offers flow. We show that lndk successfully builds an
// invoice_request and sends it.
async fn test_lndk_send_invoice_request() {
    let test_name = "lndk_send_invoice_request";
    let (_bitcoind, mut lnd, ldk1, ldk2, lndk_dir) =
        common::setup_test_infrastructure(test_name).await;

    // Here we'll produce a little network path:
    //
    // ldk1 <-> ldk2 <-> lnd
    //
    // ldk1 will be the offer creator, which will build a blinded route from ldk2 to ldk1.
    let (pubkey, _) = ldk1.get_node_info();
    let (pubkey_2, addr_2) = ldk2.get_node_info();

    println!("OTHER PUB KEY {:?}", pubkey.clone().to_string());

    ldk1.connect_to_peer(pubkey_2, addr_2).await.unwrap();
    lnd.connect_to_peer(pubkey_2, addr_2).await;

    let path_pubkeys = vec![pubkey_2, pubkey];
    let expiration = SystemTime::now() + Duration::from_secs(24 * 60 * 60);
    let offer = ldk1
        .create_offer(
            &path_pubkeys,
            Network::Regtest,
            20_000,
            Quantity::One,
            expiration,
        )
        .await
        .expect("should create offer");

    // Now we'll spin up lndk, which should forward the invoice request to ldk2.
    let (shutdown, listener) = triggered::trigger();
    let lnd_cfg = lndk::lnd::LndCfg::new(
        lnd.address.clone(),
        PathBuf::from_str(&lnd.cert_path).unwrap(),
        PathBuf::from_str(&lnd.macaroon_path).unwrap(),
    );
    let lndk_cfg = lndk::Cfg {
        lnd: lnd_cfg,
        log_dir: Some(
            lndk_dir
                .join(format!("lndk-logs.txt"))
                .to_str()
                .unwrap()
                .to_string(),
        ),
        shutdown: shutdown.clone(),
        listener,
    };

    let client = lnd.client.clone().unwrap();
    let blinded_path = offer.paths()[0].clone();

    // Make sure lndk successfully sends the invoice_request.
    let handler = &mut lndk::OfferHandler::new();
    select! {
        val = handler.run(lndk_cfg.clone()) => {
            panic!("lndk should not have completed first {:?}", val);
        },
        // We wait for ldk2 to receive the onion message.
        res = handler.pay_offer(offer.clone(), Some(20_000), Network::Regtest, client.clone(), blinded_path.clone()) => {
            assert!(res.is_ok());
            shutdown.trigger();
            ldk1.stop().await;
            ldk2.stop().await;
        }
    }
}
