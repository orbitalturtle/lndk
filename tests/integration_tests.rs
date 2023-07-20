mod common;

use bitcoincore_rpc::bitcoin::{Address, Network};
use bitcoincore_rpc::RpcApi;
use futures::try_join;
use std::str::FromStr;
use std::sync::Arc;
use std::{thread, time};

// With this test we'll spin up two ldk nodes, which we'll connect to a lnd node that's wired up to
// lndk. Since the two ldk nodes are not directly connected, this test shows that when using lndk
// with a lightning node, we can successfully forward onion messages.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_setup() {
    let test_name = String::from("test_setup");

    // Spin up a bitcoind and lnd node, which are required for our tests.
    let (
        bitcoind,
        mut lnd,
        _bitcoind_dir,
        _electrsd,
        _electrsd_dir,
        _bitcoind_2,
        _bitcoind_2_dir,
        ldk,
        ldk_2,
    ) = common::setup_test_infrastructure(test_name).await;

    let cfg = lndk::lnd::LndCfg::new(lnd.address.clone(), lnd.cert_path.clone().into(), lnd.macaroon_path.clone().into());

    // At some point need to figure out how to stop this x_X;;; <- I'd like to read about this at a high level.
    // https://www.google.com/search?q=how+to+stop+a+future+from+running+rust&hl=en&sxsrf=AB5stBiwNMk969t6LP7NAj6ptEfWfSWVUQ%3A1689382979361&ei=Q_CxZK7WFfmcptQPqca16Ak&ved=0ahUKEwjug_-Cwo-AAxV5jokEHSljDZ0Q4dUDCA8&uact=5&oq=how+to+stop+a+future+from+running+rust&gs_lp=Egxnd3Mtd2l6LXNlcnAaAhgCIiZob3cgdG8gc3RvcCBhIGZ1dHVyZSBmcm9tIHJ1bm5pbmcgcnVzdDIIECEYFhgeGB1I7hFQ4QFY5RBwBHgBkAEAmAGXAaABtgeqAQMwLji4AQPIAQD4AQHCAgoQABhHGNYEGLADwgIIECEYoAEYiwPCAgUQIRigAcICCBAhGKsCGIsDwgILECEYFhgeGB0YiwPCAgcQIRigARgK4gMEGAAgQYgGAZAGCA&sclient=gws-wiz-serp
    // SHOULD WE SET THIS UP BEFORE? *THINKING*
    //let future = lndk::run(cfg);

    let addr_str = lnd.new_onchain_address().await;
    let address: Address = Address::from_str(&addr_str)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap();
    // ERM WE DONT HAVE TO OPEN A CHANNEL?
    // Mine some bitcoin to lnd wallet so we can open a channel. And also mine 6 blocks to make sure funds are spendable??????
    bitcoind.client.generate_to_address(200, &address).unwrap();

    println!("MEH");

    ldk.node.start().unwrap();

    let two_secs = time::Duration::from_secs(5);
    thread::sleep(two_secs);        

    ldk_2.node.start().unwrap();

    println!("MEH");

    let (node_1_id, node_1_addr) = ldk.get_node_info().await;
    let (node_2_id, node_2_addr) = ldk_2.get_node_info().await;

    println!("NODE1 {} {} {:?}", node_1_id, node_1_addr, ldk.dir);
    println!("NODE2 {} {} {:?}", node_2_id, node_2_addr, ldk_2.dir);

    println!("BOUT TO CONNECT TO PEER");

    lnd.connect_to_peer(node_1_id, node_1_addr).await;
    lnd.connect_to_peer(node_2_id, node_2_addr).await;

    //let peers = ldk.node.list_peers();
    //let lnd_node_id = vec![peers[0].node_id];
    //let tlv_type: u64 = 513;
    //let random_data = "random data".as_bytes().to_vec();

    //println!("SENDING ONION MESSAGE"); 

    //ldk.node.send_onion_message(lnd_node_id, node_2_id, tlv_type, random_data);

    //// After a little time... hopefully we'll find the thingy.
    //thread::sleep(two_secs);

    //let messages = ldk.node.custom_handler.messages.lock().unwrap();
    //println!("MESSAGES: {:?}", messages);
    //std::mem::drop(messages);

    ////let _message = messages.pop_front();

    Arc::new(ldk).stop().await;
    Arc::new(ldk_2).stop().await;
    //try_join!(future);
}
