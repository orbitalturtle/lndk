mod common;

#[tokio::test]
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
    ) = common::setup_test_infrastructure(test_name).await;
}
