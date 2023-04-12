mod common;

#[tokio::test]
async fn test_setup() {
    println!("MEH");
    // Spin up a Bitcoin node.
    common::setup_test_infrastructure().await;
}
