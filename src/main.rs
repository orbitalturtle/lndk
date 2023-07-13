#[tokio::main]
async fn main() -> Result<(), ()> {
    lndk::run().await
}
