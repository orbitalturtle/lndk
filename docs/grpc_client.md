# gRPC client example

We use a gRPC API for interacting with LNDK. To pay an offer, you'll need to
connect to the LNDK server with a gRPC client, which you can do in any language. [LINK] 

Please note that since LNDK connects to LND, you'll need to pass in your LND
credentials (tls certificate, macaroon, and grpc server address). The client
must pass in this data via gRPC metadata.

An example client in Rust:

```
use offers::offers_client::OffersClient;
use offers::PayOfferRequest;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::Request;

pub mod offers {
    tonic::include_proto!("offers");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let channel = Channel::from_static("http://[::1]:7000").connect().await?;

    let tls_cert_path: MetadataValue<_> =
        "<TLS_CERT_PATH>".parse()?;
    let macaroon_path: MetadataValue<_> =
        "<MACAROON_PATH>".parse()?;
    let address: MetadataValue<_> =
        "<LND_SERVER_ADDRESS>".parse()?;

    let mut client = OffersClient::with_interceptor(channel, move |mut req: Request<()>| {
        req.metadata_mut().insert("tls_cert_path", tls_cert_path.clone());
        req.metadata_mut().insert("macaroon_path", macaroon_path.clone());
        req.metadata_mut().insert("address", address.clone());
        Ok(req)
    });

    let request = tonic::Request::new(PayOfferRequest {
	    offer: "<OFFER>".into(),
        amount: Some(1000 as u64),
    });

    match client.pay_offer(request).await {
        Ok(_) => println!("Successfully paid for offer!"),
        Err(err) => println!("Error paying for offer: {err:?}"),
    };

    Ok(())
}
```
