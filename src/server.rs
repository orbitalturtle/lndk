use crate::lnd::{get_lnd_client, get_network, LndCfg};
use crate::lndk_offers::get_destination;
use crate::{offers, OfferError, OfferHandler, PayOfferParams};
use bitcoin::secp256k1::PublicKey;
use lightning::offers::offer::Offer;
use offers::offers_server::Offers;
use offers::{PayOfferRequest, PayOfferResponse};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tonic::metadata::MetadataMap;
use tonic::{Request, Response, Status};
use tonic_lnd::lnrpc::GetInfoRequest;
pub struct LNDKServer {
    offer_handler: Arc<OfferHandler>,
    node_id: PublicKey,
}

impl LNDKServer {
    pub async fn new(offer_handler: Arc<OfferHandler>, node_id: &str) -> Self {
        Self {
            offer_handler,
            node_id: PublicKey::from_str(node_id).unwrap(),
        }
    }
}

#[tonic::async_trait]
impl Offers for LNDKServer {
    async fn pay_offer(
        &self,
        request: Request<PayOfferRequest>,
    ) -> Result<Response<PayOfferResponse>, Status> {
        log::info!("Received a request: {:?}", request);

        let metadata = request.metadata();
        let inner_request = request.get_ref();

        let lnd_cfg = check_auth_metadata(metadata)?;
        let mut client = get_lnd_client(lnd_cfg)
            .map_err(|e| Status::unavailable(format!("Couldn't connect to lnd: {e}")))?;

        let offer = Offer::from_str(&inner_request.offer).map_err(|e| {
            Status::invalid_argument(format!(
                "The provided offer was invalid. Please provide a valid offer in bech32 format,
                i.e. starting with 'lno'. Error: {e:?}"
            ))
        })?;

        let destination = get_destination(&offer).await;
        let reply_path = match self
            .offer_handler
            .create_reply_path(client.clone(), self.node_id)
            .await
        {
            Ok(reply_path) => reply_path,
            Err(e) => return Err(Status::internal(format!("Internal error: {e}"))),
        };

        let info = client
            .lightning()
            .get_info(GetInfoRequest {})
            .await
            .expect("failed to get info")
            .into_inner();
        let network = get_network(info)
            .await
            .map_err(|e| Status::internal(format!("{e:?}")))?;

        let cfg = PayOfferParams {
            offer,
            amount: inner_request.amount,
            network,
            client,
            destination,
            reply_path: Some(reply_path),
        };

        let payment = match self.offer_handler.pay_offer(cfg).await {
            Ok(payment) => {
                log::info!("Payment succeeded.");
                payment
            }
            Err(e) => match e {
                OfferError::AlreadyProcessing => {
                    return Err(Status::already_exists(format!("{e}")))
                }
                OfferError::InvalidAmount(e) => {
                    return Err(Status::invalid_argument(e.to_string()))
                }
                OfferError::InvalidCurrency => {
                    return Err(Status::invalid_argument(format!("{e}")))
                }
                _ => return Err(Status::internal(format!("Internal error: {e}"))),
            },
        };

        let reply = PayOfferResponse {
            payment_preimage: payment.payment_preimage,
        };

        Ok(Response::new(reply))
    }
}

// We need to check that the client passes in a tls cert, macaroon, and address,
// so they can connect to LND.
fn check_auth_metadata(metadata: &MetadataMap) -> Result<LndCfg, Status> {
    let tls_cert = match metadata.get("tls_cert_path") {
        Some(tls_cert) => {
            let tls_str = tls_cert.to_str().map_err(|e| {
                Status::invalid_argument(
                    format!("Invalid tls_cert_path string provided: {e}"),
                )
            })?;
            PathBuf::from_str(tls_str).map_err(|e| {
                Status::invalid_argument(
                    format!("Invalid tls_cert_path string provided: {e}"),
                )
            })?
        },
        _ => return Err(Status::unauthenticated(
            "No LND tls_cert_path provided: Make sure to provide tls certificate in request metadata",
        )),
    };

    let macaroon =
        match metadata.get("macaroon_path") {
            Some(mac_path) => {
                let mac_path_str = mac_path.to_str().map_err(|e| {
                    Status::invalid_argument(format!("Invalid macaroon_path string provided: {e}"))
                })?;
                PathBuf::from_str(mac_path_str).map_err(|e| {
                    Status::invalid_argument(format!("Invalid tls_cert_path string provided: {e}"))
                })?
            }
            _ => return Err(Status::unauthenticated(
                "No LND macaroon_path provided: Make sure to provide macaroon in request metadata",
            )),
        };

    let address = match metadata.get("address") {
        Some(address) => address
            .to_str()
            .map_err(|e| Status::invalid_argument(format!("Invalid address string provided: {e}")))?
            .to_owned(),
        _ => {
            return Err(Status::invalid_argument(
                "No LND address provided: Make sure to provide address in request metadata",
            ))
        }
    };

    Ok(LndCfg::new(address, tls_cert, macaroon))
}
