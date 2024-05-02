#[allow(unused_imports)]
mod internal {
    #![allow(clippy::enum_variant_names)]
    #![allow(clippy::unnecessary_lazy_evaluations)]
    #![allow(clippy::useless_conversion)]
    #![allow(clippy::never_loop)]
    #![allow(clippy::uninlined_format_args)]

    include!(concat!(env!("OUT_DIR"), "/configure_me_config.rs"));
}

use internal::*;
use lndk::lnd::LndCfg;
use lndk::{setup_logger, Cfg, LifecycleSignals, LndkOnionMessenger, OfferHandler};
use std::sync::Arc;

#[macro_use]
extern crate configure_me;

#[tokio::main]
async fn main() -> Result<(), ()> {
    let config = Config::including_optional_config_files(&["./lndk.conf"])
        .unwrap_or_exit()
        .0;

    let lnd_args = LndCfg::new(config.address, config.cert, config.macaroon);
    let (shutdown, listener) = triggered::trigger();
    let signals = LifecycleSignals { shutdown, listener };
    let args = Cfg {
        lnd: lnd_args,
        signals,
    };

    let handler = Arc::new(OfferHandler::new());
    setup_logger(config.log_level, config.log_dir)?;

    let messenger = LndkOnionMessenger::new();
    messenger.run(args, Arc::clone(&handler)).await
}
