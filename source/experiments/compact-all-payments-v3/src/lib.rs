//! All-arity research caller and isolated PRIVATE worker, never admission.
#[path = "../../compact-payment-proof-v1/src/error.rs"]
mod error;
pub use error::Error;
// This import requires root to apply the reviewed proposed-shared/config.patch.
// No shared source is modified by this experiment's generators.
#[path = "../../compact-payment-proof-v1/src/config.rs"]
mod config;
pub mod engine;
pub mod frame;
#[path = "../../compact-payment-proof-v1/src/metrics.rs"]
pub mod metrics;
pub mod registry;

mod private_packet;
