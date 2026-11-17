//! Minimal CP03 research ledger; acceptance belongs to exact recorded revisions.
//! Every open binds the installed protocol manifest and genuine ML-DSA provider.
//! Private proving and wallet secret/backup handling live outside this public-state crate.
mod admission;
mod archive_io;
mod cache;
mod continuation;
mod encoding;
mod error;
mod scan;
mod store;
mod tree;
mod trusted;
pub use admission::minimum_fee;
pub use archive_io::LocalArchive;
pub use cache::{CachePolicy, CacheUsage, EvictionProgress, Retention};
pub use continuation::{CONTINUATION_HEADER_BYTES, ContinuationReads, ContinuationRequest, StartupHistoryReads};
pub use cp03_history as history_codec;
pub use error::{Error, Result};
pub use store::{
    AbortProgress, AdmittedBlock, Anchor, ArchiveSession, ExportProgress, Head, Ledger, Membership,
    PendingPublication, ReconcileProgress, StoredBlock, VerificationAttempts,
};

pub use scan::{CheckedScan, check_scan};

#[cfg(feature = "admission-cost-trace")]
mod cost_trace;
#[cfg(feature = "admission-cost-trace")]
pub use cost_trace::{CostSample, CostTrace, with_admission_cost_trace};

#[cfg(feature = "storage-cost-controls")]
mod storage_cost;
#[cfg(feature = "storage-cost-controls")]
pub use storage_cost::{CacheSnapshot, DiagnosticCacheBudget};
