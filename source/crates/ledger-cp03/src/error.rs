//! Payload-free errors: this library never receives wallet keys or note plaintexts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Storage,
    StorageSchemaUnsupported,
    ArchiveBacklog,
    RetentionPolicy,
    HistoryUnavailable,
    ArchiveCorrupt,
    ArchiveIo,
    ArchiveBusy,
    HistoryHashProvider,
    Io,
    Codec,
    Identity,
    Chain,
    Fee,
    Accounting,
    Capacity,
    Anchor,
    Replay,
    Source,
    Receipt,
    Proof,
    State,
    Block,
    Missing,
    ProtocolManifestUnavailable,
    SourceSignatureProviderUnavailable,
    TransactionOutcomeUnknown,
    RollbackFailed,
}
pub type Result<T> = core::result::Result<T, Error>;
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}
impl From<cp03_history::Error> for Error {
    fn from(error: cp03_history::Error) -> Self {
        match error {
            cp03_history::Error::NativeHistoryHash(_) => Self::HistoryHashProvider,
            cp03_history::Error::Io => Self::Io,
            _ => Self::Codec,
        }
    }
}
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}
