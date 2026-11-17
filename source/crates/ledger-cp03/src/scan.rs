//! Backup-only public scan linkage. No local ledger or proof-validity assertion.
use crate::{Result, encoding::Id, trusted::Installed};
use cp03_history::{
    genesis,
    history::{ScanSession, TrustedScanEndpoint},
};
use std::io::{Read, Write};
pub struct CheckedScan {
    genesis: Id,
    height: u64,
    endpoint: Id,
    count: u64,
}
impl CheckedScan {
    pub fn genesis_id(&self) -> Id {
        self.genesis
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn endpoint_id(&self) -> Id {
        self.endpoint
    }
    pub fn leaf_count(&self) -> u64 {
        self.count
    }
}
/// Caller supplies its independently trusted immutable endpoint, never one selected
/// by the stream. All writer bytes are tentative until Ok; discard on any failure.
/// Proof validity, signatures/funding and canonical-history selection are delegated.
pub fn check_scan<R: Read, W: Write>(
    chain: [u8; 32],
    genesis_bytes: &[u8],
    reader: R,
    expected_height: u64,
    expected_id: Id,
    writer: &mut W,
) -> Result<CheckedScan> {
    let version = genesis::version(genesis_bytes)?;
    let syntax = Installed::syntax_for_version(chain, version)?;
    let genesis = genesis::parse_genesis_for_version(genesis_bytes, &syntax, version)?;
    let mut session = ScanSession::new_for_version(
        reader,
        TrustedScanEndpoint {
            chain,
            genesis_id: genesis.genesis_id(),
            expected_height,
            expected_id,
        },
        version,
    )?.with_genesis_state(crate::tree::empty(&chain)[40],genesis.total())?;
    while let Some(block) = session.next_block()? {
        // Exact original checked inner bytes; fixed outer length is uniquely encoded.
        let length = u32::try_from(block.raw().len()).map_err(|_| crate::Error::Capacity)?;
        if let Err(error) = writer
            .write_all(&length.to_le_bytes())
            .and_then(|_| writer.write_all(block.raw()))
        {
            session.abort();
            return Err(error.into());
        }
    }
    let complete = session.finish()?; // Requires exact EOF, including height zero.
    writer.flush()?;
    Ok(CheckedScan {
        genesis: genesis.genesis_id(),
        height: complete.height(),
        endpoint: complete.endpoint_id(),
        count: complete.leaf_count(),
    })
}
