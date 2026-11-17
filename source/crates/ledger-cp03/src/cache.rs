//! Local storage policy, never a payment-validity or consensus parameter.
//! Helpers require the caller's real transaction; no archive acknowledgment is minted here.
use crate::{
    Error, Result,
    encoding::{id, integer, natural},
};
use rusqlite::{Connection, Transaction, params};

pub(crate) const MAX_BATCH: usize = 16;
pub(crate) const MAX_BLOCK_BYTES: u64 = 16 * cp03_history::BODY_MAX as u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachePolicy {
    hard_bytes: u64,
    archive_limit_bytes: u64,
}

impl CachePolicy {
    /// Explicit operator-selected local quotas. They do not allocate disk space.
    pub fn new(hard_bytes: u64, archive_limit_bytes: u64) -> Result<Self> {
        if hard_bytes == 0 || archive_limit_bytes == 0 {
            return Err(Error::Capacity);
        }
        integer(hard_bytes)?;
        integer(archive_limit_bytes)?;
        Ok(Self {
            hard_bytes,
            archive_limit_bytes,
        })
    }

    pub fn hard_bytes(self) -> u64 {
        self.hard_bytes
    }
    pub fn archive_limit_bytes(self) -> u64 {
        self.archive_limit_bytes
    }

    /// A small test/operator quota may be smaller than one maximum-sized block.
    pub fn watermark(self) -> u64 {
        self.hard_bytes.saturating_sub(MAX_BLOCK_BYTES)
    }
}

impl Default for CachePolicy {
    fn default() -> Self {
        // Researcher-selected raw-cache policy. Neither value is an owner traffic
        // limit, a filesystem-capacity claim, or a guaranteed retention duration.
        Self {
            hard_bytes: 4_000_000_000_000,
            archive_limit_bytes: i64::MAX as u64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheUsage {
    pub policy: CachePolicy,
    pub cached_bytes: u64,
    pub unexported_bytes: u64,
    pub archive_committed_bytes: u64,
    pub next_segment: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionProgress {
    AtWatermark,
    PendingExport,
    Freed { rows: u8, bytes: u64 },
}

pub(crate) fn install(
    tx: &Transaction<'_>,
    policy: CachePolicy,
    catalog_id: &[u8; 32],
) -> Result<()> {
    tx.execute(
        "INSERT INTO body_cache(singleton,catalog_id,hard_bytes,cached_bytes,unexported_bytes,archive_limit_bytes,archive_committed_bytes,next_segment) VALUES(1,?3,?1,0,0,?2,0,0)",
        params![integer(policy.hard_bytes)?, integer(policy.archive_limit_bytes)?, catalog_id.as_slice()],
    )?;
    Ok(())
}

pub(crate) fn usage(db: &Connection) -> Result<CacheUsage> {
    let row = db.query_row(
        "SELECT hard_bytes,cached_bytes,unexported_bytes,archive_limit_bytes,archive_committed_bytes,next_segment FROM body_cache WHERE singleton=1",
        [],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?,
                 r.get::<_, i64>(3)?, r.get::<_, i64>(4)?, r.get::<_, i64>(5)?)),
    )?;
    let value = CacheUsage {
        policy: CachePolicy::new(natural(row.0)?, natural(row.3)?)?,
        cached_bytes: natural(row.1)?,
        unexported_bytes: natural(row.2)?,
        archive_committed_bytes: natural(row.4)?,
        next_segment: natural(row.5)?,
    };
    if value.cached_bytes > value.policy.hard_bytes
        || value.unexported_bytes > value.cached_bytes
        || value.archive_committed_bytes > value.policy.archive_limit_bytes
    {
        return Err(Error::State);
    }
    Ok(value)
}

/// A precheck under the same immediate transaction as the subsequent body inserts.
/// INSERT triggers perform the actual reservation/counter updates atomically.
pub(crate) fn reserve(tx: &Transaction<'_>, incoming_bytes: u64) -> Result<()> {
    let current = usage(tx)?;
    if incoming_bytes > MAX_BLOCK_BYTES {
        return Err(Error::Capacity);
    }
    if current
        .cached_bytes
        .checked_add(incoming_bytes)
        .ok_or(Error::Capacity)?
        > current.policy.hard_bytes
    {
        return Err(Error::ArchiveBacklog);
    }
    Ok(())
}

/// Evict only a bounded prefix of oldest cached rows. A missing durable locator
/// stops the prefix; it never permits skipping to a younger exported row.
/// This helper has no file I/O and cannot manufacture an archive catalog entry.
pub(crate) fn evict(tx: &Transaction<'_>) -> Result<EvictionProgress> {
    let before = usage(tx)?;
    let watermark = before.policy.watermark();
    if before.cached_bytes <= watermark {
        return Ok(EvictionProgress::AtWatermark);
    }
    let mut statement = tx.prepare(
        "SELECT b.height,b.ordinal,b.id,b.full_length,EXISTS(SELECT 1 FROM archive_objects a WHERE a.id=b.id AND a.full_length=b.full_length) FROM bodies b WHERE b.full IS NOT NULL ORDER BY b.height,b.ordinal LIMIT 16",
    )?;
    let candidates = statement
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, bool>(4)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    if candidates.is_empty() || candidates.len() > MAX_BATCH {
        return Err(Error::State);
    }
    let mut rows = 0u8;
    let mut bytes = 0u64;
    for (height, ordinal, stored_id, full_length, exported) in candidates {
        if before.cached_bytes.checked_sub(bytes).ok_or(Error::State)? <= watermark {
            break;
        }
        if !exported {
            break;
        }
        if height <= 0 || !(0..16).contains(&ordinal) {
            return Err(Error::State);
        }
        let body_id = id(stored_id)?;
        let length = natural(full_length)?;
        if length == 0 || length > cp03_history::BODY_MAX as u64 {
            return Err(Error::State);
        }
        if tx.execute(
            "UPDATE bodies SET full=NULL WHERE height=?1 AND ordinal=?2 AND id=?3 AND full_length=?4 AND full IS NOT NULL",
            params![height, ordinal, body_id.as_slice(), full_length],
        )? != 1 {
            return Err(Error::State);
        }
        rows = rows.checked_add(1).ok_or(Error::Capacity)?;
        bytes = bytes.checked_add(length).ok_or(Error::Capacity)?;
    }
    let after = usage(tx)?;
    if after.cached_bytes != before.cached_bytes.checked_sub(bytes).ok_or(Error::State)?
        || after.unexported_bytes != before.unexported_bytes
        || after.archive_committed_bytes != before.archive_committed_bytes
        || after.next_segment != before.next_segment
        || after.policy != before.policy
    {
        return Err(Error::State);
    }
    Ok(if rows == 0 {
        EvictionProgress::PendingExport
    } else {
        EvictionProgress::Freed { rows, bytes }
    })
}
