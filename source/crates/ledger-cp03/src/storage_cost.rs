//! UNAPPLIED default-off diagnostics on the SAME live Ledger connection.
//! No raw handle escapes; no spill/durability/acceptance policy is disabled.
use crate::{Error, Result};
use rusqlite::Connection;
use libsqlite3_sys as ffi;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticCacheBudget { Unchanged, KiB8192 }
impl DiagnosticCacheBudget {
    pub fn name(self) -> &'static str {
        match self { Self::Unchanged => "current", Self::KiB8192 => "8192kib" }
    }
}
#[derive(Debug, Clone)]
pub struct CacheSnapshot {
    pub sqlite_version_number: i32,
    pub cache_size: i64,
    pub cache_spill_threshold_pages: i64,
    pub page_size: i64,
    pub journal_mode: String,
    pub synchronous: i64,
    pub foreign_keys: i64,
    pub trusted_schema: i64,
    /// Approximate CURRENT pager heap, NOT a highwater/connection/process total.
    pub cache_used_bytes: i32,
    /// Cumulative connection pager counters, resetFlag=0. Never fsync counts.
    pub cache_spills: i32,
    pub cache_writes: i32,
    pub snapshot_sql_queries: u32,
    pub snapshot_db_status_calls: u32,
}
fn status(db: &Connection, op: i32) -> Result<i32> {
    let (mut current, mut highwater) = (0, 0);
    // Connection stays alive, synchronous single-owner call, no statements/rows
    // retained here. Read-only status call; handle is never closed or exported.
    let rc = unsafe { ffi::sqlite3_db_status(db.handle(), op, &mut current, &mut highwater, 0) };
    if rc != ffi::SQLITE_OK || current < 0 || highwater != 0 { return Err(Error::Storage); }
    Ok(current)
}
pub(crate) fn snapshot(db: &Connection) -> Result<CacheSnapshot> {
    if !db.is_autocommit() { return Err(Error::Storage); }
    let value = CacheSnapshot {
        sqlite_version_number: rusqlite::version_number(),
        cache_size: db.pragma_query_value(None, "cache_size", |r| r.get(0))?,
        cache_spill_threshold_pages: db.pragma_query_value(None, "cache_spill", |r| r.get(0))?,
        page_size: db.pragma_query_value(None, "page_size", |r| r.get(0))?,
        journal_mode: db.pragma_query_value(None, "journal_mode", |r| r.get(0))?,
        synchronous: db.pragma_query_value(None, "synchronous", |r| r.get(0))?,
        foreign_keys: db.pragma_query_value(None, "foreign_keys", |r| r.get(0))?,
        trusted_schema: db.pragma_query_value(None, "trusted_schema", |r| r.get(0))?,
        cache_used_bytes: status(db, ffi::SQLITE_DBSTATUS_CACHE_USED)?,
        cache_spills: status(db, ffi::SQLITE_DBSTATUS_CACHE_SPILL)?,
        cache_writes: status(db, ffi::SQLITE_DBSTATUS_CACHE_WRITE)?,
        snapshot_sql_queries: 7,
        snapshot_db_status_calls: 3,
    };
    if value.sqlite_version_number != 3_045_000 || value.cache_size == 0 ||
        value.cache_spill_threshold_pages <= 0 || value.page_size <= 0 ||
        value.journal_mode != "delete" || value.synchronous != 3 ||
        value.foreign_keys != 1 || value.trusted_schema != 0 {
        return Err(Error::Storage);
    }
    Ok(value)
}
pub(crate) fn configure(db: &Connection, budget: DiagnosticCacheBudget) -> Result<(CacheSnapshot, CacheSnapshot)> {
    let before = snapshot(db)?;
    if budget == DiagnosticCacheBudget::KiB8192 {
        // This ONLY changes the local suggested cache budget. CACHE_SPILL remains ON.
        db.pragma_update(None, "cache_size", -8192i64)?;
    }
    let after = snapshot(db)?;
    if before.page_size != after.page_size || before.journal_mode != after.journal_mode ||
        before.synchronous != after.synchronous || before.foreign_keys != after.foreign_keys ||
        before.trusted_schema != after.trusted_schema ||
        (budget == DiagnosticCacheBudget::Unchanged && before.cache_size != after.cache_size) ||
        (budget == DiagnosticCacheBudget::KiB8192 && after.cache_size != -8192) {
        return Err(Error::Storage);
    }
    Ok((before, after))
}
