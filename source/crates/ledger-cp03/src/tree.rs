//! Incremental depth-40 public commitment tree; absent leaves are eight zero fields.
use crate::{
    Error, Result,
    encoding::{Digest, field_bytes, fields, integer},
};
use compact_arities_v3::hash;
use rusqlite::{Connection, OptionalExtension, params};
pub const DEPTH: usize = 40;
pub const CAPACITY: u64 = 1u64 << DEPTH;
pub fn node(chain: &[u8; 32], level: usize, left: &Digest, right: &Digest) -> Digest {
    let mut v = vec![level as u64];
    v.extend(left);
    v.extend(right);
    hash::hash(chain, hash::NODE, &v)
}
pub fn empty(chain: &[u8; 32]) -> [Digest; 41] {
    let mut out = [[0; 8]; 41];
    for d in 0..40 {
        out[d + 1] = node(chain, d, &out[d], &out[d]);
    }
    out
}
pub fn get(db: &Connection, empty: &[Digest; 41], level: usize, index: u64) -> Result<Digest> {
    if level > 40 || index >= (1u64 << (40 - level)) {
        return Err(Error::Capacity);
    }
    let value: Option<Vec<u8>> = db
        .query_row(
            "SELECT value FROM nodes WHERE level=?1 AND idx=?2",
            params![level as i64, integer(index)?],
            |r| r.get(0),
        )
        .optional()?;
    match value {
        Some(v) => fields(&v),
        None => Ok(empty[level]),
    }
}
fn put(db: &Connection, height: u64, level: usize, index: u64, value: &Digest) -> Result<()> {
    let old: Option<Vec<u8>> = db
        .query_row(
            "SELECT value FROM nodes WHERE level=?1 AND idx=?2",
            params![level as i64, integer(index)?],
            |r| r.get(0),
        )
        .optional()?;
    db.execute(
        "INSERT OR IGNORE INTO node_undo(height,level,idx,old_value) VALUES(?1,?2,?3,?4)",
        params![integer(height)?, level as i64, integer(index)?, old],
    )?;
    db.execute("INSERT INTO nodes(level,idx,value) VALUES(?1,?2,?3) ON CONFLICT(level,idx) DO UPDATE SET value=excluded.value",params![level as i64,integer(index)?,field_bytes(value)])?;
    Ok(())
}
pub fn append(
    db: &Connection,
    chain: &[u8; 32],
    empty: &[Digest; 41],
    height: u64,
    index: u64,
    origin: &Digest,
    cm: &Digest,
) -> Result<Digest> {
    if index >= CAPACITY {
        return Err(Error::Capacity);
    }
    let mut v = origin.to_vec();
    v.extend(cm);
    let leaf = hash::hash(chain, hash::LEAF, &v);
    put(db, height, 0, index, &leaf)?;
    let mut at = index;
    for level in 0..40 {
        at >>= 1;
        let left = get(db, empty, level, at * 2)?;
        let right = get(db, empty, level, at * 2 + 1)?;
        put(
            db,
            height,
            level + 1,
            at,
            &node(chain, level, &left, &right),
        )?;
    }
    get(db, empty, 40, 0)
}
pub fn restore(db: &Connection, height: u64) -> Result<()> {
    // At most 32 outputs * 41 touched nodes; first preimage per block is retained.
    let mut stmt = db.prepare(
        "SELECT level,idx,old_value FROM node_undo WHERE height=?1 ORDER BY level,idx LIMIT 1313",
    )?;
    let records = stmt
        .query_map([integer(height)?], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Option<Vec<u8>>>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if records.is_empty() || records.len() > 1312 {
        return Err(Error::State);
    }
    drop(stmt);
    for (level, index, old) in records {
        if let Some(value) = old {
            fields(&value)?;
            db.execute("INSERT INTO nodes(level,idx,value) VALUES(?1,?2,?3) ON CONFLICT(level,idx) DO UPDATE SET value=excluded.value",params![level,index,value])?;
        } else {
            db.execute(
                "DELETE FROM nodes WHERE level=?1 AND idx=?2",
                params![level, index],
            )?;
        }
    }
    db.execute("DELETE FROM node_undo WHERE height=?1", [integer(height)?])?;
    Ok(())
}
/// Indexed historical value: first later change retains the value at the requested height.
pub fn at_height(
    db: &Connection,
    empty: &[Digest; 41],
    height: u64,
    level: usize,
    index: u64,
) -> Result<Digest> {
    let old:Option<Option<Vec<u8>>>=db.query_row("SELECT old_value FROM node_undo WHERE level=?1 AND idx=?2 AND height>?3 ORDER BY height LIMIT 1",params![level as i64,integer(index)?,integer(height)?],|r|r.get(0)).optional()?;
    match old {
        Some(Some(b)) => fields(&b),
        Some(None) => Ok(empty[level]),
        None => get(db, empty, level, index),
    }
}
