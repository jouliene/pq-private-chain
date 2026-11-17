//! Schema2/SOURCE03 snapshots, including the immutable body_cache catalog_id.
//! Adapted from executed scan-controls fixture294f2926. All actual rows remain RAM-only.
//! No Debug/Serialize implementation: test failures must use fixed stage labels.
use crate::fixture::{Result, need};
use rusqlite::{Connection, OpenFlags, types::Value as SqlValue};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};
type Rows = Vec<Vec<SqlValue>>;
const TABLES: [(&str, &str); 14] = [
    ("meta", "singleton"),
    ("sources", "id"),
    ("nullifiers", "id"),
    ("cores", "id"),
    ("leaves", "idx"),
    ("nodes", "level,idx"),
    ("anchors", "height"),
    ("blocks", "height"),
    ("bodies", "height,ordinal"),
    ("node_undo", "height,level,idx"),
    ("body_cache", "singleton"),
    ("archive_segments", "segment"),
    ("archive_objects", "id"),
    ("archive_pending", "height,ordinal"),
];
#[derive(PartialEq)]
pub struct Snapshot {
    version: i64,
    schema: Rows,
    tables: Vec<Rows>,
    body_identity: Rows,
}
impl Snapshot {
    /// Exact state failure invariant: all14 rows, schema and user_version, including caches/catalog.
    pub fn all_equal(&self, other: &Self) -> bool {
        self == other
    }
    /// Logical canonical-state comparison against a retained prefix. Deliberately excludes
    /// cached full bytes, body_cache, global archive catalogs and pending export queue.
    /// Those exclusions MUST be checked separately against explicit expected local history.
    pub fn canonical_equal(&self, other: &Self) -> bool {
        self.version == other.version
            && self.schema == other.schema
            && self.tables[..8] == other.tables[..8]
            && self.tables[9] == other.tables[9]
            && self.body_identity == other.body_identity
    }
    pub fn catalog_equal(&self, other: &Self) -> bool {
        self.tables[11] == other.tables[11] && self.tables[12] == other.tables[12]
    }
    pub fn objects(&self) -> usize {
        self.tables[12].len()
    }
    pub fn pending(&self) -> usize {
        self.tables[13].len()
    }
    pub fn row_counts(&self) -> Value {
        Value::Object(
            TABLES
                .iter()
                .zip(&self.tables)
                .map(|((name, _), rows)| ((*name).to_string(), json!(rows.len())))
                .collect(),
        )
    }
}
fn query(c: &Connection, sql: &str, bytes: &mut usize, rows: &mut usize) -> Result<Rows> {
    let mut statement = c.prepare(sql).map_err(|_| "snapshot prepare")?;
    let cols = statement.column_count();
    let mut cursor = statement.query([]).map_err(|_| "snapshot query")?;
    let mut out = Vec::new();
    while let Some(row) = cursor.next().map_err(|_| "snapshot row")? {
        *rows = rows.checked_add(1).ok_or("snapshot count overflow")?;
        need(*rows <= 65536, "fixture row bound")?;
        let mut values = Vec::new();
        for col in 0..cols {
            let v: SqlValue = row.get(col).map_err(|_| "snapshot value")?;
            let size = match &v {
                SqlValue::Blob(b) => b.len(),
                SqlValue::Text(s) => s.len(),
                _ => 8,
            };
            *bytes = bytes.checked_add(size).ok_or("snapshot bytes overflow")?;
            need(*bytes <= 128 * 1024 * 1024, "fixture snapshot byte bound")?;
            values.push(v);
        }
        out.push(values);
    }
    Ok(out)
}
fn open(path: &Path) -> Result<Connection> {
    let c = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| "snapshot open")?;
    c.busy_timeout(Duration::ZERO)
        .map_err(|_| "snapshot timeout")?;
    Ok(c)
}
pub fn snapshot(path: &Path) -> Result<Snapshot> {
    let c = open(path)?;
    c.execute_batch("BEGIN DEFERRED")
        .map_err(|_| "snapshot begin")?;
    let integrity: String = c
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .map_err(|_| "integrity query")?;
    need(integrity == "ok", "integrity")?;
    let (mut bytes, mut rows) = (0, 0);
    need(
        query(&c, "PRAGMA foreign_key_check", &mut bytes, &mut rows)?.is_empty(),
        "foreign keys",
    )?;
    let version = c
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|_| "snapshot version")?;
    need(version == 2, "schema2 snapshot")?;
    let schema = query(
        &c,
        "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name",
        &mut bytes,
        &mut rows,
    )?;
    let tables = TABLES
        .iter()
        .map(|(name, order)| {
            query(
                &c,
                &format!("SELECT * FROM {name} ORDER BY {order}"),
                &mut bytes,
                &mut rows,
            )
        })
        .collect::<Result<_>>()?;
    let body_identity = query(
        &c,
        "SELECT height,ordinal,id,full_length,reduced FROM bodies ORDER BY height,ordinal",
        &mut bytes,
        &mut rows,
    )?;
    c.execute_batch("ROLLBACK").map_err(|_| "snapshot end")?;
    Ok(Snapshot {
        version,
        schema,
        tables,
        body_identity,
    })
}
fn file_observation(path: &Path) -> Result<Value> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(json!({"present":false})),
        Err(_) => Err("physical metadata".into()),
        Ok(m) => {
            need(m.is_file(), "physical regular file")?;
            Ok(
                json!({"present":true,"logical_bytes":m.len(),"allocated_512_byte_blocks":m.blocks()}),
            )
        }
    }
}
/// Quiescent test observation OUTSIDE all Ledger operation clocks. A new readonly connection
/// does not reveal the live Ledger connection's cache/synchronous settings or peak journal size.
pub fn physical(path: &Path) -> Result<Value> {
    let c = open(path)?;
    c.execute_batch("BEGIN DEFERRED")
        .map_err(|_| "physical begin")?;
    let mut numbers = Vec::new();
    for pragma in ["page_size", "page_count", "freelist_count"] {
        let n: i64 = c
            .query_row(&format!("PRAGMA {pragma}"), [], |r| r.get(0))
            .map_err(|_| "physical pragma")?;
        need(n >= 0, "physical nonnegative")?;
        numbers.push(n);
    }
    c.execute_batch("ROLLBACK").map_err(|_| "physical end")?;
    drop(c);
    let sidecar = |suffix: &str| {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        PathBuf::from(name)
    };
    Ok(
        json!({"scope":"quiescent separate readonly observations; not peak or live connection config",
        "page_size":numbers[0],"page_count":numbers[1],"freelist_count":numbers[2],
        "main":file_observation(path)?,"journal":file_observation(&sidecar("-journal"))?,
        "wal":file_observation(&sidecar("-wal"))?}),
    )
}
