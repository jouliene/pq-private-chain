//! Public durable state. BEGIN IMMEDIATE serializes parent checks and tentative updates.
use crate::{
    CachePolicy, CacheUsage, Error, EvictionProgress, Result, admission, cache,
    encoding::{self, Digest, Id, field_bytes, fields, id, integer, natural},
    tree,
    trusted::Installed,
};
use compact_arities_v3::statement::MAX;
use cp03_history::{body, genesis, history};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};

#[path = "store_archive.rs"]
mod archive_store;
pub use archive_store::{
    AbortProgress, ArchiveSession, ExportProgress, PendingPublication, ReconcileProgress,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    pub height: u64,
    pub id: Id,
    pub leaf_count: u64,
    pub root: Digest,
    pub fees: u64,
    pub liabilities: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Anchor {
    pub root: Digest,
    pub leaf_count: u64,
}
pub struct Membership {
    pub index: u64,
    pub origin: Digest,
    pub cm: Digest,
    pub siblings: [Digest; 40],
    pub anchor: Anchor,
}
pub struct StoredBlock {
    pub header: Vec<u8>,
    pub bodies: Vec<Vec<u8>>,
}
pub struct AdmittedBlock {
    pub head: Head,
    pub header: Vec<u8>,
    pub body_ids: Vec<Id>,
}
/// Physical verification work, including rejected attempts; never a verdict.
/// RAM-only and intentionally not rolled back with consensus state.
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub struct VerificationAttempts {pub proofs:u64,pub source_signatures:u64}
pub struct Ledger {
    db: Connection,
    db_path: PathBuf,
    db_device: u64,
    db_inode: u64,
    catalog_id: [u8; 32],
    installed: Installed,
    genesis_id: Id,
    total: u64,
    empty: [Digest; 41],
    poisoned: bool,
    last_error: Option<Error>,
}

// Default-off diagnostic stop, never a producer/proof/body selector.
// Only the isolated PUBLIC crash-control build contains this environment branch.
#[cfg(feature = "crash-controls")]
fn crash_control_stop(phase: &'static str) {
    if std::env::var("CP03_LEDGER_CRASH_POINT").ok().as_deref() != Some(phase) {
        return;
    }
    let marker: &[u8] = match phase {
        "before-commit" => b"CP03_CRASH_POINT before-commit\n",
        "after-commit" => b"CP03_CRASH_POINT after-commit\n",
        _ => std::process::exit(126),
    };
    if std::io::stderr().write_all(marker).is_err() {
        std::process::exit(126);
    }
    if unsafe { libc::raise(libc::SIGSTOP) } != 0 {
        std::process::exit(126);
    }
}

/// Explicit transaction result handling: successful rollback permits further use;
/// failed rollback/commit poisons the connection until a fresh durable-store open.
fn transaction<T>(
    db: &mut Connection,
    poisoned: &mut bool,
    last: &mut Option<Error>,
    behavior: TransactionBehavior,
    work: impl FnOnce(&Transaction<'_>) -> Result<T>,
) -> Result<T> {
    if *poisoned {
        return Err(Error::TransactionOutcomeUnknown);
    }
    let tx = {
        #[cfg(feature = "admission-cost-trace")]
        let _cost = crate::cost_trace::span("transaction-begin");
        db.transaction_with_behavior(behavior)?
    };
    *poisoned = true;
    *last = None;
    match work(&tx) {
        Ok(value) => {
            #[cfg(feature = "crash-controls")]
            crash_control_stop("before-commit");
            match {
                #[cfg(feature = "admission-cost-trace")]
                let _cost = crate::cost_trace::span("durable-commit");
                tx.commit()
            } {
                Ok(()) => {
                    #[cfg(feature = "crash-controls")]
                    crash_control_stop("after-commit");
                    *poisoned = false;
                    Ok(value)
                }
                Err(_) => {
                    *last = Some(Error::Storage);
                    Err(Error::TransactionOutcomeUnknown)
                }
            }
        }
        Err(error) => {
            *last = Some(error);
            match {
                #[cfg(feature = "admission-cost-trace")]
                let _cost = crate::cost_trace::span("transaction-rollback");
                tx.rollback()
            } {
                Ok(()) => {
                    *poisoned = false;
                    Err(error)
                }
                Err(_) => Err(Error::RollbackFailed),
            }
        }
    }
}

fn configure(db: &Connection) -> Result<()> {
    db.busy_timeout(Duration::from_millis(0))?; // No hidden retry/latency claim.
    db.pragma_update(None, "foreign_keys", "ON")?;
    db.pragma_update(None, "trusted_schema", "OFF")?;
    let mode: String = db.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
    // Do not inherit WAL: the retained older bundled source has not been
    // qualified for the official 2026 WAL-reset race. No silent database migration.
    if mode != "delete" {
        return Err(Error::Storage);
    }
    db.pragma_update(None, "synchronous", "EXTRA")?;
    // Local suggested pager budget, not a wire/consensus/proof parameter.
    // Keep spilling enabled and preserve DELETE/EXTRA; never trade durability
    // for a method-time target. Negative cache_size is approximate KiB, not RSS.
    db.pragma_update(None, "cache_size", -8192i64)?;
    let cache_size: i64 = db.pragma_query_value(None, "cache_size", |r| r.get(0))?;
    let cache_spill: i64 = db.pragma_query_value(None, "cache_spill", |r| r.get(0))?;
    let sync: i64 = db.pragma_query_value(None, "synchronous", |r| r.get(0))?;
    let fk: i64 = db.pragma_query_value(None, "foreign_keys", |r| r.get(0))?;
    let trusted: i64 = db.pragma_query_value(None, "trusted_schema", |r| r.get(0))?;
    if sync != 3 || fk != 1 || trusted != 0 || cache_size != -8192 || cache_spill <= 0 {
        return Err(Error::Storage);
    }
    Ok(())
}
// Public local namespace identity, not a wallet secret or protocol parameter.
fn new_catalog_id() -> Result<[u8; 32]> {
    let mut value = [0u8; 32];
    let mut used = 0usize;
    while used < value.len() {
        let n =
            unsafe { libc::getrandom(value[used..].as_mut_ptr().cast(), value.len() - used, 0) };
        if n < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(Error::Io);
        }
        if n == 0 {
            return Err(Error::Io);
        }
        used = used.checked_add(n as usize).ok_or(Error::Capacity)?;
    }
    Ok(value)
}
fn local_db_identity(path: &Path) -> Result<(PathBuf, u64, u64)> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(Error::Storage);
    }
    Ok((fs::canonicalize(path)?, metadata.dev(), metadata.ino()))
}

fn open_connection(path: &Path) -> Result<Connection> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(Error::Storage);
    }
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    configure(&db)?;
    Ok(db)
}
fn head(db: &Connection) -> Result<Head> {
    let row = db.query_row(
        "SELECT height,head,leaf_count,root,fees,liabilities FROM meta WHERE singleton=1",
        [],
        |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
            ))
        },
    )?;
    let h = Head {
        height: natural(row.0)?,
        id: id(row.1)?,
        leaf_count: natural(row.2)?,
        root: fields(&row.3)?,
        fees: natural(row.4)?,
        liabilities: natural(row.5)?,
    };
    if h.leaf_count > tree::CAPACITY
        || (database_version(db)?==3 && h.height > h.leaf_count / 2)
        || h.fees > MAX
        || h.liabilities > MAX
    {
        return Err(Error::State);
    }
    Ok(h)
}
fn database_version(db:&Connection)->Result<u16>{
    match db.pragma_query_value(None,"user_version",|r|r.get::<_,i64>(0))?{2=>Ok(3),3=>Ok(4),_=>Err(Error::StorageSchemaUnsupported)}
}
fn lengths_at(db:&Connection,height:u64)->Result<Vec<usize>>{
    let mut q=db.prepare("SELECT full_length FROM bodies WHERE height=?1 ORDER BY ordinal LIMIT 129")?;
    let values=q.query_map([integer(height)?],|r|r.get::<_,i64>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
    values.into_iter().map(|x|usize::try_from(x).map_err(|_|Error::State)).collect()
}
fn accounting(h: &Head, total: u64) -> Result<()> {
    if h.fees.checked_add(h.liabilities).ok_or(Error::Accounting)? > total {
        return Err(Error::Accounting);
    }
    Ok(())
}
fn set_head(db: &Connection, h: &Head) -> Result<()> {
    if db.execute("UPDATE meta SET height=?1,head=?2,leaf_count=?3,root=?4,fees=?5,liabilities=?6 WHERE singleton=1",params![integer(h.height)?,h.id.as_slice(),integer(h.leaf_count)?,field_bytes(&h.root),integer(h.fees)?,integer(h.liabilities)?])?!=1{return Err(Error::State)}
    Ok(())
}
fn history_rows(db: &Connection, height: u64) -> Result<StoredBlock> {
    let header: Vec<u8> = db
        .query_row(
            "SELECT header FROM blocks WHERE height=?1",
            [integer(height)?],
            |r| r.get(0),
        )
        .optional()?
        .ok_or(Error::Missing)?;
    let h = history::parse_header(&header)?;
    if h.version()!=database_version(db)?{return Err(Error::Identity)}
    let mut stmt =
        db.prepare("SELECT ordinal,id,full FROM bodies WHERE height=?1 ORDER BY ordinal LIMIT 129")?;
    let rows = stmt
        .query_map([integer(height)?], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Option<Vec<u8>>>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if rows.len() != h.body_ids().len() {
        return Err(Error::State);
    }
    let mut bodies = Vec::new();
    for (j, (ordinal, stored, b)) in rows.into_iter().enumerate() {
        let b = b.ok_or(Error::HistoryUnavailable)?;
        if ordinal != j as i64
            || body::parse_full(&b)?.body_id() != h.body_ids()[j]
            || stored != h.body_ids()[j]
        {
            return Err(Error::State);
        }
        bodies.push(b);
    }
    if h.version()==4&&h.encoded_full_bytes()!=Some(history::network_encoded_size(&bodies.iter().map(Vec::len).collect::<Vec<_>>())?){return Err(Error::State)}
    Ok(StoredBlock { header, bodies })
}
impl Ledger {
    /// Synthetic genesis only. Installed-manifest/provider gates are not bypassed.
    pub fn create(path: &Path, chain: [u8; 32], bytes: &[u8]) -> Result<Self> {
        Self::create_with_archive_policy(path, chain, bytes, CachePolicy::default())
    }
    /// Operator-local raw-cache/archive quotas; never selected by a payment.
    pub fn create_with_archive_policy(
        path: &Path,
        chain: [u8; 32],
        bytes: &[u8],
        policy: CachePolicy,
    ) -> Result<Self> {
        let catalog_id = new_catalog_id()?;
        let version=genesis::version(bytes)?;
        let policy=policy.for_version(version)?;
        let installed = Installed::load_for_version(chain,version)?;
        let parsed = genesis::parse_genesis_for_version(bytes, &installed.syntax,version)?;
        let empty = tree::empty(&chain);
        let initial = Head {
            height: 0,
            id: parsed.genesis_id(),
            leaf_count: 0,
            root: empty[40],
            fees: 0,
            liabilities: parsed.total(),
        };
        // Exclusive file creation never overwrites another store. No private data enters it.
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.sync_all()?;
        drop(file);
        let mut db = open_connection(path)?;
        let (db_path, db_device, db_inode) = local_db_identity(path)?;
        let mut poisoned = false;
        let mut last_error = None;
        transaction(
            &mut db,
            &mut poisoned,
            &mut last_error,
            TransactionBehavior::Immediate,
            |tx| {
                tx.execute_batch(if version==3{include_str!("schema.sql")}else{include_str!("schema-network04.sql")})?;
                let schema=if version==3{2}else{3};
                tx.pragma_update(None, "user_version", schema)?;
                tx.execute("INSERT INTO meta(singleton,schema_version,genesis,genesis_id,chain,total,height,head,leaf_count,root,fees,liabilities) VALUES(1,?6,?1,?2,?3,?4,0,?2,0,?5,0,?4)",params![bytes,initial.id.as_slice(),chain.as_slice(),integer(parsed.total())?,field_bytes(&initial.root),schema])?;
                cache::install(tx, policy, &catalog_id)?;
                // Projection only AFTER the shared exact canonical genesis parser accepted every byte.
                for i in 0..usize::from(parsed.source_count()) {
                    let at = 376 + i * 2648;
                    let entry = bytes.get(at..at + 2648).ok_or(Error::Codec)?;
                    let credit = u64::from_le_bytes(entry[48..56].try_into().unwrap());
                    tx.execute("INSERT INTO sources(id,credit,public_key,consumed_height) VALUES(?1,?2,?3,NULL)",params![&entry[..48],integer(credit)?,&entry[56..]])?;
                }
                tx.execute(
                    "INSERT INTO anchors(height,root,leaf_count) VALUES(0,?1,0)",
                    [field_bytes(&initial.root)],
                )?;
                Ok(())
            },
        )?;
        // New directory entry durability is distinct from SQLite's transactional fsync.
        fs::File::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()?;
        Ok(Self {
            db,
            db_path,
            db_device,
            db_inode,
            catalog_id,
            installed,
            genesis_id: initial.id,
            total: parsed.total(),
            empty,
            poisoned: false,
            last_error: None,
        })
    }
    /// Opens trusted local durable storage, never a producer-supplied snapshot/acceptance cache.
    pub fn open(path: &Path, chain: [u8; 32]) -> Result<Self> {
        let mut db = open_connection(path)?;
        let prefix:Vec<u8>=db.query_row("SELECT substr(genesis,1,12) FROM meta WHERE singleton=1",[],|r|r.get(0))?;
        let chain_version=genesis::version(&prefix)?;
        let installed=Installed::load_for_version(chain,chain_version)?;
        let (db_path, db_device, db_inode) = local_db_identity(path)?;
        let empty = tree::empty(&chain);
        let (genesis_id, total, catalog_id) = {
            let tx = db.transaction_with_behavior(TransactionBehavior::Deferred)?;
            let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
            if version != if chain_version==3{2}else{3} { return Err(Error::StorageSchemaUnsupported); }
            let (bytes,stored_id,stored_chain,total):(Vec<u8>,Vec<u8>,Vec<u8>,i64)=tx.query_row("SELECT genesis,genesis_id,chain,total FROM meta WHERE singleton=1 AND schema_version=?1 AND length(genesis)<=?2",params![version,genesis::GENESIS_MAX as i64],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
            let catalog_bytes: Vec<u8> = tx.query_row(
                "SELECT catalog_id FROM body_cache WHERE singleton=1",
                [],
                |r| r.get(0),
            )?;
            let catalog_id: [u8; 32] = catalog_bytes.try_into().map_err(|_| Error::State)?;
            cache::usage(&tx)?;
            let parsed = genesis::parse_genesis_for_version(&bytes, &installed.syntax,chain_version)?;
            if stored_id != parsed.genesis_id()
                || stored_chain != chain
                || natural(total)? != parsed.total()
            {
                return Err(Error::Identity);
            }
            let h = head(&tx)?;
            accounting(&h, parsed.total())?;
            // Bounded registry readback against the already parsed immutable genesis.
            let mut registry = tx.prepare(
                "SELECT id,credit,public_key,consumed_height FROM sources ORDER BY id LIMIT 129",
            )?;
            let records = registry
                .query_map([], |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, Option<i64>>(3)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(registry);
            if records.len() != usize::from(parsed.source_count()) {
                return Err(Error::State);
            }
            let mut liabilities = 0u64;
            for (i, (source, credit, key, consumed)) in records.iter().enumerate() {
                let entry = &bytes[376 + i * 2648..376 + (i + 1) * 2648];
                let amount = u64::from_le_bytes(entry[48..56].try_into().unwrap());
                if source.as_slice() != &entry[..48]
                    || natural(*credit)? != amount
                    || key.as_slice() != &entry[56..]
                {
                    return Err(Error::State);
                }
                match consumed {
                    Some(at) if *at <= 0 || natural(*at)? > h.height => return Err(Error::State),
                    Some(_) => (),
                    None => {
                        liabilities = liabilities.checked_add(amount).ok_or(Error::Accounting)?
                    }
                }
            }
            if liabilities != h.liabilities {
                return Err(Error::State);
            }
            if tree::get(&tx, &empty, 40, 0)? != h.root {
                return Err(Error::State);
            }
            if h.height == 0 {
                if h.id != parsed.genesis_id()
                    || h.leaf_count != 0
                    || h.fees != 0
                    || h.liabilities != parsed.total()
                {
                    return Err(Error::State);
                }
            } else {
                let header: Vec<u8> = tx.query_row(
                    "SELECT header FROM blocks WHERE height=?1",
                    [integer(h.height)?],
                    |r| r.get(0),
                )?;
                let parsed = history::parse_header(&header)?;
                if parsed.version()!=chain_version{return Err(Error::Identity)}
                let fields=history::UnverifiedBlockFields {
                    chain,
                    parent: header[44..108].try_into().map_err(|_| Error::State)?,
                    height: h.height,
                    leaf_count: h.leaf_count,
                    root: h.root,
                    fee_escrow: h.fees,
                    unconsumed_liabilities: h.liabilities,
                    body_ids: parsed.body_ids().to_vec(),
                };
                let rebuilt=if chain_version==3{history::encode_unverified_header(&fields)?}else{
                    let lengths=lengths_at(&tx,h.height)?;
                    if lengths.len()!=parsed.body_ids().len(){return Err(Error::State)}
                    history::encode_network_header(&fields,history::network_encoded_size(&lengths)?)?
                };
                if parsed.block_id() != h.id || rebuilt != header {
                    return Err(Error::State);
                }
            }
            tx.commit()?;
            (parsed.genesis_id(), parsed.total(), catalog_id)
        };
        Ok(Self {
            db,
            db_path,
            db_device,
            db_inode,
            catalog_id,
            installed,
            genesis_id,
            total,
            empty,
            poisoned: false,
            last_error: None,
        })
    }
    pub fn head(&self) -> Result<Head> {
        self.ready()?;
        head(&self.db)
    }
    fn ready(&self) -> Result<()> {
        if self.poisoned {
            Err(Error::TransactionOutcomeUnknown)
        } else {
            Ok(())
        }
    }
    pub fn last_operation_error(&self) -> Option<Error> {
        self.last_error
    }
    pub fn read_body<R: Read>(reader: R) -> Result<Vec<u8>> {
        Ok(body::read_full(reader)?)
    }
    pub fn append_local_block(&mut self, bodies: &[Vec<u8>]) -> Result<AdmittedBlock> {
        self.apply(bodies, None)
    }
    /// Local validation is identical; supplied canonical header must equal all derived effects.
    pub fn apply_expected_block(
        &mut self,
        header: &[u8],
        bodies: &[Vec<u8>],
    ) -> Result<AdmittedBlock> {
        self.apply(bodies, Some(header))
    }
    fn apply(&mut self, bodies: &[Vec<u8>], expected: Option<&[u8]>) -> Result<AdmittedBlock> {
        let version=self.installed.version;
        if (version==3&&!(1..=16).contains(&bodies.len()))
            || (version==4&&bodies.len()>128)
            || bodies.iter().any(|b| b.len() > cp03_history::BODY_MAX)
        {
            return Err(Error::Capacity);
        }
        if version==4{history::network_encoded_size(&bodies.iter().map(Vec::len).collect::<Vec<_>>())?;}
        let parsed = {
            #[cfg(feature = "admission-cost-trace")]
            let _cost = crate::cost_trace::span("body-parse-and-hashes");
            bodies
                .iter()
                .map(|b| body::parse_full(b))
                .collect::<core::result::Result<Vec<_>, _>>()?
        };
        let incoming_bytes = bodies.iter().try_fold(0u64, |n, b| {
            n.checked_add(b.len() as u64).ok_or(Error::Capacity)
        })?;
        let body_ids = parsed.iter().map(|b| b.body_id()).collect::<Vec<_>>();
        if let Some(bytes) = expected {
            let header = history::parse_header(bytes)?;
            if header.version()!=version||header.body_ids() != body_ids.as_slice() {
                return Err(Error::Block);
            }
        }
        let installed = &self.installed;
        let empty = &self.empty;
        let total = self.total;
        transaction(
            &mut self.db,
            &mut self.poisoned,
            &mut self.last_error,
            TransactionBehavior::Immediate,
            |tx| {
                let parent = head(tx)?;
                accounting(&parent, total)?;
                let height = parent.height.checked_add(1).ok_or(Error::Capacity)?;
                integer(height)?;
                if let Some(bytes) = expected {
                    if bytes[12..44] != installed.syntax.chain
                        || bytes[44..108] != parent.id
                        || history::parse_header(bytes)?.height() != height
                    {
                        return Err(Error::Block);
                    }
                }
                let next_count = parent
                    .leaf_count
                    .checked_add(2 * bodies.len() as u64)
                    .ok_or(Error::Capacity)?;
                if next_count > tree::CAPACITY {
                    return Err(Error::Capacity);
                }
                cache::reserve(tx, incoming_bytes)?;
                let mut state = parent;
                state.height = height;
                let mut reduced = Vec::new();
                for body in &parsed {
                    // Anchor table is unchanged until EVERY body has passed; tentative consumption is current.
                    admission::verify(tx, installed, parent.leaf_count, body)?;
                    #[cfg(feature = "admission-cost-trace")]
                    let _cost_state = crate::cost_trace::span("state-and-tree");
                    let s = body.prefix().statement();
                    let core = s.core().map_err(|_| Error::Codec)?;
                    tx.execute(
                        "INSERT INTO cores(id,height) VALUES(?1,?2)",
                        params![field_bytes(&core), integer(height)?],
                    )?;
                    for nf in &s.nullifiers {
                        tx.execute(
                            "INSERT INTO nullifiers(id,height) VALUES(?1,?2)",
                            params![field_bytes(nf), integer(height)?],
                        )?;
                    }
                    if let Some(source) = s.source_id {
                        if tx.execute("UPDATE sources SET consumed_height=?1 WHERE id=?2 AND consumed_height IS NULL",params![integer(height)?,source.as_slice()])?!=1{return Err(Error::Source)}
                        state.liabilities = state
                            .liabilities
                            .checked_sub(s.credit)
                            .ok_or(Error::Accounting)?;
                    }
                    state.fees = state.fees.checked_add(s.fee).ok_or(Error::Accounting)?;
                    accounting(&state, total)?;
                    for (j, origin) in s
                        .output_origins()
                        .map_err(|_| Error::Codec)?
                        .iter()
                        .enumerate()
                    {
                        tx.execute("INSERT INTO leaves(idx,origin,cm,height,body_id,ordinal) VALUES(?1,?2,?3,?4,?5,?6)",params![integer(state.leaf_count)?,field_bytes(origin),field_bytes(&s.commitments[j]),integer(height)?,body.body_id().as_slice(),j as i64])?;
                        state.root = tree::append(
                            tx,
                            &s.chain,
                            empty,
                            height,
                            state.leaf_count,
                            origin,
                            &s.commitments[j],
                        )?;
                        state.leaf_count =
                            state.leaf_count.checked_add(1).ok_or(Error::Capacity)?;
                    }
                    reduced.push(body.reduced_bytes()?);
                }
                #[cfg(feature = "admission-cost-trace")]
                let _cost_history = crate::cost_trace::span("history-anchor-meta-writes");
                if state.leaf_count != next_count {
                    return Err(Error::State);
                }
                let fields = history::UnverifiedBlockFields {
                    chain: installed.syntax.chain,
                    parent: parent.id,
                    height,
                    leaf_count: state.leaf_count,
                    root: state.root,
                    fee_escrow: state.fees,
                    unconsumed_liabilities: state.liabilities,
                    body_ids: body_ids.clone(),
                };
                let header=if version==3{history::encode_unverified_header(&fields)?}else{
                    history::encode_network_header(&fields,history::network_encoded_size(&bodies.iter().map(Vec::len).collect::<Vec<_>>())?)?
                };
                if expected.is_some_and(|bytes| bytes != header) {
                    return Err(Error::Block);
                }
                state.id = history::parse_header(&header)?.block_id();
                tx.execute("INSERT INTO blocks(height,id,parent,header,leaf_count,root,fees,liabilities,old_count,old_root,old_fees,old_liabilities) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",params![integer(height)?,state.id.as_slice(),parent.id.as_slice(),&header,integer(state.leaf_count)?,field_bytes(&state.root),integer(state.fees)?,integer(state.liabilities)?,integer(parent.leaf_count)?,field_bytes(&parent.root),integer(parent.fees)?,integer(parent.liabilities)?])?;
                for (j, b) in bodies.iter().enumerate() {
                    tx.execute(
                        "INSERT INTO bodies(height,ordinal,id,full,reduced,full_length) VALUES(?1,?2,?3,?4,?5,?6)",
                        params![
                            integer(height)?,
                            j as i64,
                            body_ids[j].as_slice(),
                            b,
                            &reduced[j],
                            integer(b.len() as u64)?
                        ],
                    )?;
                }
                tx.execute(
                    "INSERT INTO anchors(height,root,leaf_count) VALUES(?1,?2,?3)",
                    params![
                        integer(height)?,
                        field_bytes(&state.root),
                        integer(state.leaf_count)?
                    ],
                )?;
                tx.execute(
                    "DELETE FROM anchors WHERE height<?1",
                    [integer(height.saturating_sub(255))?],
                )?;
                set_head(tx, &state)?;
                Ok(AdmittedBlock {
                    head: state,
                    header,
                    body_ids,
                })
            },
        )
    }
    /// Caller selects canonical history externally. No fork-choice or consensus verdict.
    pub fn rollback_tip(&mut self, expected_tip: Id) -> Result<StoredBlock> {
        self.rollback_tip_prepared(expected_tip, None)
    }

    fn rollback_tip_prepared(
        &mut self,
        expected_tip: Id,
        prepared: Option<archive_store::VerifiedHistorical>,
    ) -> Result<StoredBlock> {
        let genesis_id = self.genesis_id;
        let total = self.total;
        let empty = &self.empty;
        transaction(
            &mut self.db,
            &mut self.poisoned,
            &mut self.last_error,
            TransactionBehavior::Immediate,
            |tx| {
                let tip = head(tx)?;
                if tip.height == 0 || tip.id != expected_tip {
                    return Err(Error::Identity);
                }
                let removed = match prepared {
                    Some(checked) => {
                        checked.recheck(tx, tip.height)?;
                        checked.into_block()
                    }
                    None => history_rows(tx, tip.height)?,
                };
                let row:(Vec<u8>,i64,Vec<u8>,i64,i64)=tx.query_row("SELECT parent,old_count,old_root,old_fees,old_liabilities FROM blocks WHERE height=?1",[integer(tip.height)?],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
                let parent = Head {
                    height: tip.height - 1,
                    id: id(row.0)?,
                    leaf_count: natural(row.1)?,
                    root: fields(&row.2)?,
                    fees: natural(row.3)?,
                    liabilities: natural(row.4)?,
                };
                accounting(&parent, total)?;
                if parent
                    .leaf_count
                    .checked_add(2 * removed.bodies.len() as u64)
                    != Some(tip.leaf_count)
                {
                    return Err(Error::State);
                }
                if parent.height == 0
                    && (parent.id != genesis_id
                        || parent.leaf_count != 0
                        || parent.root != empty[40]
                        || parent.fees != 0
                        || parent.liabilities != total)
                {
                    return Err(Error::State);
                }
                if parent.height > 0 {
                    let previous: Vec<u8> = tx.query_row(
                        "SELECT id FROM blocks WHERE height=?1",
                        [integer(parent.height)?],
                        |r| r.get(0),
                    )?;
                    if previous != parent.id {
                        return Err(Error::State);
                    }
                }
                tree::restore(tx, tip.height,removed.bodies.len()*2)?;
                if tree::get(tx, empty, 40, 0)? != parent.root {
                    return Err(Error::State);
                }
                tx.execute("DELETE FROM leaves WHERE height=?1", [integer(tip.height)?])?;
                tx.execute(
                    "DELETE FROM nullifiers WHERE height=?1",
                    [integer(tip.height)?],
                )?;
                tx.execute("DELETE FROM cores WHERE height=?1", [integer(tip.height)?])?;
                tx.execute(
                    "UPDATE sources SET consumed_height=NULL WHERE consumed_height=?1",
                    [integer(tip.height)?],
                )?;
                tx.execute("DELETE FROM blocks WHERE height=?1", [integer(tip.height)?])?; // cascades both full/reduced body rows
                tx.execute("DELETE FROM anchors", [])?;
                tx.execute("INSERT INTO anchors(height,root,leaf_count) SELECT height,root,leaf_count FROM blocks WHERE height>=?1 AND height<=?2 ORDER BY height",params![integer(parent.height.saturating_sub(255))?,integer(parent.height)?])?;
                if parent.height < 256 {
                    tx.execute(
                        "INSERT INTO anchors(height,root,leaf_count) VALUES(0,?1,0)",
                        [field_bytes(&empty[40])],
                    )?;
                }
                set_head(tx, &parent)?;
                Ok(removed)
            },
        )
    }
    pub fn cache_usage(&self) -> Result<CacheUsage> {
        self.ready()?;
        cache::usage(&self.db)
    }
    /// Explicit bounded maintenance, never hidden inside live payment admission.
    pub fn evict_oldest_step(&mut self) -> Result<EvictionProgress> {
        transaction(
            &mut self.db,
            &mut self.poisoned,
            &mut self.last_error,
            TransactionBehavior::Immediate,
            cache::evict,
        )
    }
    pub fn is_spent(&self, nf: &Digest) -> Result<bool> {
        self.ready()?;
        encoding::fields(&field_bytes(nf))?;
        Ok(self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM nullifiers WHERE id=?1)",
            [field_bytes(nf)],
            |r| r.get(0),
        )?)
    }
    /// An occurrence lookup returns no note value/key. A single read transaction fixes the path.
    pub fn membership(
        &mut self,
        origin: &Digest,
        cm: &Digest,
        anchor: Anchor,
    ) -> Result<Membership> {
        fields(&field_bytes(origin))?;
        fields(&field_bytes(cm))?;
        fields(&field_bytes(&anchor.root))?;
        let chain = self.installed.syntax.chain;
        let empty = &self.empty;
        transaction(
            &mut self.db,
            &mut self.poisoned,
            &mut self.last_error,
            TransactionBehavior::Deferred,
            |tx| {
                let anchor_height: Option<i64> = tx.query_row(
                    "SELECT MAX(height) FROM anchors WHERE root=?1 AND leaf_count=?2",
                    params![field_bytes(&anchor.root), integer(anchor.leaf_count)?],
                    |r| r.get(0),
                )?;
                let at = natural(anchor_height.ok_or(Error::Anchor)?)?;
                let index: Option<i64> = tx
                    .query_row(
                        "SELECT idx FROM leaves WHERE origin=?1 AND cm=?2",
                        params![field_bytes(origin), field_bytes(cm)],
                        |r| r.get(0),
                    )
                    .optional()?;
                let index = natural(index.ok_or(Error::Missing)?)?;
                if index >= anchor.leaf_count {
                    return Err(Error::Anchor);
                }
                membership_path(tx, empty, &chain, at, index, *origin, *cm, anchor)
            },
        )
    }
    /// Public funded index lookup and retained-anchor path in one read snapshot.
    pub fn membership_at(&mut self, index: u64, anchor: Anchor) -> Result<Membership> {
        fields(&field_bytes(&anchor.root))?;
        if index >= anchor.leaf_count || anchor.leaf_count > tree::CAPACITY {
            return Err(Error::Anchor);
        }
        let chain = self.installed.syntax.chain;
        let empty = &self.empty;
        transaction(
            &mut self.db,
            &mut self.poisoned,
            &mut self.last_error,
            TransactionBehavior::Deferred,
            |tx| {
                let at: Option<i64> = tx.query_row(
                    "SELECT MAX(height) FROM anchors WHERE root=?1 AND leaf_count=?2",
                    params![field_bytes(&anchor.root), integer(anchor.leaf_count)?],
                    |r| r.get(0),
                )?;
                let at = natural(at.ok_or(Error::Anchor)?)?;
                let row: Option<(Vec<u8>, Vec<u8>)> = tx
                    .query_row(
                        "SELECT origin,cm FROM leaves WHERE idx=?1",
                        [integer(index)?],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                let (origin, cm) = row.ok_or(Error::Missing)?;
                membership_path(
                    tx,
                    empty,
                    &chain,
                    at,
                    index,
                    fields(&origin)?,
                    fields(&cm)?,
                    anchor,
                )
            },
        )
    }
    pub fn block_version(&self)->u16{self.installed.version}
    pub fn verification_attempts(&self)->VerificationAttempts{
        VerificationAttempts{proofs:self.installed.proof_attempts.load(std::sync::atomic::Ordering::Relaxed),
            source_signatures:self.installed.source_signature_attempts.load(std::sync::atomic::Ordering::Relaxed)}
    }
    pub fn genesis_id(&self) -> Id {
        self.genesis_id
    }
    /// Export one internally captured endpoint using bounded per-frame read transactions.
    /// No database transaction is held across a writer callback. Concurrent append
    /// does not extend the captured endpoint; rollback may make an unread frame unavailable.
    /// Writer data is tentative until Ok; callers must discard partial output on any failure.
    /// The returned endpoint describes a captured local view, not current consensus authority.
    pub fn export_scan<W: Write>(&mut self, writer: &mut W) -> Result<Head> {
        // A failed prior commit/rollback must remain poisoned, with its original cause.
        self.ready()?;
        self.last_error = None;
        let result = (|| {
            let chain = self.installed.syntax.chain;
            let endpoint = self.head()?;
            let mut previous = self.genesis_id;
            let mut count = 0u64;
            for height in 1..=endpoint.height {
                // Header and reduced records share one short read snapshot; owned
                // bytes return only after that transaction successfully ends.
                let frame = self.scan_frame(height)?;
                let block = history::parse_scan_block(&frame[4..])?;
                let header = block.header();
                count = count
                    .checked_add(2 * header.body_ids().len() as u64)
                    .ok_or(Error::Capacity)?;
                if header.height() != height
                    || header.raw()[12..44] != chain
                    || header.raw()[44..108] != previous
                    || header.leaf_count() != count
                {
                    return Err(Error::State);
                }
                previous = header.block_id();
                writer.write_all(&frame)?;
            }
            if previous != endpoint.id || count != endpoint.leaf_count {
                return Err(Error::State);
            }
            writer.flush()?;
            Ok(endpoint)
        })();
        if let Err(error) = &result {
            // scan_frame already retains any uncertain commit/rollback cause.
            // Errors after a successful short read (including Write errors) are
            // recorded without manufacturing a poisoned database connection.
            if !self.poisoned {
                self.last_error = Some(*error);
            }
        }
        result
    }
    pub fn full_block(&mut self, height: u64) -> Result<StoredBlock> {
        transaction(
            &mut self.db,
            &mut self.poisoned,
            &mut self.last_error,
            TransactionBehavior::Deferred,
            |tx| history_rows(tx, height),
        )
    }
    /// One framed scan block only. Consumers independently supply and verify their expected endpoint.
    pub fn scan_frame(&mut self, height: u64) -> Result<Vec<u8>> {
        transaction(
            &mut self.db,
            &mut self.poisoned,
            &mut self.last_error,
            TransactionBehavior::Deferred,
            |tx| scan_frame(tx, height),
        )
    }
}

fn membership_path(
    tx: &Connection,
    empty: &[Digest; 41],
    chain: &[u8; 32],
    at: u64,
    index: u64,
    origin: Digest,
    cm: Digest,
    anchor: Anchor,
) -> Result<Membership> {
    let mut siblings = [[0; 8]; 40];
    for (level, sibling) in siblings.iter_mut().enumerate() {
        *sibling = tree::at_height(tx, empty, at, level, (index >> level) ^ 1)?;
    }
    let mut payload = origin.to_vec();
    payload.extend(cm);
    let mut value = compact_arities_v3::hash::hash(chain, compact_arities_v3::hash::LEAF, &payload);
    for (level, sibling) in siblings.iter().enumerate() {
        value = if (index >> level) & 1 == 0 {
            tree::node(chain, level, &value, sibling)
        } else {
            tree::node(chain, level, sibling, &value)
        };
    }
    if value != anchor.root {
        return Err(Error::State);
    }
    Ok(Membership {
        index,
        origin,
        cm,
        siblings,
        anchor,
    })
}

fn scan_frame(tx: &Connection, height: u64) -> Result<Vec<u8>> {
    let header: Vec<u8> = tx
        .query_row(
            "SELECT header FROM blocks WHERE height=?1",
            [integer(height)?],
            |r| r.get(0),
        )
        .optional()?
        .ok_or(Error::Missing)?;
    let mut statement =
        tx.prepare("SELECT ordinal,reduced FROM bodies WHERE height=?1 ORDER BY ordinal LIMIT 129")?;
    let rows = statement
        .query_map([integer(height)?], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    let parsed_header=history::parse_header(&header)?;
    if parsed_header.version()!=database_version(tx)?{return Err(Error::Identity)}
    if (rows.is_empty()&&parsed_header.version()==3)
        || rows.len() > if parsed_header.version()==3{16}else{128}
        || rows
            .iter()
            .enumerate()
            .any(|(i, (j, b))| *j != i as i64 || b.len() > cp03_history::REDUCED_MAX)
    {
        return Err(Error::State);
    }
    let slices = rows.iter().map(|(_, b)| b.as_slice()).collect::<Vec<_>>();
    let block = history::encode_unverified_scan_block(&header, &slices)?;
    let frame = history::frame_unverified_scan_block(&block)?;
    Ok(frame)
}

// Only the separately compiled PUBLIC diagnostic caller has this local-cache API.
#[cfg(feature = "storage-cost-controls")]
impl Ledger {
    pub fn diagnostic_cache_snapshot(&self) -> Result<crate::CacheSnapshot> {
        self.ready()?;
        crate::storage_cost::snapshot(&self.db)
    }
    pub fn diagnostic_cache_budget(
        &mut self,
        budget: crate::DiagnosticCacheBudget,
    ) -> Result<(crate::CacheSnapshot, crate::CacheSnapshot)> {
        self.ready()?;
        crate::storage_cost::configure(&self.db, budget)
    }
}
