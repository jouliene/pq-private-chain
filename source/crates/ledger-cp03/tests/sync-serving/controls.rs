//! Public structural serving controls. Empty canonical history is NOT a proof,
//! expiry, private-wallet or payment-throughput test. Genuine histories are
//! exercised separately through the installed CLI and actual wallet.
use super::*;
use std::{io, sync::atomic::{AtomicU64, Ordering}};

fn setup(db: &Connection, count: u64) -> (Head, Vec<Head>) {
    db.execute_batch("PRAGMA user_version=3; CREATE TABLE meta(singleton INTEGER PRIMARY KEY,
        height INTEGER,head BLOB,leaf_count INTEGER,root BLOB,fees INTEGER,liabilities INTEGER,
        genesis_id BLOB,chain BLOB,total INTEGER);
        CREATE TABLE blocks(height INTEGER PRIMARY KEY,id BLOB,header BLOB);
        CREATE TABLE bodies(height INTEGER,ordinal INTEGER,reduced BLOB,
        PRIMARY KEY(height,ordinal)) WITHOUT ROWID;").unwrap();
    let initial = Head {height: 0, id: [9; 64], leaf_count: 0, root: [0; 8], fees: 0, liabilities: 0};
    let mut heads = vec![initial];
    for height in 1..=count {
        let raw = history::encode_network_header(&history::UnverifiedBlockFields {
            chain: [7; 32], parent: heads.last().unwrap().id, height, leaf_count: 0,
            root: [0; 8], fee_escrow: 0, unconsumed_liabilities: 0, body_ids: vec![],
        }, 228).unwrap();
        let h = continuation_header_cursor(&history::parse_header(&raw).unwrap(), [7; 32], 4).unwrap();
        db.execute("INSERT INTO blocks VALUES(?1,?2,?3)", params![height, h.id.as_slice(), raw]).unwrap();
        heads.push(h);
    }
    let h = heads.last().unwrap();
    db.execute("INSERT INTO meta VALUES(1,?1,?2,0,?3,0,0,?4,?5,0)",
        params![h.height, h.id.as_slice(), field_bytes(&h.root), initial.id.as_slice(), [7u8; 32].as_slice()]).unwrap();
    (initial, heads)
}
fn request(initial: Head, base: Head, target: Head) -> ContinuationRequest {
    ContinuationRequest {block_version: 4, chain: [7; 32], genesis_id: initial.id, base, target}
}
fn serve<W: Write>(db: &mut Connection, initial: Head, request: &ContinuationRequest, writer: &mut W)
    -> (Result<Head>, ContinuationReads) {
    let mut reads = ContinuationReads::default();
    let mut output = CountedWriter {inner: writer, written: 0};
    let mut poisoned = false; let mut last = None;
    let result = transaction(db, &mut poisoned, &mut last, TransactionBehavior::Deferred,
        |tx| continuation_snapshot(tx, request, initial, 4, [7; 32], 0, &mut output, &mut reads));
    reads.response_bytes_written = output.written;
    assert!(!poisoned, "successful read rollback/commit must release the snapshot");
    (result, reads)
}

#[test]
fn sync_serving_fixed_grammar_and_rejections() {
    let initial = Head {height: 0, id: [9; 64], leaf_count: 0, root: [0; 8], fees: 0, liabilities: 0};
    let target = Head {height: 300, id: [4; 64], ..initial};
    let req = request(initial, initial, target); let raw = req.encode().unwrap();
    assert_eq!(raw.len(), 436); assert_eq!(&raw[..8], b"CPHREQ01");
    assert_eq!(u64::from_le_bytes(raw[428..436].try_into().unwrap()), 300);
    assert_eq!(ContinuationRequest::decode(&raw).unwrap(), req);
    assert!(ContinuationRequest::decode(&req.response_header().unwrap()).is_err());
    let mut bad = raw; bad[428] ^= 1; assert!(ContinuationRequest::decode(&bad).is_err());
    let mut bad = raw; bad[188..196].copy_from_slice(&0xffff_ffff_0000_0001u64.to_le_bytes());
    assert!(ContinuationRequest::decode(&bad).is_err());
    let mut bad = raw.to_vec(); bad.push(0); assert!(ContinuationRequest::decode(&bad).is_err());
    let mut bad = request(initial, initial, initial); bad.target.root[0] = 1;
    assert!(bad.encode().is_err());
    let mut bad = req; bad.target.height = u64::MAX; assert!(bad.encode().is_err());
}

#[test]
fn sync_serving_same_head_is_constant_and_reads_no_frames() {
    let mut db = Connection::open_in_memory().unwrap(); let (initial, heads) = setup(&db, 10);
    db.execute("UPDATE blocks SET header=x'00' WHERE height=1", []).unwrap();
    let req = request(initial, heads[10], heads[10]); let mut out = vec![];
    let (result, reads) = serve(&mut db, initial, &req, &mut out);
    assert_eq!(result.unwrap(), heads[10]); assert_eq!(out, req.response_header().unwrap());
    assert_eq!(reads.history_header_rows, 0); assert_eq!(reads.reduced_record_rows, 0);
    assert_eq!(reads.base_header_rows, 1); assert_eq!(reads.target_header_rows, 1);
    assert_eq!(reads.sqlite_fullscan_steps, 0); assert_eq!(reads.response_bytes_written, 436);
}

#[test]
fn sync_serving_direct_range_ignores_unrequested_corrupt_prefix_and_exceeds_256() {
    let mut db = Connection::open_in_memory().unwrap(); let (initial, heads) = setup(&db, 260);
    db.execute("UPDATE blocks SET header=x'00' WHERE height=1", []).unwrap();
    let req = request(initial, heads[2], heads[260]); let mut out = vec![];
    let (result, reads) = serve(&mut db, initial, &req, &mut out);
    assert_eq!(result.unwrap(), heads[260]);
    assert_eq!(reads.history_header_rows, 258); assert_eq!(reads.history_header_bytes, 258 * 216);
    assert_eq!(reads.reduced_record_rows, 0); assert_eq!(reads.sqlite_fullscan_steps, 0);
    assert_eq!(reads.history_frame_bytes, 258 * 232);
    assert_eq!(out.len() as u64, 436 + 258 * 232);
    assert_eq!(reads.response_bytes_written, out.len() as u64);
    let mut at = 436;
    for height in 3..=260 {
        let size = u32::from_le_bytes(out[at..at + 4].try_into().unwrap()) as usize;
        let block = history::parse_scan_block(&out[at + 4..at + 4 + size]).unwrap();
        assert_eq!(block.header().height(), height); at += 4 + size;
    }
    assert_eq!(at, out.len());
}

#[test]
fn sync_serving_wrong_context_and_cursors_publish_nothing() {
    let mut db = Connection::open_in_memory().unwrap(); let (initial, heads) = setup(&db, 3);
    let good = request(initial, heads[1], heads[3]);
    for which in 0..5 {
        let mut req = good;
        match which {0 => req.chain[0] ^= 1, 1 => req.genesis_id[0] ^= 1,
            2 => req.base.id[0] ^= 1, 3 => req.target.root[0] = 1, _ => req.block_version = 3}
        let mut out = vec![]; let (result, reads) = serve(&mut db, initial, &req, &mut out);
        assert!(result.is_err()); assert!(out.is_empty()); assert_eq!(reads.response_bytes_written, 0);
    }
}

struct FailAfter {bytes: Vec<u8>, limit: usize}
impl Write for FailAfter {
    fn write(&mut self, raw: &[u8]) -> io::Result<usize> {
        let n = raw.len().min(self.limit - self.bytes.len());
        if n == 0 { return Err(io::Error::other("public interruption control")); }
        self.bytes.extend_from_slice(&raw[..n]); Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
#[test]
fn sync_serving_writer_interruption_counts_actual_bytes_and_retry_is_clean() {
    let mut db = Connection::open_in_memory().unwrap(); let (initial, heads) = setup(&db, 3);
    let req = request(initial, heads[1], heads[3]);
    let mut failed = FailAfter {bytes: vec![], limit: 450};
    let (result, reads) = serve(&mut db, initial, &req, &mut failed);
    assert_eq!(result.err(), Some(Error::Io)); assert_eq!(reads.response_bytes_written, 450);
    assert_eq!(reads.history_header_rows, 1); assert_eq!(reads.history_frame_bytes, 232);
    let mut retry = vec![]; let (result, reads) = serve(&mut db, initial, &req, &mut retry);
    assert_eq!(result.unwrap(), heads[3]); assert_eq!(reads.history_header_rows, 2);
    assert_eq!(&retry[..450], failed.bytes); assert_eq!(retry.len(), 436 + 2 * 232);
}

#[test]
fn sync_serving_snapshot_blocks_concurrent_replacement_until_completion() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!("cp03-public-sync-serving-{}-{}.sqlite",
        std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    let file = fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap(); drop(file);
    let mut db = Connection::open(&path).unwrap(); let (initial, heads) = setup(&db, 3);
    let other = Connection::open(&path).unwrap(); other.busy_timeout(Duration::ZERO).unwrap();
    struct Replacer {other: Connection, blocked: bool, attempted: bool, bytes: Vec<u8>}
    impl Write for Replacer {
        fn write(&mut self, raw: &[u8]) -> io::Result<usize> {
            if !self.attempted {
                self.attempted = true;
                self.blocked = matches!(self.other.execute("UPDATE blocks SET header=x'00' WHERE height=2", []),
                    Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::DatabaseBusy);
            }
            self.bytes.extend_from_slice(raw); Ok(raw.len())
        }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }
    let mut writer = Replacer {other, blocked: false, attempted: false, bytes: vec![]};
    let (result, reads) = serve(&mut db, initial, &request(initial, heads[1], heads[3]), &mut writer);
    assert_eq!(result.unwrap(), heads[3]); assert!(writer.attempted && writer.blocked);
    assert_eq!(reads.history_header_rows, 2);
    writer.other.execute("UPDATE blocks SET header=x'00' WHERE height=2", []).unwrap();
    drop(writer); drop(db); fs::remove_file(path).unwrap();
}
