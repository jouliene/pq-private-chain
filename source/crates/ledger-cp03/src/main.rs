//! Local public-artifact CLI. No private witness/key/receipt plaintext intake.
use ledger_cp03::{Anchor, CachePolicy, CONTINUATION_HEADER_BYTES, ContinuationReads,
    ContinuationRequest, Error, Head, Ledger, Result, history_codec};
use serde_json::{Value, json};
use std::{
    env, fs,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn bytes<const N: usize>(text: &str) -> Result<[u8; N]> {
    if text.len() != 2 * N
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Codec);
    }
    let mut out = [0; N];
    for (i, v) in out.iter_mut().enumerate() {
        *v = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| Error::Codec)?;
    }
    Ok(out)
}
fn number(s: &str) -> Result<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return Err(Error::Codec);
    }
    s.parse().map_err(|_| Error::Codec)
}
fn digest(s: &str) -> Result<[u64; 8]> {
    let raw = bytes::<64>(s)?;
    let out =
        core::array::from_fn(|i| u64::from_le_bytes(raw[8 * i..8 * i + 8].try_into().unwrap()));
    if out.iter().any(|v| *v >= 0xffff_ffff_0000_0001) {
        return Err(Error::Codec);
    }
    Ok(out)
}
fn field_hex(v: &[u64; 8]) -> String {
    hex(&v.iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<_>>())
}
/// Linux public CLI file intake, not a generic network-stream timeout.
/// NONBLOCK precedes fstat so a FIFO with no writer cannot block in open.
fn open_regular(path: &Path, cap: Option<usize>) -> Result<fs::File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(Error::Codec);
    }
    if cap.is_some_and(|limit| metadata.len() > limit as u64) {
        return Err(Error::Capacity);
    }
    Ok(file)
}
fn read(path: &Path, cap: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    open_regular(path, Some(cap))?
        .take(cap.checked_add(1).ok_or(Error::Capacity)? as u64)
        .read_to_end(&mut out)?;
    if out.len() > cap {
        return Err(Error::Capacity);
    }
    Ok(out)
}
fn describe(h: Head, genesis: [u8; 64], chain: [u8; 32]) -> Value {
    json!({"schema":"CP03-LEDGER-CLI-01","chain":hex(&chain),"genesis_id":hex(&genesis),
        "height":h.height.to_string(),"block_id":hex(&h.id),"leaf_count":h.leaf_count.to_string(),
        "root_le":field_hex(&h.root),"fee_escrow":h.fees.to_string(),"unconsumed_liabilities":h.liabilities.to_string()})
}
fn describe_version(h:Head,genesis:[u8;64],chain:[u8;32],version:u16)->Value{
    let mut value=describe(h,genesis,chain);
    if version==4{value["block_version"]=json!("4");}value
}
/// Create-only publication in the same directory. No complete marker or stdout on failure.
/// An I/O failure after link/sync may leave the public file; its presence is not a success verdict.
fn publish<T>(path: &Path, write: impl FnOnce(&mut fs::File) -> Result<T>) -> Result<T> {
    let mut name = path.as_os_str().to_owned();
    name.push(".partial");
    let partial = PathBuf::from(name);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)?;
    let result = (|| {
        let endpoint = write(&mut file)?;
        file.sync_all()?;
        fs::hard_link(&partial, path)?;
        fs::remove_file(&partial)?;
        fs::File::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()?;
        Ok(endpoint)
    })();
    if result.is_err() {
        drop(file);
        let _ = fs::remove_file(&partial);
    }
    result
}
fn run() -> Result<Value> {
    // Paths/chain/index/root are public. Never accept a private fixture argument.
    let args = env::args_os().skip(1).take(134).collect::<Vec<_>>();
    if args.len() < 3 || args.len() > 132 {
        return Err(Error::Codec);
    }
    if args[0] == "check-scan" {
        if args.len() != 7 {
            return Err(Error::Codec);
        }
        let chain = bytes::<32>(args[1].to_str().ok_or(Error::Codec)?)?;
        let genesis = read(Path::new(&args[2]), history_codec::genesis::GENESIS_MAX)?;
        // History stays streamed; no global history-byte limit is introduced.
        let scan = open_regular(Path::new(&args[3]), None)?;
        let height = number(args[4].to_str().ok_or(Error::Codec)?)?;
        let id = bytes::<64>(args[5].to_str().ok_or(Error::Codec)?)?;
        let checked = publish(Path::new(&args[6]), |file| {
            ledger_cp03::check_scan(chain, &genesis, scan, height, id, file)
        })?;
        return Ok(
            json!({"schema":"CP03-CHECKED-SCAN-01","validity":"delegated-endpoint-relative","chain":hex(&chain),"genesis_id":hex(&checked.genesis_id()),"height":checked.height().to_string(),"block_id":hex(&checked.endpoint_id()),"leaf_count":checked.leaf_count().to_string()}),
        );
    }
    let op = args[0].to_str().ok_or(Error::Codec)?;
    let path = Path::new(&args[1]);
    let chain = bytes::<32>(args[2].to_str().ok_or(Error::Codec)?)?;
    if op == "scan-range" {
        if args.len() != 5 { return Err(Error::Codec); }
        let request = ContinuationRequest::decode(&read(Path::new(&args[3]), CONTINUATION_HEADER_BYTES)?)?;
        let opened = std::time::Instant::now();
        let (mut ledger, startup) = Ledger::open_counted(path, chain)?;
        let open_nanoseconds = opened.elapsed().as_nanos().to_string();
        let started = std::time::Instant::now();
        let mut reads = ContinuationReads::default();
        let target = publish(Path::new(&args[4]), |file| ledger.export_continuation(&request, file, &mut reads))?;
        return Ok(json!({"schema":"CP04-CONTINUATION-SERVED01",
            "validity":"trusted-local-ledger; caller selects validating endpoint",
            "endpoint":describe_version(target, ledger.genesis_id(), chain, ledger.block_version()),
            "request_bytes":CONTINUATION_HEADER_BYTES,"frame_count":request.frame_count()?.to_string(),
            "startup":{"wall_nanoseconds":open_nanoseconds,"tip_header_rows":startup.tip_header_rows,
                "tip_header_bytes":startup.tip_header_bytes,"tip_body_length_rows":startup.tip_body_length_rows,
                "scope":"Bounded trusted-local open also checks genesis/source registry/cache/tree metadata and installed runtime; not a history prefix scan"},
            "serving":{"wall_nanoseconds":started.elapsed().as_nanos().to_string(),
                "snapshot_meta_rows":reads.snapshot_meta_rows,
                "base_header_rows":reads.base_header_rows,"base_header_bytes":reads.base_header_bytes,
                "target_header_rows":reads.target_header_rows,"target_header_bytes":reads.target_header_bytes,
                "history_header_rows":reads.history_header_rows,"history_header_bytes":reads.history_header_bytes,
                "reduced_record_rows":reads.reduced_record_rows,"reduced_record_bytes":reads.reduced_record_bytes,
                "sqlite_fullscan_steps":reads.sqlite_fullscan_steps,
                "history_frame_bytes":reads.history_frame_bytes,"response_bytes_written":reads.response_bytes_written,
                "scope":"Actual returned SQL history rows/blob bytes and successful writer bytes; metadata separated; not physical page/disk IO"}}));
    }
    if op == "init"||op=="init-retain" {
        if (op=="init"&&args.len()!=4)||(op=="init-retain"&&![4,5].contains(&args.len())) {
            return Err(Error::Codec);
        }
        let genesis = read(Path::new(&args[3]), history_codec::genesis::GENESIS_MAX)?;
        let ledger = if op=="init"{Ledger::create(path, chain, &genesis)?}else{
            let bytes=if args.len()==5{number(args[4].to_str().ok_or(Error::Codec)?)?}else{512*1024*1024};
            Ledger::create_with_archive_policy(path,chain,&genesis,CachePolicy::retaining(bytes)?)?
        };
        return Ok(describe_version(ledger.head()?, ledger.genesis_id(), chain,ledger.block_version()));
    }
    let mut ledger = Ledger::open(path, chain)?;
    let h = match op {
        "head" if args.len() == 3 => ledger.head()?,
        "admit" | "replay" => {
            let start = if op == "replay" { 4 } else { 3 };
            if args.len() < start || (args.len()==start&&ledger.block_version()==3)
                || args.len() - start > if ledger.block_version()==3{16}else{128} {
                return Err(Error::Codec);
            }
            let mut bodies = Vec::new();
            for path in &args[start..] {
                bodies.push(Ledger::read_body(open_regular(
                    Path::new(path),
                    Some(history_codec::BODY_MAX),
                )?)?);
            }
            if op == "replay" {
                let header = read(Path::new(&args[3]), history_codec::HEADER_MAX)?;
                ledger.apply_expected_block(&header, &bodies)?.head
            } else {
                ledger.append_local_block(&bodies)?.head
            }
        }
        "rollback" if args.len() == 4 => {
            ledger.rollback_tip(bytes::<64>(args[3].to_str().ok_or(Error::Codec)?)?)?;
            ledger.head()?
        }
        "membership" if args.len() == 6 => {
            let index = number(args[3].to_str().ok_or(Error::Codec)?)?;
            let count = number(args[4].to_str().ok_or(Error::Codec)?)?;
            let root = digest(args[5].to_str().ok_or(Error::Codec)?)?;
            let m = ledger.membership_at(
                index,
                Anchor {
                    root,
                    leaf_count: count,
                },
            )?;
            return Ok(
                json!({"schema":"CP03-MEMBERSHIP-01","index":m.index.to_string(),"origin_le":field_hex(&m.origin),"cm_le":field_hex(&m.cm),"count":m.anchor.leaf_count.to_string(),"root_le":field_hex(&m.anchor.root),"siblings_le":m.siblings.iter().map(field_hex).collect::<Vec<_>>()}),
            );
        }
        "spent" if args.len() == 4 => {
            let nf = digest(args[3].to_str().ok_or(Error::Codec)?)?;
            return Ok(json!({"schema":"CP03-SPENT-01","spent":ledger.is_spent(&nf)?}));
        }
        "scan" if args.len() == 4 => publish(Path::new(&args[3]), |file| ledger.export_scan(file))?,
        _ => return Err(Error::Codec),
    };
    Ok(describe_version(h, ledger.genesis_id(), chain,ledger.block_version()))
}
fn main() {
    match run() {
        Ok(value) => {
            let output = serde_json::to_vec(&value).expect("fixed public JSON");
            if std::io::stdout()
                .write_all(&output)
                .and_then(|_| std::io::stdout().write_all(b"\n"))
                .is_err()
            {
                std::process::exit(2);
            }
        }
        Err(error) => {
            eprintln!("CP03_LEDGER_ERROR {error:?}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod cli_file_controls {
    use super::*;
    use std::{
        ffi::CString,
        os::unix::{ffi::OsStrExt, fs::symlink},
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct PublicDirectory(PathBuf);
    impl PublicDirectory {
        fn new() -> Self {
            let name = format!(
                "cp03-public-file-control-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            let path = std::env::temp_dir().join(name);
            fs::create_dir(&path).expect("exclusive PUBLIC control directory");
            Self(path)
        }
        fn fifo(&self) -> PathBuf {
            let path = self.0.join("public-fifo");
            let name = CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            path
        }
    }
    impl Drop for PublicDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn rejects_fifo_without_writer_before_reading() {
        let directory = PublicDirectory::new();
        let fifo = directory.fifo();
        assert!(matches!(open_regular(&fifo, None), Err(Error::Codec)));
    }
    #[test]
    fn rejects_fifo_with_nonterminating_writer_before_reading() {
        let directory = PublicDirectory::new();
        let fifo = directory.fifo();
        let _held_writer = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo)
            .unwrap();
        assert!(matches!(open_regular(&fifo, None), Err(Error::Codec)));
    }
    #[test]
    fn rejects_directory_and_symlink() {
        let directory = PublicDirectory::new();
        assert!(matches!(
            open_regular(&directory.0, None),
            Err(Error::Codec)
        ));
        let file = directory.0.join("public-file");
        fs::write(&file, b"PUBLIC").unwrap();
        let link = directory.0.join("public-link");
        symlink(&file, &link).unwrap();
        assert!(matches!(open_regular(&link, None), Err(Error::Io)));
    }
    #[test]
    fn exact_cap_and_streamed_regular_file_preserve_bytes() {
        let directory = PublicDirectory::new();
        let file = directory.0.join("public-file");
        fs::write(&file, b"PUBLIC").unwrap();
        assert_eq!(read(&file, 6).unwrap(), b"PUBLIC");
        assert!(matches!(read(&file, 5), Err(Error::Capacity)));
        let mut stream = open_regular(&file, None).unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"PUBLIC");
    }
}
