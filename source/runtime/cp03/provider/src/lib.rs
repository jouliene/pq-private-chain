//! Fixed native CP03 source-signature worker. Public inputs only; not admission.
//! Linux-only research integration under the stable installed-runtime assumptions
//! in README.md. No transaction can select code, context, provider, or executable.
#![cfg(target_os = "linux")]

mod pins;

use sha2::{Digest, Sha256};
use std::{
    fs::{File, Metadata, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, RawFd},
        unix::{fs::{MetadataExt, OpenOptionsExt}, process::CommandExt},
    },
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const SOURCE: &str = include_str!("../embedded/source-signature.mjs");
const SOURCE_HASH: &str = "560d795353d3a6282da3c71b0af3baf5df75ffb702e7c3793a3c944c7565de2f";
const NODE: &str = "/UNINSTALLED/CP03/node";
const KEY_BYTES: usize = 2592;
const MESSAGE_BYTES: usize = 314;
const SIGNATURE_BYTES: usize = 4627;
const REQUEST_BYTES: usize = 7541;
const OUTPUT_BYTES: usize = 64;
const DEADLINE: Duration = Duration::from_secs(5);
const CLEANUP_DEADLINE: Duration = Duration::from_secs(1);
const ADDRESS_SPACE: libc::rlim_t = 4 * 1024 * 1024 * 1024;

/// Payload-free operational failure. Never interpret it as signature invalidity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceOperationalError;
impl std::fmt::Display for SourceOperationalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CP03 source provider unavailable")
    }
}
impl std::error::Error for SourceOperationalError {}
type Result<T> = std::result::Result<T, SourceOperationalError>;
fn operational<T>(value: std::io::Result<T>) -> Result<T> {
    value.map_err(|_| SourceOperationalError)
}

#[derive(PartialEq, Eq)]
struct FileIdentity {
    dev: u64, ino: u64, size: u64, mode: u32, uid: u32, gid: u32,
    mtime: i64, mtime_ns: i64, ctime: i64, ctime_ns: i64,
}
fn identity(meta: Metadata) -> Result<FileIdentity> {
    if !meta.is_file() { return Err(SourceOperationalError); }
    Ok(FileIdentity {
        dev: meta.dev(), ino: meta.ino(), size: meta.len(), mode: meta.mode(),
        uid: meta.uid(), gid: meta.gid(), mtime: meta.mtime(), mtime_ns: meta.mtime_nsec(),
        ctime: meta.ctime(), ctime_ns: meta.ctime_nsec(),
    })
}
fn open_regular(path: &str) -> Result<File> {
    let file = operational(OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(path))?;
    identity(operational(file.metadata())?)?;
    Ok(file)
}
fn hex_hash(hash: &[u8]) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}
struct PinnedFile { path: &'static str, file: File, original: FileIdentity }
impl PinnedFile {
    fn prepare(path: &'static str, expected: &str) -> Result<Self> {
        let mut file = open_regular(path)?;
        let original = identity(operational(file.metadata())?)?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let length = operational(file.read(&mut buffer))?;
            if length == 0 { break; }
            digest.update(&buffer[..length]);
        }
        if hex_hash(&digest.finalize()) != expected
            || identity(operational(file.metadata())?)? != original {
            return Err(SourceOperationalError);
        }
        let pin = Self { path, file, original };
        pin.unchanged()?;
        Ok(pin)
    }
    fn unchanged(&self) -> Result<()> {
        let current_path = open_regular(self.path)?;
        if identity(operational(current_path.metadata())?)? != self.original
            || identity(operational(self.file.metadata())?)? != self.original {
            return Err(SourceOperationalError);
        }
        Ok(())
    }
}

/// Verifier-owned immutable installation. A fresh worker verifies every call;
/// no signature verdict or transaction-supplied code is cached. prepare hashes
/// runtime bytes once; calls enforce the documented stable-file identity guard.
pub struct PreparedSourceVerifier {
    files: Vec<PinnedFile>,
    node_index: usize,
    worker: String,
}
impl PreparedSourceVerifier {
    pub fn prepare() -> Result<Self> {
        if hex_hash(&Sha256::digest(SOURCE.as_bytes())) != SOURCE_HASH {
            return Err(SourceOperationalError);
        }
        let mut files = Vec::with_capacity(pins::NATIVE.len());
        let mut node_index = None;
        for &(path, digest) in pins::NATIVE {
            if path == NODE { node_index = Some(files.len()); }
            files.push(PinnedFile::prepare(path, digest)?);
        }
        let node_index = node_index.ok_or(SourceOperationalError)?;
        Ok(Self { files, node_index, worker: format!("{SOURCE}\nrunPublicWorker();\n") })
    }

    /// pk must be the registered key and message must be reconstructed by the
    /// ledger from canonical statement/registry/installed IDs. No private data.
    /// Ok(false) means a complete fixed INVALID/exit1 verdict, or wrong transport
    /// lengths. Err includes provider drift, timeout, malformed output or cleanup.
    pub fn verify(&self, pk: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        if pk.len() != KEY_BYTES || message.len() != MESSAGE_BYTES || signature.len() != SIGNATURE_BYTES {
            return Ok(false);
        }
        self.unchanged()?;
        let mut request = Vec::with_capacity(REQUEST_BYTES);
        request.extend_from_slice(b"CPAUTH03");
        request.extend_from_slice(pk);
        request.extend_from_slice(message);
        request.extend_from_slice(signature);
        let outcome = self.run(&request);
        // A native/transport verdict cannot override detected runtime drift.
        self.unchanged()?;
        outcome
    }

    fn unchanged(&self) -> Result<()> {
        for pin in &self.files { pin.unchanged()?; }
        Ok(())
    }

    fn run(&self, request: &[u8]) -> Result<bool> {
        let node_fd = self.files[self.node_index].file.as_raw_fd();
        let expected_parent = unsafe { libc::getpid() };
        let mut command = Command::new(format!("/proc/self/fd/{node_fd}"));
        command.args(["--disable-sigusr1", "--input-type=module", "--eval", &self.worker])
            .env_clear().env("PATH", "/usr/bin:/bin").env("LANG", "C")
            .env("LC_ALL", "C").env("TZ", "UTC").current_dir("/")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        // Only async-signal-safe syscalls in the fork child. The held executable
        // fd remains available through execve lookup; ELF execution then closes
        // O_CLOEXEC descriptors. It is not a script needing the fd afterward.
        unsafe {
            command.pre_exec(move || {
                // A separate session is outside the ledger's process group.
                // Kill this worker if its creating parent thread dies, and
                // close the fork-to-prctl race before any native execution.
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong,
                               0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != expected_parent {
                    return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
                }
                if libc::setsid() == -1 { return Err(std::io::Error::last_os_error()); }
                // Preserve stdin/stdout/stderr only after exec. CLOEXEC on the
                // held Node fd still permits the kernel's ELF exec lookup.
                // Fail closed if this Linux syscall is unavailable.
                if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, libc::CLOSE_RANGE_CLOEXEC) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                for (which, value) in [(libc::RLIMIT_CORE, 0), (libc::RLIMIT_AS, ADDRESS_SPACE),
                                       (libc::RLIMIT_CPU, 5), (libc::RLIMIT_NOFILE, 64)] {
                    let limit = libc::rlimit { rlim_cur: value, rlim_max: value };
                    if libc::setrlimit(which, &limit) == -1 { return Err(std::io::Error::last_os_error()); }
                }
                // Do not widen the caller's affinity. Select one allowed CPU.
                let mut mask: libc::cpu_set_t = std::mem::zeroed();
                if libc::sched_getaffinity(0, std::mem::size_of_val(&mask), &mut mask) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                let selected = (0..libc::CPU_SETSIZE as usize).find(|&cpu| libc::CPU_ISSET(cpu, &mask))
                    .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;
                libc::CPU_ZERO(&mut mask);
                libc::CPU_SET(selected, &mut mask);
                if libc::sched_setaffinity(0, std::mem::size_of_val(&mask), &mask) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let started = Instant::now();
        let child = operational(command.spawn())?;
        let mut job = OwnedJob { child, cleanup_attempted: false };
        let io_outcome = exchange(&mut job.child, request, started);
        // Always clean the owned group before reaping its leader, even after a
        // normal/nonzero exit. WNOWAIT below avoids post-reap PID reuse races.
        let status = job.finish()?;
        let stdout = io_outcome?;
        match (status.code(), stdout.as_slice()) {
            (Some(0), b"CPAUTH03 VALID\n") => Ok(true),
            (Some(1), b"CPAUTH03 INVALID\n") => Ok(false),
            (Some(2), b"CPAUTH03 OPERATIONAL\n") => Err(SourceOperationalError),
            _ => Err(SourceOperationalError),
        }
    }
}

fn nonblocking(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(SourceOperationalError);
    }
    Ok(())
}
fn drain(stream: &mut impl Read, output: &mut Vec<u8>) -> Result<bool> {
    let mut buffer = [0u8; OUTPUT_BYTES + 1];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(length) => {
                if output.len() + length > OUTPUT_BYTES { return Err(SourceOperationalError); }
                output.extend_from_slice(&buffer[..length]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(SourceOperationalError),
        }
    }
}
fn leader_exited(pid: u32) -> Result<bool> {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::waitid(libc::P_PID, pid, &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT) };
    if result == -1 { return Err(SourceOperationalError); }
    Ok(unsafe { info.si_pid() } != 0)
}
fn exchange(child: &mut Child, request: &[u8], started: Instant) -> Result<Vec<u8>> {
    let mut input = Some(child.stdin.take().ok_or(SourceOperationalError)?);
    let mut stdout = child.stdout.take().ok_or(SourceOperationalError)?;
    let mut stderr = child.stderr.take().ok_or(SourceOperationalError)?;
    nonblocking(input.as_ref().ok_or(SourceOperationalError)?.as_raw_fd())?;
    nonblocking(stdout.as_raw_fd())?;
    nonblocking(stderr.as_raw_fd())?;
    let mut written = 0;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    loop {
        if started.elapsed() >= DEADLINE { return Err(SourceOperationalError); }
        if let Some(pipe) = input.as_mut() {
            match pipe.write(&request[written..]) {
                Ok(0) => return Err(SourceOperationalError),
                Ok(n) => written += n,
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => {},
                Err(_) => return Err(SourceOperationalError),
            }
            if written == request.len() { input.take(); } // Exact EOF to worker.
        }
        let out_eof = drain(&mut stdout, &mut out)?;
        let err_eof = drain(&mut stderr, &mut err)?;
        if !err.is_empty() { return Err(SourceOperationalError); }
        if leader_exited(child.id())? && out_eof && err_eof {
            if written != request.len() { return Err(SourceOperationalError); }
            return Ok(out);
        }
        thread::sleep(Duration::from_millis(1));
    }
}

struct OwnedJob { child: Child, cleanup_attempted: bool }
impl OwnedJob {
    fn finish(&mut self) -> Result<ExitStatus> {
        if self.cleanup_attempted { return Err(SourceOperationalError); }
        self.cleanup_attempted = true;
        let killed = unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) };
        let kill_ok = killed == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
        let start = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) if kill_ok => return Ok(status),
                Ok(Some(_)) | Err(_) => return Err(SourceOperationalError),
                Ok(None) if start.elapsed() < CLEANUP_DEADLINE => thread::sleep(Duration::from_millis(1)),
                Ok(None) => return Err(SourceOperationalError),
            }
        }
    }
}
impl Drop for OwnedJob {
    fn drop(&mut self) {
        if !self.cleanup_attempted { let _ = self.finish(); }
    }
}
