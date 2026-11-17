//! Root-allocated real-provider controls. Only PUBLIC signed requests are read.
//! Usage: provider_controls PUBLIC_REQUEST_A PUBLIC_REQUEST_B
//! Both requests must be genuine signatures on the same message, by distinct keys.
use cp03_source_provider::PreparedSourceVerifier;
use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt, path::Path, time::Instant};

const BYTES: usize = 7541;
const KEY_END: usize = 2600;
const MESSAGE_END: usize = 2914;
type Result<T> = std::result::Result<T, ()>;

fn request(path: &Path) -> Result<Vec<u8>> {
    let file = OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path).map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file() || metadata.len() != BYTES as u64 { return Err(()); }
    let mut bytes = Vec::with_capacity(BYTES + 1);
    file.take((BYTES + 1) as u64).read_to_end(&mut bytes).map_err(|_| ())?;
    if bytes.len() != BYTES || &bytes[..8] != b"CPAUTH03" { return Err(()); }
    Ok(bytes)
}

struct Sample { user: f64, system: f64, child_user: f64, child_system: f64, self_peak: i64, child_peak: i64 }
fn sample() -> Result<Sample> {
    let mut own: libc::rusage = unsafe { std::mem::zeroed() };
    let mut children: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut own) } != 0
        || unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut children) } != 0 { return Err(()); }
    let seconds = |v: libc::timeval| v.tv_sec as f64 + v.tv_usec as f64 / 1_000_000.;
    let s = Sample { user: seconds(own.ru_utime), system: seconds(own.ru_stime),
        child_user: seconds(children.ru_utime), child_system: seconds(children.ru_stime),
        self_peak: own.ru_maxrss, child_peak: children.ru_maxrss };
    if [s.user, s.system, s.child_user, s.child_system].iter().any(|v| !v.is_finite() || *v < 0.)
        || s.self_peak <= 0 || s.child_peak < 0 { return Err(()); }
    Ok(s)
}
struct Measurement { wall: f64, own_user: f64, own_system: f64, child_user: f64, child_system: f64, self_peak: i64, child_peak: i64 }
fn measured<T>(op: impl FnOnce() -> Result<T>) -> Result<(T, Measurement)> {
    let started = Instant::now();
    let before = sample()?;
    let result = op()?;
    let after = sample()?;
    let measurement = Measurement { wall: started.elapsed().as_secs_f64(),
        own_user: after.user - before.user, own_system: after.system - before.system,
        child_user: after.child_user - before.child_user, child_system: after.child_system - before.child_system,
        self_peak: after.self_peak, child_peak: after.child_peak };
    if [measurement.wall, measurement.own_user, measurement.own_system,
        measurement.child_user, measurement.child_system].iter().any(|v| !v.is_finite() || *v < 0.) { return Err(()); }
    Ok((result, measurement))
}
impl Measurement {
    fn json(&self) -> String {
        // Fixed field names and validated numeric values only; no input/provider payload.
        format!("{{\"wall_seconds\":{},\"self_user_seconds\":{},\"self_system_seconds\":{},\"waited_child_user_seconds\":{},\"waited_child_system_seconds\":{},\"cumulative_self_maxrss_kib\":{},\"cumulative_waited_child_maxrss_kib\":{}}}",
            self.wall, self.own_user, self.own_system, self.child_user, self.child_system, self.self_peak, self.child_peak)
    }
}

fn run() -> Result<String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 { return Err(()); }
    let a = request(Path::new(&args[0]))?;
    let b = request(Path::new(&args[1]))?;
    let (pk_a, message, sig_a) = (&a[8..KEY_END], &a[KEY_END..MESSAGE_END], &a[MESSAGE_END..]);
    let (pk_b, message_b, sig_b) = (&b[8..KEY_END], &b[KEY_END..MESSAGE_END], &b[MESSAGE_END..]);
    if message != message_b || pk_a == pk_b || sig_a == sig_b { return Err(()); }
    let (provider, preparation) = measured(|| PreparedSourceVerifier::prepare().map_err(|_| ()))?;
    let mut controls = Vec::new();
    let mut check = |name: &'static str, pk: &[u8], msg: &[u8], sig: &[u8], expected: bool, native: bool| -> Result<()> {
        let (got, metric) = measured(|| provider.verify(pk, msg, sig).map_err(|_| ()))?;
        if got != expected { return Err(()); }
        controls.push(format!("{{\"name\":\"{name}\",\"passed\":true,\"native_worker_expected\":{native},\"expected_valid\":{expected},\"measurement\":{}}}", metric.json()));
        Ok(())
    };
    check("genuine_valid_a", pk_a, message, sig_a, true, true)?;
    check("genuine_valid_b", pk_b, message, sig_b, true, true)?;
    check("different_registered_key", pk_b, message, sig_a, false, true)?;
    let mut bad = sig_a.to_vec(); bad[0] ^= 1;
    check("corrupt_signature", pk_a, message, &bad, false, true)?;
    check("short_key", &pk_a[1..], message, sig_a, false, false)?;
    check("short_message", pk_a, &message[1..], sig_a, false, false)?;
    check("short_signature", pk_a, message, &sig_a[1..], false, false)?;
    let mut suffix = sig_a.to_vec(); suffix.push(0);
    check("signature_suffix", pk_a, message, &suffix, false, false)?;
    drop(check);
    if controls.len() != 8 { return Err(()); }
    drop(provider);
    Ok(format!("{{\"format\":\"CP03-ACTUAL-PROVIDER-CONTROLS02\",\"preparation\":{},\"controls\":[{}],\"private_input\":false,\"payment_or_issuance_admission\":false,\"operational_fault_injection\":false,\"scope\":\"public files read before timing; CPU self plus separately waited workers; RSS counters cumulative, not per-call or simultaneous tree; provider destruction outside preparation/verification samples\"}}", preparation.json(), controls.join(",")))
}

fn main() {
    std::panic::set_hook(Box::new(|_| eprintln!("CP03_PROVIDER_CONTROL_PANIC")));
    match run() {
        Ok(result) => println!("{result}"),
        Err(()) => { eprintln!("CP03_PROVIDER_CONTROLS_FAILED"); std::process::exit(1); }
    }
}
