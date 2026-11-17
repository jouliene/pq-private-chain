//! Linux in-process resource sampling. No private/witness/mask values.
use crate::Error;
use serde_json::{Value, json};
pub fn process_self() -> Result<Value, Error> {
    let mut r = core::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: valid writable rusage pointer; Linux writes exactly this ABI struct.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, r.as_mut_ptr()) } != 0 {
        return Err(Error::Resource);
    }
    let r = unsafe { r.assume_init() };
    let seconds = |v: libc::timeval| v.tv_sec as f64 + (v.tv_usec as f64) * 1e-6;
    Ok(
        json!({"cpu_user_seconds_total_until_sample":seconds(r.ru_utime),"cpu_system_seconds_total_until_sample":seconds(r.ru_stime),"peak_rss_kib_until_sample":r.ru_maxrss,"scope":"Linux RUSAGE_SELF entire process/all threads until post-operation sample; final JSON output excluded","units":"seconds and KiB"}),
    )
}
