//! UNAPPLIED diagnostic feature: fixed-label wall/CPU spans around REAL work.
//! No acceptance/cache/storage policy switch. A missing metric invalidates only
//! the diagnostic trace; the original method's result is always returned.
use std::{cell::RefCell, time::Instant};

const LIMIT: usize = 512;
#[derive(Debug)]
pub struct CostSample {
    pub phase: &'static str,
    pub wall_seconds: f64,
    /// SELF user/system, then actually waited CHILDREN user/system.
    pub cpu_seconds: Option<[f64; 4]>,
}
#[derive(Debug)]
pub struct CostTrace {
    pub valid: bool,
    pub samples: Vec<CostSample>,
}
thread_local! {
    static ACTIVE: RefCell<Option<CostTrace>> = const { RefCell::new(None) };
}
fn usage() -> Option<[f64; 4]> {
    let mut result = [0.0; 4];
    for (index, who) in [libc::RUSAGE_SELF, libc::RUSAGE_CHILDREN].into_iter().enumerate() {
        let mut value = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        if unsafe { libc::getrusage(who, value.as_mut_ptr()) } != 0 { return None; }
        let value = unsafe { value.assume_init() };
        result[2*index] = value.ru_utime.tv_sec as f64 + value.ru_utime.tv_usec as f64 * 1e-6;
        result[2*index+1] = value.ru_stime.tv_sec as f64 + value.ru_stime.tv_usec as f64 * 1e-6;
    }
    Some(result)
}
pub(crate) struct Span {
    phase: &'static str,
    clock: Option<Instant>,
    cpu: Option<[f64; 4]>,
}
pub(crate) fn span(phase: &'static str) -> Span {
    let enabled = ACTIVE.with(|v| v.borrow().is_some());
    Span { phase, cpu: if enabled { usage() } else { None },
        clock: if enabled { Some(Instant::now()) } else { None } }
}
impl Drop for Span {
    fn drop(&mut self) {
        let Some(clock) = self.clock else { return; };
        let wall_seconds = clock.elapsed().as_secs_f64();
        let cpu_seconds = match (self.cpu, usage()) {
            (Some(before), Some(after)) => {
                let deltas: [f64; 4] = core::array::from_fn(|i| after[i] - before[i]);
                if deltas.iter().all(|v| v.is_finite() && *v >= 0.0) { Some(deltas) } else { None }
            },
            _ => None,
        };
        ACTIVE.with(|v| {
            if let Some(trace) = v.borrow_mut().as_mut() {
                if trace.samples.len() == LIMIT { trace.valid = false; return; }
                if cpu_seconds.is_none() || !wall_seconds.is_finite() { trace.valid = false; }
                trace.samples.push(CostSample { phase: self.phase, wall_seconds, cpu_seconds });
            }
        });
    }
}
pub fn with_admission_cost_trace<T>(work: impl FnOnce() -> T) -> (T, CostTrace) {
    if ACTIVE.with(|v| {
        let mut slot = v.borrow_mut();
        if let Some(trace) = slot.as_mut() { trace.valid = false; true } else { false }
    }) {
        // Never suppress/change the genuine work if an unsupported nested caller appears.
        return (work(), CostTrace { valid: false, samples: Vec::new() });
    }
    ACTIVE.with(|v| *v.borrow_mut() = Some(CostTrace { valid: true, samples: Vec::with_capacity(LIMIT) }));
    struct Reset;
    impl Drop for Reset { fn drop(&mut self) { ACTIVE.with(|v| *v.borrow_mut() = None); } }
    let _reset = Reset;
    let result = work();
    let trace = ACTIVE.with(|v| v.borrow_mut().take()).expect("diagnostic trace slot invariant");
    (result, trace)
}
