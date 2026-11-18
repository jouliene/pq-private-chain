use anyhow::{ensure, Result};
use plonky2::field::types::PrimeField64;
use qnero_aggregator::{Proof, F};
use qnero_circuit::chain::{ct_digest, declared_crypto_suite, SUITE_1_CIPHERTEXT_BYTES};
use qnero_notes::NoteCiphertext;
use std::collections::HashSet;
use std::io::{Read, Write};

pub const CT: usize = SUITE_1_CIPHERTEXT_BYTES;
pub const TAG: u64 = 0x415056320001;
const FRAME_LIMIT: usize = 32 * 1024 * 1024;
const PACKET_LIMIT: usize = 2 * 1024 * 1024;
pub struct Packet<'a> {
    pub arity: usize,
    pub proof: &'a [u8],
    pub cts: &'a [u8],
}
pub fn packet(raw: &[u8]) -> Result<Packet<'_>> {
    ensure!(
        raw.len() >= 9 && raw.len() <= PACKET_LIMIT && &raw[..4] == b"APV2",
        "packet format"
    );
    let arity = usize::from(raw[4]);
    ensure!((1..=4).contains(&arity), "arity");
    let n = u32::from_le_bytes(raw[5..9].try_into()?) as usize;
    ensure!(
        n > 0 && n + 9 + 2 * CT * arity == raw.len(),
        "packet length"
    );
    Ok(Packet {
        arity,
        proof: &raw[9..9 + n],
        cts: &raw[9 + n..],
    })
}
pub fn encode(arity: usize, proof: &Proof, cts: &[u8]) -> Vec<u8> {
    let body = proof.to_bytes();
    let mut out = b"APV2".to_vec();
    out.push(arity as u8);
    out.extend((body.len() as u32).to_le_bytes());
    out.extend(body);
    out.extend(cts);
    out
}
pub fn read_frame(r: &mut impl Read) -> Result<Vec<u8>> {
    let mut n = [0; 4];
    r.read_exact(&mut n)?;
    let len = u32::from_le_bytes(n) as usize;
    ensure!(len <= FRAME_LIMIT, "frame size");
    let mut out = vec![0; len];
    r.read_exact(&mut out)?;
    Ok(out)
}
pub fn write_frame(w: &mut impl Write, data: &[u8]) -> Result<()> {
    ensure!(data.len() <= FRAME_LIMIT, "frame size");
    w.write_all(&(data.len() as u32).to_le_bytes())?;
    w.write_all(data)?;
    w.flush()?;
    Ok(())
}

fn word(fields: &[F]) -> [u8; 32] {
    let mut out = [0; 32];
    for (a, b) in out.chunks_exact_mut(8).zip(fields) {
        a.copy_from_slice(&b.to_canonical_u64().to_le_bytes());
    }
    out
}
pub fn effects(p: &Packet<'_>, proof: &Proof) -> Result<Vec<u8>> {
    let all = &proof.public_inputs;
    let slots = if p.arity == 1 {
        all.as_slice()
    } else {
        ensure!(
            all.len() == 2 + 26 * p.arity
                && all[0].to_canonical_u64() == TAG
                && all[1].to_canonical_u64() == p.arity as u64,
            "wrapper public shape"
        );
        &all[2..]
    };
    ensure!(slots.len() == 26 * p.arity, "slot length");
    let mut nullifiers = HashSet::new();
    let mut commitments = HashSet::new();
    let mut out = Vec::new();
    for (s, cts) in slots.chunks_exact(26).zip(p.cts.chunks_exact(2 * CT)) {
        out.extend(word(&s[..4]));
        out.extend(u32::try_from(s[4].to_canonical_u64())?.to_le_bytes());
        for off in [5, 9] {
            let value = word(&s[off..off + 4]);
            ensure!(nullifiers.insert(value), "duplicate input");
            out.extend(value);
        }
        for off in [13, 17] {
            let value = word(&s[off..off + 4]);
            ensure!(
                value != [0; 32] && commitments.insert(value),
                "duplicate/padding output"
            );
            out.extend(value);
        }
        let fee = s[21].to_canonical_u64();
        ensure!(fee == 3, "research fee");
        out.extend(fee.to_le_bytes());
        ensure!(
            ct_digest(&[&cts[..CT], &cts[CT..]]) == word(&s[22..26]),
            "receipt digest"
        );
        for ct in cts.chunks_exact(CT) {
            ensure!(
                declared_crypto_suite(ct) == Some(1)
                    && NoteCiphertext::from_bytes(ct)?.to_bytes() == ct,
                "receipt codec"
            );
        }
        out.extend(cts);
    }
    Ok(out)
}

pub struct Meter {
    start: std::time::Instant,
    cpu: f64,
}
fn process_cpu() -> f64 {
    #[repr(C)]
    struct Timespec {
        seconds: i64,
        nanos: i64,
    }
    extern "C" {
        fn clock_gettime(id: i32, t: *mut Timespec) -> i32;
    }
    let mut value = Timespec {
        seconds: 0,
        nanos: 0,
    };
    // Linux x86-64 CLOCK_PROCESS_CPUTIME_ID, including worker threads.
    assert_eq!(unsafe { clock_gettime(2, &mut value) }, 0);
    value.seconds as f64 + value.nanos as f64 * 1e-9
}
impl Meter {
    pub fn start() -> Self {
        Self {
            start: std::time::Instant::now(),
            cpu: process_cpu(),
        }
    }
    pub fn finish(self, name: &str) {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let rss = status
            .lines()
            .find(|l| l.starts_with("VmHWM:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("0");
        eprintln!(
            "METER {name} {:.9} {:.9} {rss}",
            self.start.elapsed().as_secs_f64(),
            process_cpu() - self.cpu
        );
    }
}
