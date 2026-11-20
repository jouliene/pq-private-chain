//! Standalone research prover and public-only verifier for two locally pinned relations.
use p3_field::{
    BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField,
    extension::BinomialExtensionField,
};
use p3_goldilocks::Goldilocks as F;
use std::io::{Read, Write};
use std::path::Path;
type E = BinomialExtensionField<F, 5>;
const OUTER_ROUNDS: usize = 19;
const MAIN_WORDS: usize = 1 << 18;
const PCS_MAIN: [usize; 4] = [16384, 1024, 64, 64];
const PCS_DOMAINS: [usize; 4] = [1 << 19, 1 << 17, 1 << 16, 1 << 17];
const TRANSCRIPT_DOMAIN: &[u8] =
    b"PQPC/FUNDED-WHIR-01/EF5/K19/M18/guard4-all/radix16/N19-17-16-17/Q53-38-30-31";
const RECEIPT: usize = 1792;
const MAX_PROOF: usize = 245952;
#[path = "../../../wallet-created/structured/algebra.rs"]
mod algebra;
mod matrix;
#[path = "../../../wallet-created/structured/oracle.rs"]
mod oracle;
#[path = "../../../wallet-created/structured/outer.rs"]
mod outer;
#[path = "../../../wallet-created/structured/pcs.rs"]
mod pcs;
#[path = "../../../wallet-created/structured/tape.rs"]
mod tape;
use algebra::*;
use matrix::Sparse;
use tape::Tape;

#[derive(Clone, Copy, PartialEq)]
enum Profile {
    Transfer,
    Leg,
}

impl Profile {
    fn parse(s: &str) -> Self {
        match s {
            "MNG1" => Self::Transfer,
            "SLG1" => Self::Leg,
            _ => panic!("unknown relation"),
        }
    }
    fn words(self) -> usize {
        match self {
            Self::Transfer => 31,
            Self::Leg => 34,
        }
    }
    fn tag(self) -> &'static [u8] {
        match self {
            Self::Transfer => b"FWT1\x01",
            Self::Leg => b"FWL1\x01",
        }
    }
    fn matrix_len(self) -> usize {
        match self {
            Self::Transfer => 15245888,
            Self::Leg => 15637808,
        }
    }
    fn registration(self) -> &'static str {
        match self {
            Self::Transfer => "a1cfa119fe582ecd935734ac51db5d1e6c91af9e0019af737d79791dd688cb9c",
            Self::Leg => "2bc9e336428462084efd673d31da240992e25a289e7fa6ab88237f2d568f6f3e",
        }
    }
}

fn take<'a>(data: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (part, rest) = data.split_at(n);
    *data = rest;
    part
}
fn u32le(data: &mut &[u8]) -> usize {
    u32::from_le_bytes(take(data, 4).try_into().unwrap()) as usize
}
fn word(data: &mut &[u8]) -> F {
    let x = u64::from_le_bytes(take(data, 8).try_into().unwrap());
    assert!(x < 0xffffffff00000001);
    F::from_u64(x)
}
fn bounded(path: &Path, n: usize) -> Vec<u8> {
    let mut data = Vec::new();
    std::fs::File::open(path)
        .unwrap()
        .take((n + 1) as u64)
        .read_to_end(&mut data)
        .unwrap();
    assert!(data.len() <= n);
    data
}
fn statement(profile: Profile, encoded: &[u8], receipts: &[u8]) -> Vec<F> {
    assert_eq!(encoded.len(), 8 * profile.words());
    assert_eq!(receipts.len(), 2 * RECEIPT);
    let mut preimage = b"qnero/ct".to_vec();
    preimage.extend(2u32.to_le_bytes());
    for ct in receipts.chunks_exact(RECEIPT) {
        preimage.extend((RECEIPT as u32).to_le_bytes());
        preimage.extend_from_slice(ct);
    }
    assert_eq!(
        qp_poseidon_core::hash_bytes(&preimage),
        encoded[22 * 8..26 * 8]
    );
    let mut buf = encoded;
    let mut z = vec![F::ONE];
    while !buf.is_empty() {
        z.push(word(&mut buf));
    }
    let fields = &z[1..];
    assert!(fields[4].as_canonical_u64() <= u32::MAX as u64);
    assert!(fields[5..9] != fields[9..13] && fields[13..17] != fields[17..21]);
    for cm in [&fields[13..17], &fields[17..21]] {
        assert!(cm.iter().any(|x| *x != F::ZERO));
    }
    match profile {
        Profile::Transfer => {
            assert!(fields[21] == F::from_u8(3) && fields[26..].iter().all(|&x| x == F::ZERO));
        }
        Profile::Leg => {
            assert!(fields[21] == F::ZERO || fields[21] == F::from_u8(3));
            assert!(
                fields[26..]
                    .iter()
                    .all(|&x| x.as_canonical_u64() <= u32::MAX as u64)
            );
        }
    }
    z
}

fn main() {
    // Do not include failed values or private assignments in role diagnostics.
    std::panic::set_hook(Box::new(|info| {
        if let Some(loc) = info.location() {
            eprintln!("rejected at {}:{}", loc.file(), loc.line());
        }
    }));
    let a: Vec<_> = std::env::args().skip(1).collect();
    assert!(a.len() >= 4);
    let profile = Profile::parse(&a[1]);
    let matrix = Sparse::load(&bounded(Path::new(&a[2]), profile.matrix_len()), profile);
    let program = tape::hash(
        b"registered-funded-matrix",
        &[profile.tag(), profile.registration().as_bytes()],
    );
    match a[0].as_str() {
        "verify" => {
            assert_eq!(a.len(), 4);
            let data = bounded(
                Path::new(&a[3]),
                9 + profile.words() * 8 + MAX_PROOF + 2 * RECEIPT,
            );
            let mut p = data.as_slice();
            assert_eq!(take(&mut p, 5), profile.tag());
            let length = u32le(&mut p);
            assert!(length <= MAX_PROOF);
            let encoded = take(&mut p, profile.words() * 8);
            let proof = take(&mut p, length);
            let public = statement(profile, encoded, p);
            let mut t = Tape::new(encoded, &program, Some(proof.to_vec()));
            let root = pcs::start(&mut t, None, &mut None);
            let claim = outer::execute(&mut t, &matrix, &[], &public, None);
            pcs::execute(&mut t, Some(&matrix), claim, &public, root, &mut None);
            println!(
                "accepted {} public words; {} proof bytes",
                profile.words(),
                length
            );
        }
        "prove" => {
            assert_eq!(a.len(), 6);
            let encoded = bounded(Path::new(&a[3]), profile.words() * 8);
            let receipts = bounded(Path::new(&a[4]), 2 * RECEIPT);
            let public = statement(profile, &encoded, &receipts);
            let mut input = Vec::new();
            let byte_count = matrix.columns * 8;
            std::io::stdin()
                .take((byte_count + 1) as u64)
                .read_to_end(&mut input)
                .unwrap();
            assert_eq!(input.len(), byte_count);
            let mut buf = input.as_slice();
            let z: Vec<F> = (0..matrix.columns).map(|_| word(&mut buf)).collect();
            assert!(z[..public.len()] == public);
            drop(input);
            let mut t = Tape::new(&encoded, &program, None);
            let mut rng = Some(tape::Draw::random());
            let secret = outer::Secret::new(
                &z,
                public.len(),
                z.len() - public.len(),
                rng.as_mut().unwrap(),
            );
            let root = pcs::start(&mut t, Some(&secret), &mut rng);
            let claim = outer::execute(&mut t, &matrix, &z, &public, Some(&secret));
            drop(secret);
            drop(z);
            pcs::execute(&mut t, None, claim, &public, root, &mut rng);
            assert!(t.data.len() <= MAX_PROOF);
            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&a[5])
                .unwrap();
            for part in [
                profile.tag(),
                &(t.data.len() as u32).to_le_bytes(),
                &encoded,
                &t.data,
                &receipts,
            ] {
                out.write_all(part).unwrap();
            }
            println!(
                "created {} public words; {} proof bytes",
                profile.words(),
                t.data.len()
            );
        }
        _ => panic!("unknown mode"),
    }
}
