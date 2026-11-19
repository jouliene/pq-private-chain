//! Reconstruct public devnet rewards using the pinned, unmodified Qnero primitives.
use qnero_notes::{commitment_from_inner, note_inner, Digest, MAX_VALUE};
use std::io::{self, Read};

fn main() {
    let mut rows = Vec::new();
    io::stdin().read_to_end(&mut rows).unwrap();
    assert_eq!(rows.len() % 72, 0, "partial public reward row");
    for body in rows.chunks_exact(72) {
        let value = u64::from_le_bytes(body[64..].try_into().unwrap());
        let miner = Digest::from_slice(&body[32..64]).unwrap();
        assert!(value > 0 && value <= MAX_VALUE);
        let derive = |domain: &[u8]| {
            let bytes = [domain, body].concat();
            Digest::hash_bytes(&[&bytes])
        };
        let inner = note_inner(&miner, &derive(b"PQDEV1/reward/rho"), &derive(b"PQDEV1/reward/r"));
        println!("{}", commitment_from_inner(&inner, value).to_hex());
    }
}
