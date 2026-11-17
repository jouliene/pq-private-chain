use crate::permutation::{P, permute};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks as F;
pub const VERSION: u64 = 0x43505032;
pub const AUTH: u64 = 1;
pub const NOTE: u64 = 2;
pub const NF: u64 = 3;
pub const LEAF: u64 = 4;
pub const NODE: u64 = 5;
pub const CORE: u64 = 6;
pub const ORIGIN: u64 = 7;
pub type Digest = [u64; 8];
pub fn canonical(x: u64) -> Result<F, String> {
    if x >= P {
        Err("noncanonical field integer".into())
    } else {
        Ok(F::from_u64(x))
    }
}
pub fn chunks(x: &[u8; 32]) -> [u64; 5] {
    core::array::from_fn(|i| {
        let start = i * 7;
        let end = (start + 7).min(32);
        let mut b = [0; 8];
        b[..end - start].copy_from_slice(&x[start..end]);
        u64::from_le_bytes(b)
    })
}
pub fn framed(chain: &[u8; 32], role: u64, payload: &[F]) -> Vec<F> {
    let mut v = vec![F::from_u64(VERSION), F::from_u64(role)];
    v.extend(chunks(chain).map(F::from_u64));
    v.push(F::from_usize(payload.len()));
    v.extend_from_slice(payload);
    v.push(F::ONE);
    while !v.len().is_multiple_of(8) {
        v.push(F::ZERO);
    }
    v
}
pub fn hash(chain: &[u8; 32], role: u64, payload: &[u64]) -> Digest {
    assert!(
        payload.iter().all(|&x| x < P),
        "PUBLIC frontend noncanonical hash payload"
    );
    let fs: Vec<F> = payload.iter().copied().map(F::from_u64).collect();
    let mut s = [F::ZERO; 16];
    for b in framed(chain, role, &fs).chunks_exact(8) {
        for j in 0..8 {
            s[j] += b[j];
        }
        s = permute(s);
    }
    core::array::from_fn(|j| s[j].as_canonical_u64())
}
