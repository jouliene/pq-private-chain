//! Root-frozen SHA3-512 adapters: role || payload || u64le(payload byte length).
use p3_field::PrimeField64;
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use tiny_keccak::{Hasher, Sha3};

use crate::types::{Digest, Val};

#[derive(Clone, Copy, Debug)]
pub struct LeafHash;
#[derive(Clone, Copy, Debug)]
pub struct NodeHash;
#[derive(Clone, Copy, Debug)]
pub struct TranscriptHash;

pub const LEAF_TAG: &[u8] = b"PQPC/CP-FRI/01/LEAF\0";
pub const NODE_TAG: &[u8] = b"PQPC/CP-FRI/01/NODE\0";
pub const TRANSCRIPT_TAG: &[u8] = b"PQPC/CP-FRI/01/TRANSCRIPT\0";

pub fn sha3_512(bytes: &[u8]) -> [u8; 64] {
    let mut state = Sha3::v512();
    state.update(bytes);
    finish(state)
}

fn finish(state: Sha3) -> [u8; 64] {
    let mut out = [0; 64];
    state.finalize(&mut out);
    out
}

fn words(bytes: [u8; 64]) -> Digest {
    core::array::from_fn(|i| {
        u64::from_le_bytes(
            bytes[i * 8..i * 8 + 8]
                .try_into()
                .expect("fixed digest limb"),
        )
    })
}

impl CryptographicHasher<Val, Digest> for LeafHash {
    fn hash_iter<I: IntoIterator<Item = Val>>(&self, input: I) -> Digest {
        let mut state = Sha3::v512();
        state.update(LEAF_TAG);
        let mut length = 0u64;
        for value in input {
            length = length.checked_add(8).expect("leaf payload length overflow");
            state.update(&value.as_canonical_u64().to_le_bytes());
        }
        state.update(&length.to_le_bytes());
        words(finish(state))
    }
}

impl PseudoCompressionFunction<Digest, 2> for NodeHash {
    fn compress(&self, input: [Digest; 2]) -> Digest {
        let mut state = Sha3::v512();
        state.update(NODE_TAG);
        for digest in input {
            for word in digest {
                state.update(&word.to_le_bytes());
            }
        }
        state.update(&128u64.to_le_bytes());
        words(finish(state))
    }
}

impl CryptographicHasher<u8, [u8; 64]> for TranscriptHash {
    fn hash_iter<I: IntoIterator<Item = u8>>(&self, input: I) -> [u8; 64] {
        let mut state = Sha3::v512();
        state.update(TRANSCRIPT_TAG);
        // A bounded stack buffer avoids allocation proportional to observed input.
        let mut buffer = [0u8; 256];
        let mut used = 0;
        let mut length = 0u64;
        for byte in input {
            length = length
                .checked_add(1)
                .expect("transcript payload length overflow");
            buffer[used] = byte;
            used += 1;
            if used == buffer.len() {
                state.update(&buffer);
                used = 0;
            }
        }
        state.update(&buffer[..used]);
        state.update(&length.to_le_bytes());
        finish(state)
    }
}
