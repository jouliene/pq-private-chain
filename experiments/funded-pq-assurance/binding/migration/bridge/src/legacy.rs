//! Exact four-word funded hash used by the C output commitment.
use crate::sponge::{Arithmetic, Builder, Host};
use anyhow::{Result, ensure};
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField as F,
        types::{Field, Field64, PrimeField64},
    },
    iop::target::Target,
};

pub type Digest = [u64; 4];
pub type TargetDigest = [Target; 4];
pub const NOTE: u64 = 0x716e0003;
pub const CM: u64 = 0x716e0004;
pub const OPEN: u64 = 0x415354310001;
pub const LIMIT: u64 = 1 << 62;

fn hash<A: Arithmetic>(a: &mut A, words: &[A::Word]) -> [A::Word; 4] {
    let mut message = Vec::with_capacity(words.len() + 8);
    message.extend_from_slice(words);
    message.push(a.constant(1));
    while message.len() % 8 != 0 {
        message.push(a.constant(0));
    }
    let mut state = [a.constant(0); 12];
    for block in message.chunks(8) {
        for (slot, &word) in state.iter_mut().zip(block) {
            *slot = a.add(*slot, word);
        }
        state = a.permute(state);
    }
    state[..4].try_into().unwrap()
}

pub fn circuit_hash(builder: &mut Builder, words: &[Target]) -> TargetDigest {
    hash(builder, words)
}

pub fn host_hash(words: &[u64]) -> Result<Digest> {
    let fields = words
        .iter()
        .map(|&word| {
            ensure!(word < F::ORDER, "noncanonical legacy field word");
            Ok(F::from_canonical_u64(word))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(hash(&mut Host, &fields).map(|word| word.to_canonical_u64()))
}

pub fn commitment(
    pk: Digest,
    asset: Digest,
    native: u64,
    token: u64,
    rho: Digest,
    raw: Digest,
) -> Result<Digest> {
    ensure!(native < LIMIT && token < LIMIT, "legacy amount range");
    ensure!(
        asset.iter().all(|&word| word < 1 << 63),
        "legacy asset range"
    );
    ensure!((token == 0) == (asset == [0; 4]), "legacy asset/value rule");
    let typed = host_hash(
        &[OPEN]
            .into_iter()
            .chain(asset)
            .chain([token])
            .chain(raw)
            .collect::<Vec<_>>(),
    )?;
    let inner = host_hash(
        &[NOTE]
            .into_iter()
            .chain(pk)
            .chain(rho)
            .chain(typed)
            .collect::<Vec<_>>(),
    )?;
    host_hash(
        &[CM]
            .into_iter()
            .chain(inner)
            .chain([native])
            .collect::<Vec<_>>(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_message_hash_matches_independent_reference() {
        // python3 -IB experiments/funded-membership/reference.py, hash_fields([])
        assert_eq!(
            host_hash(&[]).unwrap(),
            [
                6_603_546_443_285_426_716,
                17_641_567_038_109_752_820,
                7_440_670_873_261_577_637,
                3_790_858_589_358_498_814,
            ]
        );
    }
}
