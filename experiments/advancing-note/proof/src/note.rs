use crate::sponge::{self, Host};
use anyhow::{Result, ensure};
use plonky2::field::{
    goldilocks_field::GoldilocksField as F,
    types::{Field, Field64, PrimeField64},
};
use serde::{Deserialize, Serialize};

pub type Digest = [u64; 7];
pub const CAPACITY: u64 = 1 << 40;
pub const LIMIT: u64 = 1 << 62;
#[derive(Copy, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Note {
    pub owner: Digest,
    pub asset: [u32; 8],
    pub native: u64,
    pub token: u64,
    pub salt: Digest,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub note: Note,
    pub sk: Digest,
    pub index: u64,
    pub path: Vec<Digest>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Witness {
    pub inputs: Vec<Input>,
    pub outputs: [Note; 2],
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    pub root: Digest,
    pub count: u64,
    pub fee: u64,
    pub context: [u32; 12],
    pub nullifiers: [Digest; 2],
    pub outputs: [Digest; 2],
}

pub fn scalar(n: u64) -> Result<F> {
    ensure!(n < F::ORDER, "noncanonical field word");
    Ok(F::from_canonical_u64(n))
}
pub fn host_hash(tag: u64, words: &[u64]) -> Result<Digest> {
    let fields = words
        .iter()
        .copied()
        .map(scalar)
        .collect::<Result<Vec<_>>>()?;
    Ok(sponge::hash(&mut Host, tag, &fields).map(|x| x.to_canonical_u64()))
}
impl Note {
    pub fn words(&self) -> Vec<u64> {
        let mut v = self.owner.to_vec();
        v.extend(self.asset.map(u64::from));
        v.extend([self.native, self.token]);
        v.extend(self.salt);
        v
    }
    pub fn commitment(&self) -> Result<Digest> {
        ensure!(
            self.native < LIMIT && self.token < LIMIT,
            "note amount range"
        );
        ensure!(
            (self.token == 0) == (self.asset == [0; 8]),
            "asset identifier"
        );
        host_hash(sponge::NOTE, &self.words())
    }
}
pub fn nf(sk: Digest, index: u64, commitment: Digest) -> Result<Digest> {
    ensure!(index < CAPACITY, "position");
    let mut v = sk.to_vec();
    v.push(index);
    v.extend(commitment);
    host_hash(sponge::NULLIFIER, &v)
}
pub fn parent(level: u8, left: Digest, right: Digest) -> Result<Digest> {
    ensure!(level < 40, "tree level");
    let mut v = left.to_vec();
    v.extend(right);
    host_hash(sponge::PARENT + u64::from(level), &v)
}
impl Statement {
    pub fn words(&self) -> Vec<u64> {
        let mut v = self.root.to_vec();
        v.extend([self.count, self.fee]);
        v.extend(self.context.map(u64::from));
        v.extend(self.nullifiers.into_iter().flatten());
        v.extend(self.outputs.into_iter().flatten());
        v
    }
    pub fn check(&self) -> Result<()> {
        ensure!(
            (1..=CAPACITY).contains(&self.count) && matches!(self.fee, 0 | 3),
            "statement count/fee"
        );
        ensure!(
            self.nullifiers[0] != self.nullifiers[1],
            "duplicate nullifier"
        );
        self.words()
            .into_iter()
            .try_for_each(|x| scalar(x).map(|_| ()))
    }
}
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
pub enum Op {
    Owner {
        sk: Digest,
    },
    Note {
        note: Note,
    },
    Padding {
        sk: Digest,
        nullifier: Digest,
    },
    Empty,
    Parent {
        level: u8,
        left: Digest,
        right: Digest,
    },
    Nf {
        sk: Digest,
        index: u64,
        commitment: Digest,
    },
}
impl Op {
    pub fn eval(self) -> Result<Digest> {
        match self {
            Self::Owner { sk } => host_hash(sponge::OWNER, &sk),
            Self::Note { note } => note.commitment(),
            Self::Padding { sk, nullifier } => {
                let mut words = sk.to_vec();
                words.extend(nullifier);
                host_hash(sponge::PADDING, &words)
            }
            Self::Empty => host_hash(sponge::EMPTY, &[]),
            Self::Parent { level, left, right } => parent(level, left, right),
            Self::Nf {
                sk,
                index,
                commitment,
            } => nf(sk, index, commitment),
        }
    }
}
