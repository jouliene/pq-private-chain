//! Canonical CP-P2-03 variable statement; source authorization is a separate protocol gate.
use crate::{
    hash::{self, Digest},
    permutation::P,
};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks as F;
pub const MAX: u64 = 1_840_960_000_000_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arity {
    Credit,
    One,
    Two,
}
impl Arity {
    pub fn from_n(n: usize) -> Result<Self, String> {
        match n {
            0 => Ok(Self::Credit),
            1 => Ok(Self::One),
            2 => Ok(Self::Two),
            _ => Err("unsupported input arity".into()),
        }
    }
    pub const fn n(self) -> usize {
        match self {
            Self::Credit => 0,
            Self::One => 1,
            Self::Two => 2,
        }
    }
    pub const fn kind(self) -> u8 {
        if self.n() == 0 { 3 } else { 1 }
    }
    pub const fn bytes(self) -> usize {
        match self {
            Self::Credit => 448,
            Self::One => 464,
            Self::Two => 528,
        }
    }
    pub const fn public_fields(self) -> usize {
        33 + 8 * self.n()
    }
    pub const fn fee(self) -> usize {
        21 + 8 * self.n()
    }
    pub const fn root(self) -> usize {
        self.fee() + 1
    }
    pub const fn count(self) -> usize {
        self.fee() + 9
    }
    pub const fn credit(self) -> usize {
        self.fee() + 10
    }
    pub const fn debit(self) -> usize {
        self.fee() + 11
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub arity: Arity,
    pub chain: [u8; 32],
    pub nonce: [u8; 32],
    pub nullifiers: Vec<Digest>,
    pub commitments: [Digest; 2],
    pub fee: u64,
    pub root: Digest,
    pub count: u64,
    pub credit: u64,
    pub debit: u64,
    pub receipts: [[u8; 48]; 2],
    pub source_id: Option<[u8; 48]>,
}
fn word(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn digest(b: &[u8], at: usize) -> Result<Digest, String> {
    let d = core::array::from_fn(|i| word(b, at + 8 * i));
    if d.iter().any(|&x| x >= P) {
        Err("noncanonical public field".into())
    } else {
        Ok(d)
    }
}
/// Six 7-byte limbs and one 6-byte limb, injective and below the field modulus.
pub fn source_chunks(b: &[u8; 48]) -> [u64; 7] {
    core::array::from_fn(|i| {
        let start = 7 * i;
        let end = (start + 7).min(48);
        let mut a = [0; 8];
        a[..end - start].copy_from_slice(&b[start..end]);
        u64::from_le_bytes(a)
    })
}
impl Statement {
    pub fn parse(b: &[u8]) -> Result<Self, String> {
        if b.len() < 16
            || &b[..8] != b"CP-P2-03"
            || b[8..10] != [3, 0]
            || b[11] != 2
            || b[13..16] != [0, 0, 0]
        {
            return Err("statement header".into());
        }
        let arity = Arity::from_n(b[10] as usize)?;
        if b.len() != arity.bytes() || b[12] != arity.kind() {
            return Err("statement kind/arity/length".into());
        }
        let mut at = 80;
        let mut nullifiers = Vec::with_capacity(arity.n());
        for _ in 0..arity.n() {
            nullifiers.push(digest(b, at)?);
            at += 64;
        }
        let commitments = [digest(b, at)?, digest(b, at + 64)?];
        at += 128;
        let fee = word(b, at);
        at += 8;
        let root = digest(b, at)?;
        at += 64;
        let count = word(b, at);
        let credit = word(b, at + 8);
        let debit = word(b, at + 16);
        at += 24;
        let receipts = [
            b[at..at + 48].try_into().unwrap(),
            b[at + 48..at + 96].try_into().unwrap(),
        ];
        at += 96;
        let source_id = if arity == Arity::Credit {
            Some(b[at..at + 48].try_into().unwrap())
        } else {
            None
        };
        let s = Self {
            arity,
            chain: b[16..48].try_into().unwrap(),
            nonce: b[48..80].try_into().unwrap(),
            nullifiers,
            commitments,
            fee,
            root,
            count,
            credit,
            debit,
            receipts,
            source_id,
        };
        s.validate()?;
        Ok(s)
    }
    fn canonical_shape(&self) -> Result<(), String> {
        if self.nullifiers.len() != self.arity.n()
            || self.source_id.is_some() != (self.arity == Arity::Credit)
        {
            return Err("statement arity/source shape".into());
        }
        if self
            .nullifiers
            .iter()
            .chain(self.commitments.iter())
            .chain(core::iter::once(&self.root))
            .flatten()
            .any(|&x| x >= P)
            || [self.fee, self.count, self.credit, self.debit]
                .iter()
                .any(|&x| x >= P)
        {
            return Err("noncanonical public field".into());
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<(), String> {
        self.canonical_shape()?;
        if self.fee > MAX || self.debit != 0 {
            return Err("public fee/debit".into());
        }
        if self.count > (1u64 << 40) {
            return Err("count bound".into());
        }
        if self.arity == Arity::Credit {
            if self.credit == 0 || self.credit > MAX {
                return Err("credit bound".into());
            }
        } else if self.credit != 0 || self.count == 0 {
            return Err("transfer credit/count".into());
        }
        if self.arity == Arity::Two && self.nullifiers[0] == self.nullifiers[1] {
            return Err("duplicate nullifier".into());
        }
        Ok(())
    }
    /// Canonical representation only, also used to identify deliberately invalid direct-AIR fixtures.
    /// Every public intake MUST call parse/validate, which enforces the semantic grammar.
    pub fn bytes(&self) -> Result<Vec<u8>, String> {
        self.canonical_shape()?;
        let mut b = b"CP-P2-03".to_vec();
        b.extend([3, 0, self.arity.n() as u8, 2, self.arity.kind(), 0, 0, 0]);
        b.extend(self.chain);
        b.extend(self.nonce);
        for d in self.nullifiers.iter().chain(self.commitments.iter()) {
            for &x in d {
                b.extend(x.to_le_bytes());
            }
        }
        b.extend(self.fee.to_le_bytes());
        for &x in &self.root {
            b.extend(x.to_le_bytes());
        }
        for x in [self.count, self.credit, self.debit] {
            b.extend(x.to_le_bytes());
        }
        for r in self.receipts {
            b.extend(r);
        }
        if let Some(id) = self.source_id {
            b.extend(id);
        }
        assert_eq!(b.len(), self.arity.bytes());
        Ok(b)
    }
    /// Canonical fields, not semantic prefiltering: invalid credit/debit must reach direct AIR tests.
    pub fn projection(&self) -> Result<Vec<F>, String> {
        self.canonical_shape()?;
        let mut v = hash::chunks(&self.chain).to_vec();
        for d in self.nullifiers.iter().chain(self.commitments.iter()) {
            v.extend(d);
        }
        v.push(self.fee);
        v.extend(self.root);
        v.extend([self.count, self.credit, self.debit]);
        assert_eq!(v.len(), self.arity.public_fields());
        Ok(v.into_iter().map(F::from_u64).collect())
    }
    pub fn core(&self) -> Result<Digest, String> {
        self.canonical_shape()?;
        let mut v = vec![self.arity.kind() as u64, self.arity.n() as u64, 2];
        for d in self.nullifiers.iter().chain(self.commitments.iter()) {
            v.extend(d);
        }
        v.push(self.fee);
        v.extend(hash::chunks(&self.nonce));
        v.push(1);
        if let Some(id) = self.source_id {
            v.extend(source_chunks(&id));
            v.push(self.credit);
        }
        Ok(hash::hash(&self.chain, hash::CORE, &v))
    }
    pub fn output_origins(&self) -> Result<[Digest; 2], String> {
        let c = self.core()?;
        Ok(core::array::from_fn(|j| {
            let mut v = c.to_vec();
            v.push(j as u64);
            hash::hash(&self.chain, hash::ORIGIN, &v)
        }))
    }
}
