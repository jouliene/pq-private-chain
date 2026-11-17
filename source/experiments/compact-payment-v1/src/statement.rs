//! Exact root-owned CP_P2_FRONTEND_01 statement. No proof verifier exists in this frontend.
use crate::hash::{self, Digest};
use crate::permutation::P;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks as F;
pub const MAX: u64 = 1_840_960_000_000_000;
pub const STATEMENT_BYTES: usize = 528;
pub const PUBLIC_FIELDS: usize = 49;
pub const FEE: usize = 37;
pub const ROOT: usize = 38;
pub const COUNT: usize = 46;
pub const CREDIT: usize = 47;
pub const DEBIT: usize = 48;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub chain: [u8; 32],
    pub nonce: [u8; 32],
    pub nullifiers: [Digest; 2],
    pub commitments: [Digest; 2],
    pub fee: u64,
    pub root: Digest,
    pub count: u64,
    pub credit: u64,
    pub debit: u64,
    pub receipts: [[u8; 48]; 2],
}
fn word(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn digest(b: &[u8], o: usize) -> Result<Digest, String> {
    let a = core::array::from_fn(|j| word(b, o + 8 * j));
    if a.iter().any(|&x| x >= P) {
        return Err("noncanonical public field".into());
    }
    Ok(a)
}
impl Statement {
    pub fn parse(b: &[u8]) -> Result<Self, String> {
        if b.len() != 528 {
            return Err("statement length".into());
        }
        if &b[..8] != b"CP-P2-01" || &b[8..16] != [1, 0, 2, 2, 1, 0, 0, 0] {
            return Err("statement header".into());
        }
        let s = Self {
            chain: b[16..48].try_into().unwrap(),
            nonce: b[48..80].try_into().unwrap(),
            nullifiers: [digest(b, 80)?, digest(b, 144)?],
            commitments: [digest(b, 208)?, digest(b, 272)?],
            fee: word(b, 336),
            root: digest(b, 344)?,
            count: word(b, 408),
            credit: word(b, 416),
            debit: word(b, 424),
            receipts: [
                b[432..480].try_into().unwrap(),
                b[480..528].try_into().unwrap(),
            ],
        };
        s.validate()?;
        Ok(s)
    }
    pub fn validate(&self) -> Result<(), String> {
        for v in self
            .nullifiers
            .iter()
            .chain(self.commitments.iter())
            .chain(core::iter::once(&self.root))
        {
            if v.iter().any(|&x| x >= P) {
                return Err("noncanonical public field".into());
            }
        }
        if self.fee > MAX {
            return Err("fee range".into());
        }
        if self.count == 0 || self.count > 1u64 << 40 {
            return Err("count range".into());
        }
        if self.credit != 0 || self.debit != 0 {
            return Err("transfer public issuance".into());
        }
        if self.nullifiers[0] == self.nullifiers[1] {
            return Err("duplicate public nullifier".into());
        }
        Ok(())
    }
    pub fn bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(528);
        b.extend_from_slice(b"CP-P2-01");
        b.extend([1, 0, 2, 2, 1, 0, 0, 0]);
        b.extend(self.chain);
        b.extend(self.nonce);
        for a in self.nullifiers.iter().chain(self.commitments.iter()) {
            for &x in a {
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
        for r in &self.receipts {
            b.extend(r);
        }
        assert_eq!(b.len(), 528);
        b
    }
    /// Caller must validate the canonical statement before constructing the approved public vector.
    pub fn projection(&self) -> [F; 49] {
        let mut v = Vec::with_capacity(49);
        v.extend(hash::chunks(&self.chain));
        for a in self.nullifiers.iter().chain(self.commitments.iter()) {
            v.extend(a);
        }
        v.push(self.fee);
        v.extend(self.root);
        v.extend([self.count, self.credit, self.debit]);
        assert_eq!(v.len(), 49);
        core::array::from_fn(|i| {
            assert!(v[i] < P);
            F::from_u64(v[i])
        })
    }
    pub fn core(&self) -> Digest {
        let mut v = vec![1, 2, 2];
        for a in self.nullifiers.iter().chain(self.commitments.iter()) {
            v.extend(a);
        }
        v.push(self.fee);
        v.extend(hash::chunks(&self.nonce));
        v.push(1);
        assert_eq!(v.len(), 42);
        hash::hash(&self.chain, hash::CORE, &v)
    }
    pub fn output_origins(&self) -> [Digest; 2] {
        let c = self.core();
        core::array::from_fn(|j| {
            let mut v = c.to_vec();
            v.push(j as u64);
            hash::hash(&self.chain, hash::ORIGIN, &v)
        })
    }
}
