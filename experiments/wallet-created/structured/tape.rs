use super::*;
use tiny_keccak::{Hasher, Sha3, Shake, Xof};

pub type Digest = [u8; 64];

pub fn hash(label: &[u8], parts: &[&[u8]]) -> Digest {
    let mut h = Sha3::v512();
    h.update(b"PQPC/CFW-01");
    h.update(&(label.len() as u32).to_le_bytes());
    h.update(label);
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    let mut out = [0; 64];
    h.finalize(&mut out);
    out
}

pub fn pack(values: &[E]) -> Vec<u8> {
    let mut data = Vec::with_capacity(40 * values.len());
    for e in values {
        for v in <E as BasedVectorSpace<F>>::as_basis_coefficients_slice(e) {
            data.extend_from_slice(&v.as_canonical_u64().to_le_bytes());
        }
    }
    data
}
pub fn unpack(data: &[u8]) -> Vec<E> {
    assert!(data.len().is_multiple_of(40));
    data.chunks_exact(40)
        .map(|chunk| {
            E::from_basis_coefficients_fn(|i| {
                let n = u64::from_le_bytes(chunk[8 * i..8 * i + 8].try_into().unwrap());
                assert!(n < 0xffffffff00000001, "noncanonical field");
                F::from_u64(n)
            })
        })
        .collect()
}
pub struct Draw(Shake);
impl Draw {
    fn seed(bytes: &[u8]) -> Self {
        let mut h = Shake::v256();
        h.update(bytes);
        Self(h)
    }
    pub fn random() -> Self {
        let mut seed = [0; 64];
        std::fs::File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut seed)
            .unwrap();
        Self::seed(&seed)
    }
    pub fn bytes(&mut self, buf: &mut [u8]) {
        self.0.squeeze(buf);
    }
    pub fn base(&mut self) -> F {
        loop {
            let mut b = [0; 8];
            self.bytes(&mut b);
            let n = u64::from_le_bytes(b);
            if n < 0xffffffff00000001 {
                return F::from_u64(n);
            }
        }
    }
    pub fn field(&mut self) -> E {
        E::from_basis_coefficients_fn(|_| self.base())
    }
    pub fn fields(&mut self, n: usize) -> Vec<E> {
        (0..n).map(|_| self.field()).collect()
    }
    pub fn index(&mut self, n: usize) -> usize {
        assert!(n.is_power_of_two());
        let mut b = [0; 8];
        self.bytes(&mut b);
        u64::from_le_bytes(b) as usize & (n - 1)
    }
}

pub struct Tape {
    state: Digest,
    pub data: Vec<u8>,
    pos: usize,
    pub proving: bool,
}
impl Tape {
    pub fn new(statement: &[u8], program: &Digest, proof: Option<Vec<u8>>) -> Self {
        Self {
            state: hash(
                b"registered-statement",
                &[TRANSCRIPT_DOMAIN, program, statement],
            ),
            proving: proof.is_none(),
            data: proof.unwrap_or_default(),
            pos: 0,
        }
    }
    pub fn raw(&mut self, data: Option<&[u8]>, n: usize) -> Vec<u8> {
        if self.proving {
            let d = data.unwrap();
            assert_eq!(d.len(), n);
            self.data.extend_from_slice(d);
        }
        let end = self.pos.checked_add(n).unwrap();
        let buf = self.data.get(self.pos..end).expect("short proof").to_vec();
        self.pos = end;
        buf
    }
    pub fn message(&mut self, tag: &str, data: Option<&[u8]>, n: usize) -> Vec<u8> {
        let buf = self.raw(data, n);
        self.state = hash(b"message", &[tag.as_bytes(), &self.state, &buf]);
        buf
    }
    pub fn fields(&mut self, tag: &str, data: Option<&[E]>, n: usize) -> Vec<E> {
        let packed = data.map(pack);
        unpack(&self.message(tag, packed.as_deref(), n * 40))
    }
    pub fn draw(&mut self, tag: &str) -> Draw {
        self.state = hash(b"verifier-coin-packet", &[tag.as_bytes(), &self.state]);
        Draw::seed(&self.state)
    }
    pub fn end(&self) {
        assert_eq!(self.pos, self.data.len(), "trailing proof");
    }
}
