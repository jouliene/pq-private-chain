//! The verifier reads the locally registered matrix, never a circuit from a packet.
use super::*;
use sha2::{Digest, Sha256};

pub struct Sparse {
    ends: Vec<[usize; 3]>,
    entries: Vec<(usize, F)>,
    pub columns: usize,
    pub public: usize, // includes ONE
}
pub type Plan = Sparse;

impl Sparse {
    pub fn load(raw: &[u8], profile: Profile) -> Self {
        assert_eq!(raw.len(), profile.matrix_len());
        assert_eq!(
            Sha256::digest(raw)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            profile.registration()
        );
        let mut data = raw;
        assert_eq!(take(&mut data, 8), b"FWHRCS01");
        let public = u32le(&mut data) + 1;
        let columns = u32le(&mut data);
        let rows = u32le(&mut data);
        assert_eq!(public, 1 + profile.words());
        assert!(rows <= 1 << OUTER_ROUNDS && columns - public <= MAIN_WORDS);
        let mut ends = Vec::with_capacity(rows);
        let mut entries = Vec::with_capacity(data.len() / 12);
        for _ in 0..rows {
            ends.push(std::array::from_fn(|_| {
                for _ in 0..u32le(&mut data) {
                    let c = u32le(&mut data);
                    assert!(c < columns);
                    entries.push((c, word(&mut data)));
                }
                entries.len()
            }));
        }
        assert!(data.is_empty());
        Self {
            ends,
            entries,
            columns,
            public,
        }
    }

    pub fn row_values(&self, z: &[F]) -> [Vec<E>; 3] {
        let mut result: [Vec<E>; 3] =
            std::array::from_fn(|_| Vec::with_capacity(1 << OUTER_ROUNDS));
        let mut pos = 0;
        for ends in &self.ends {
            let values: [F; 3] = std::array::from_fn(|i| {
                let sum = self.entries[pos..ends[i]]
                    .iter()
                    .map(|&(c, v)| z[c] * v)
                    .sum();
                pos = ends[i];
                sum
            });
            assert!(
                values[0] * values[1] == values[2],
                "unsatisfied rank-one constraint"
            );
            for (dst, x) in result.iter_mut().zip(values) {
                dst.push(E::from(x));
            }
        }
        for v in &mut result {
            v.resize(1 << OUTER_ROUNDS, E::ZERO);
        }
        result
    }

    pub fn dense_form(&self, alpha: &[E], rho: E) -> Vec<E> {
        let mix = [E::ONE, rho, rho.square()];
        let mut out = vec![E::ZERO; self.columns];
        let mut pos = 0;
        for (ends, w) in self.ends.iter().zip(eq(alpha)) {
            for (i, &end) in ends.iter().enumerate() {
                let scale = w * mix[i];
                for &(c, k) in &self.entries[pos..end] {
                    out[c] += scale * k;
                }
                pos = end;
            }
        }
        out
    }

    pub fn apply(&self, alpha: &[E], rho: E, beta: &[F], gamma: &[E]) -> (Vec<E>, Vec<E>, (), ()) {
        let mut public = self.dense_form(alpha, rho);
        let mut witness = public.split_off(self.public);
        for (j, &base) in beta.iter().enumerate() {
            let mix = rho.exp_u64((4 + j) as u64);
            let mut power = base;
            for c in &mut witness {
                *c += mix * power;
                power *= base;
            }
        }
        // The padding after the actual private columns has zero coefficients.
        let width = PCS_MAIN[0];
        let mut folded = vec![E::ZERO; width];
        for (row, weight) in witness.chunks(width).zip(eq(gamma)) {
            for (dest, &value) in folded.iter_mut().zip(row) {
                *dest += weight * value;
            }
        }
        (public, folded, (), ())
    }
}
