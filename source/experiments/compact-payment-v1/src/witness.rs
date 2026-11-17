//! PUBLIC-fixture witness data. This is not a private-proof input/entropy interface.
use crate::{
    air::{PaymentAir, message},
    hash::{self, Digest},
    layout::*,
    permutation::{self, P},
    statement::{MAX, Statement},
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{GenericPoseidon2LinearLayersGoldilocks as Layers, Goldilocks as F};
use p3_matrix::dense::RowMajorMatrix;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub note: [u64; 20],
    pub key: [u64; 5],
    pub origin: Digest,
    pub index: u64,
    pub siblings: Vec<Digest>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Witness {
    pub inputs: [Input; 2],
    pub outputs: [[u64; 20]; 2],
}
impl Witness {
    pub fn canonical(&self) -> Result<(), String> {
        for i in &self.inputs {
            if i.siblings.len() != 40 {
                return Err("path length".into());
            }
            if i.note
                .iter()
                .chain(i.key.iter())
                .chain(i.origin.iter())
                .chain(i.siblings.iter().flatten())
                .any(|&x| x >= P)
            {
                return Err("noncanonical witness field".into());
            }
            if i.index >= P {
                return Err("noncanonical witness index".into());
            }
        }
        if self.outputs.iter().flatten().any(|&x| x >= P) {
            return Err("noncanonical output note".into());
        }
        Ok(())
    }
    pub fn commitments(&self, chain: &[u8; 32]) -> [Digest; 2] {
        core::array::from_fn(|i| hash::hash(chain, hash::NOTE, &self.inputs[i].note))
    }
    pub fn leaves(&self, chain: &[u8; 32]) -> [Digest; 2] {
        let cm = self.commitments(chain);
        core::array::from_fn(|i| {
            let mut p = self.inputs[i].origin.to_vec();
            p.extend(cm[i]);
            hash::hash(chain, hash::LEAF, &p)
        })
    }
    pub fn nullifiers(&self, chain: &[u8; 32]) -> [Digest; 2] {
        let cm = self.commitments(chain);
        core::array::from_fn(|i| {
            let mut p = self.inputs[i].key.to_vec();
            p.extend(self.inputs[i].origin);
            p.extend(cm[i]);
            hash::hash(chain, hash::NF, &p)
        })
    }
}
pub struct Trace {
    pub matrix: RowMajorMatrix<F>,
    pub hash_outputs: Vec<Digest>,
}
fn put(row: &mut [F], at: usize, words: &[u64]) {
    for (j, &x) in words.iter().enumerate() {
        assert!(x < P);
        row[at + j] = F::from_u64(x);
    }
}
fn bits(row: &mut [F], at: usize, n: usize, x: u64) {
    for j in 0..n {
        row[at + j] = F::from_u64((x >> j) & 1);
    }
}
fn difference(a: u64, b: u64) -> u64 {
    (F::from_u64(a) - F::from_u64(b)).as_canonical_u64()
}
/// Generate a fresh trace even for semantically malicious canonical witnesses.
/// In particular no authority, membership, balance or amount-range host check can
/// substitute for the subsequently executed AIR constraints.
pub fn generate(air: &PaymentAir, s: &Statement, w: &Witness) -> Result<Trace, String> {
    w.canonical()?;
    let height = air.program().height();
    let v = s.projection();
    let cms = w.commitments(&s.chain);
    let mut context = vec![F::ZERO; CONTEXT];
    for i in 0..4 {
        let n = if i < 2 {
            &w.inputs[i].note
        } else {
            &w.outputs[i - 2]
        };
        put(&mut context, CTX_NOTES + 20 * i, n);
    }
    for i in 0..2 {
        put(&mut context, CTX_KEYS + 5 * i, &w.inputs[i].key);
        put(&mut context, CTX_ORIGINS + 8 * i, &w.inputs[i].origin);
        put(&mut context, CTX_CM + 8 * i, &cms[i]);
        context[CTX_INDICES + i] = F::from_u64(w.inputs[i].index);
        bits(&mut context, CTX_BITS + 40 * i, 40, w.inputs[i].index);
    }
    let mut values = vec![F::ZERO; height * WIDTH];
    let mut inputs = Vec::with_capacity(height);
    let mut outputs = Vec::with_capacity(height);
    let mut hashes = Vec::new();
    let mut state = [F::ZERO; 16];
    let mut rolling = [F::ZERO; 8];
    for row_idx in 0..height {
        let r = &mut values[row_idx * WIDTH..(row_idx + 1) * WIDTH];
        r[CTX..CTX + CONTEXT].copy_from_slice(&context);
        r[CURRENT..CURRENT + 8].copy_from_slice(&rolling);
        let op = air.program().op(row_idx);
        if let Some(o) = op {
            let n = if o.item < 2 {
                &w.inputs[o.item].note
            } else {
                &w.outputs[o.item - 2]
            };
            put(r, WORK_NOTE, n);
            if o.item < 2 {
                put(r, WORK_KEY, &w.inputs[o.item].key);
                put(r, WORK_ORIGIN, &w.inputs[o.item].origin);
                put(r, WORK_CM, &cms[o.item]);
            } else {
                put(r, WORK_CM, &s.commitments[o.item - 2]);
            }
            if o.role == 5 {
                put(r, SIBLING, &w.inputs[o.item].siblings[o.depth]);
                r[BRANCH] = F::from_u64((w.inputs[o.item].index >> o.depth) & 1);
            }
            if o.first() {
                state = [F::ZERO; 16];
            }
        } else {
            state = [F::ZERO; 16];
        }
        for j in 0..8 {
            let swap = r[BRANCH] * (r[SIBLING + j] - r[CURRENT + j]);
            r[LEFT + j] = r[CURRENT + j] + swap;
            r[RIGHT + j] = r[SIBLING + j] - swap;
        }
        for (i, &at) in [0, 2, 348, 352, 6].iter().enumerate() {
            if row_idx == at {
                let amount = if i < 2 {
                    w.inputs[i].note[1]
                } else if i < 4 {
                    w.outputs[i - 2][1]
                } else {
                    s.fee
                };
                bits(r, RANGE_A, 51, amount);
                bits(r, RANGE_D, 51, difference(MAX, amount));
            }
        }
        for (i, &at) in [10, 184].iter().enumerate() {
            if row_idx == at {
                bits(
                    r,
                    RANGE_A,
                    40,
                    difference(difference(s.count, 1), w.inputs[i].index),
                );
            }
        }
        let p = &air.program().preprocessing().values[row_idx * PP_WIDTH..(row_idx + 1) * PP_WIDTH];
        let add = message(r, p, &v);
        for j in 0..8 {
            state[j] += add[j];
        }
        inputs.push(state);
        let out = permutation::permute(state);
        outputs.push(out);
        state = out;
        if let Some(o) = op {
            if o.last() {
                hashes.push(core::array::from_fn(|j| out[j].as_canonical_u64()));
                if o.role == 4 || o.role == 5 {
                    rolling.copy_from_slice(&out[..8]);
                }
            }
        }
    }
    // Execute the actual retained P3 generator; do not synthesize its auxiliary prefix.
    let prefix = p3_poseidon2_air::generate_trace_rows::<F, Layers, 16, 7, 1, 4, 24>(
        inputs,
        &permutation::constants(),
        0,
    );
    assert_eq!(prefix.values.len(), height * permutation::PERM_COLS);
    for row in 0..height {
        let p = &prefix.values[row * permutation::PERM_COLS..(row + 1) * permutation::PERM_COLS];
        assert_eq!(
            &p[permutation::PERM_COLS - 16..],
            &outputs[row],
            "native/P3 permutation correspondence"
        );
        values[row * WIDTH..row * WIDTH + permutation::PERM_COLS].copy_from_slice(p);
    }
    Ok(Trace {
        matrix: RowMajorMatrix::new(values, WIDTH),
        hash_outputs: hashes,
    })
}
