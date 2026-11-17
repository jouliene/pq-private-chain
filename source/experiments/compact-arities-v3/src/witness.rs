//! Exact-arity PUBLIC witness interface. Canonicality only; invalid semantics reach AIR.
use crate::{
    air::{PaymentAir, message},
    hash::{self, Digest},
    layout::*,
    permutation::{self, P},
    statement::{Arity, MAX, Statement},
};
pub use compact_payment_v1::witness::Input;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{GenericPoseidon2LinearLayersGoldilocks as Layers, Goldilocks as F};
use p3_matrix::dense::RowMajorMatrix;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Witness {
    pub inputs: Vec<Input>,
    pub outputs: [[u64; 20]; 2],
}
impl Witness {
    pub fn canonical(&self, arity: Arity) -> Result<(), String> {
        if self.inputs.len() != arity.n() {
            return Err("exact witness input arity".into());
        }
        for i in &self.inputs {
            if i.siblings.len() != 40 {
                return Err("path length".into());
            }
            if i.index >= P
                || i.note
                    .iter()
                    .chain(i.key.iter())
                    .chain(i.origin.iter())
                    .chain(i.siblings.iter().flatten())
                    .any(|&x| x >= P)
            {
                return Err("noncanonical input field/index".into());
            }
        }
        if self.outputs.iter().flatten().any(|&x| x >= P) {
            return Err("noncanonical output note".into());
        }
        Ok(())
    }
    pub fn commitments(&self, chain: &[u8; 32]) -> Vec<Digest> {
        self.inputs
            .iter()
            .map(|i| hash::hash(chain, hash::NOTE, &i.note))
            .collect()
    }
    pub fn nullifiers(&self, chain: &[u8; 32]) -> Vec<Digest> {
        let cms = self.commitments(chain);
        self.inputs
            .iter()
            .zip(cms)
            .map(|(i, cm)| {
                let mut b = i.key.to_vec();
                b.extend(i.origin);
                b.extend(cm);
                hash::hash(chain, hash::NF, &b)
            })
            .collect()
    }
    pub fn leaves(&self, chain: &[u8; 32]) -> Vec<Digest> {
        let cms = self.commitments(chain);
        self.inputs
            .iter()
            .zip(cms)
            .map(|(i, cm)| {
                let mut b = i.origin.to_vec();
                b.extend(cm);
                hash::hash(chain, hash::LEAF, &b)
            })
            .collect()
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
pub fn generate(air: &PaymentAir, s: &Statement, w: &Witness) -> Result<Trace, String> {
    let arity = air.program().arity();
    if s.arity != arity {
        return Err("trusted program/statement arity mismatch".into());
    }
    w.canonical(arity)?;
    let v = s.projection()?;
    let cms = w.commitments(&s.chain);
    let mut values = vec![F::ZERO; HEIGHT * WIDTH];
    let mut permutation_inputs = Vec::with_capacity(HEIGHT);
    let mut permutation_outputs = Vec::with_capacity(HEIGHT);
    let mut hashes = Vec::new();
    let mut state = [F::ZERO; 16];
    let mut rolling = [F::ZERO; 8];
    let mut balance = F::from_u64(s.credit);
    for row in 0..HEIGHT {
        let r = &mut values[row * WIDTH..(row + 1) * WIDTH];
        r[CURRENT..CURRENT + 8].copy_from_slice(&rolling);
        r[BALANCE] = balance;
        let op = air.program().op(row);
        if let Some(o) = op {
            let note_words = if o.item < 2 {
                &w.inputs[o.item].note
            } else {
                &w.outputs[o.item - 2]
            };
            put(r, note(0), note_words);
            put(r, WORK_NOTE, note_words);
            if o.item < 2 {
                let input = &w.inputs[o.item];
                put(r, key(0), &input.key);
                put(r, origin(0), &input.origin);
                put(r, cm(0), &cms[o.item]);
                r[index()] = F::from_u64(input.index);
                bits(r, bit(0), 40, input.index);
                put(r, WORK_KEY, &input.key);
                put(r, WORK_ORIGIN, &input.origin);
                put(r, WORK_CM, &cms[o.item]);
                if o.role == 5 {
                    put(r, SIBLING, &input.siblings[o.depth]);
                    r[BRANCH] = F::from_u64((input.index >> o.depth) & 1);
                }
            } else {
                put(r, WORK_CM, &s.commitments[o.item - 2]);
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
        let p = &air.program().preprocessing().values[row * PP_WIDTH..(row + 1) * PP_WIDTH];
        let mut range = None;
        for i in 0..arity.n() {
            if p[PP_RANGE + i] == F::ONE {
                range = Some(w.inputs[i].note[1]);
            }
        }
        for j in 0..2 {
            if p[PP_RANGE + 2 + j] == F::ONE {
                range = Some(w.outputs[j][1]);
            }
        }
        if p[PP_RANGE + 4] == F::ONE {
            range = Some(s.fee);
        }
        if p[PP_CREDIT] == F::ONE {
            range = Some(s.credit);
        }
        if let Some(x) = range {
            bits(r, RANGE_A, 51, x);
            bits(r, RANGE_D, 51, difference(MAX, x));
        }
        if p[PP_CREDIT_POS] == F::ONE {
            bits(r, RANGE_A, 51, difference(s.credit, 1));
        }
        for i in 0..arity.n() {
            if p[PP_INDEX + i] == F::ONE {
                bits(
                    r,
                    RANGE_A,
                    40,
                    difference(difference(s.count, 1), w.inputs[i].index),
                );
            }
        }
        let add = message(r, p, &v);
        for j in 0..8 {
            state[j] += add[j];
        }
        permutation_inputs.push(state);
        let out = permutation::permute(state);
        permutation_outputs.push(out);
        state = out;
        if let Some(o) = op {
            if o.last() {
                hashes.push(core::array::from_fn(|j| out[j].as_canonical_u64()));
                if o.role == 4 || o.role == 5 {
                    rolling.copy_from_slice(&out[..8]);
                }
            }
        }
        balance += p[PP_AMOUNT_SIGN] * r[note(1)] - p[PP_FEE] * F::from_u64(s.fee);
    }
    let prefix = p3_poseidon2_air::generate_trace_rows::<F, Layers, 16, 7, 1, 4, 24>(
        permutation_inputs,
        &permutation::constants(),
        0,
    );
    assert_eq!(prefix.values.len(), HEIGHT * permutation::PERM_COLS);
    for row in 0..HEIGHT {
        let r = &prefix.values[row * permutation::PERM_COLS..(row + 1) * permutation::PERM_COLS];
        assert_eq!(
            &r[permutation::PERM_COLS - 16..],
            &permutation_outputs[row],
            "native/P3 correspondence"
        );
        values[row * WIDTH..row * WIDTH + permutation::PERM_COLS].copy_from_slice(r);
    }
    Ok(Trace {
        matrix: RowMajorMatrix::new(values, WIDTH),
        hash_outputs: hashes,
    })
}
