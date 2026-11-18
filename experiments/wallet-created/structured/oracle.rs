use super::*;
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use std::collections::{BTreeMap, BTreeSet};
use tape::{Digest, Draw, hash, pack, unpack};

pub struct Oracle {
    columns: Vec<Vec<F>>,
    salts: Vec<Digest>,
    levels: Vec<Vec<Digest>>,
}

fn leaf(id: u8, index: usize, salt: &Digest, data: &[u8]) -> Digest {
    hash(
        b"rs-leaf",
        &[&[id], &(index as u32).to_le_bytes(), salt, data],
    )
}
fn node(id: u8, depth: usize, l: &Digest, r: &Digest) -> Digest {
    hash(b"rs-parent", &[&[id, depth as u8], l, r])
}
impl Oracle {
    pub fn new(id: u8, n: usize, rows: &[Vec<E>], rng: &mut Draw) -> Self {
        let dft = Radix2DitParallel::<F>::default();
        let mut columns = Vec::new();
        for row in rows {
            let mut limbs = vec![F::ZERO; 5 * n];
            for (dst, x) in limbs.chunks_exact_mut(5).zip(row) {
                dst.copy_from_slice(<E as BasedVectorSpace<F>>::as_basis_coefficients_slice(x));
            }
            let log_pad = (n / row.len().next_power_of_two()).ilog2() as usize;
            let transformed = dft.dft_batch_padded(RowMajorMatrix::new(limbs, 5), log_pad);
            columns.push(transformed.to_row_major_matrix().values);
        }
        let mut salts = vec![[0; 64]; n];
        let mut leaves = Vec::with_capacity(n);
        let mut buf = Vec::with_capacity(rows.len() * 40);
        for (i, salt) in salts.iter_mut().enumerate() {
            rng.bytes(salt);
            buf.clear();
            for col in &columns {
                for x in &col[5 * i..5 * i + 5] {
                    buf.extend_from_slice(&x.as_canonical_u64().to_le_bytes());
                }
            }
            leaves.push(leaf(id, i, salt, &buf));
        }
        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let depth = levels.len() - 1;
            let next = levels[depth]
                .chunks_exact(2)
                .map(|p| node(id, depth, &p[0], &p[1]))
                .collect();
            levels.push(next);
        }
        Self {
            columns,
            salts,
            levels,
        }
    }
    pub fn root(&self) -> Digest {
        self.levels.last().unwrap()[0]
    }
}
pub fn commit(t: &mut Tape, id: u8, oracle: Option<&Oracle>) -> Digest {
    t.message(
        &format!("rs-root-{id}"),
        oracle.map(|o| o.root()).as_ref().map(|r| r.as_slice()),
        64,
    )
    .try_into()
    .unwrap()
}

pub fn open(
    t: &mut Tape,
    id: u8,
    root: Digest,
    n: usize,
    width: usize,
    indices: &[usize],
    oracle: Option<&Oracle>,
) -> Vec<Vec<E>> {
    let distinct: BTreeSet<_> = indices.iter().copied().collect();
    let mut current = BTreeMap::new();
    let mut values = BTreeMap::new();
    for i in distinct {
        let raw = oracle.map(|o| {
            let row: Vec<E> = o
                .columns
                .iter()
                .map(|c| E::from_basis_coefficients_fn(|j| c[5 * i + j]))
                .collect();
            pack(&row)
        });
        let data = t.raw(raw.as_deref(), 40 * width);
        let salt: Digest = t
            .raw(oracle.map(|o| o.salts[i].as_slice()), 64)
            .try_into()
            .unwrap();
        current.insert(i, leaf(id, i, &salt, &data));
        values.insert(i, unpack(&data));
    }
    for depth in 0..n.ilog2() as usize {
        let missing: Vec<_> = current
            .keys()
            .map(|i| i ^ 1)
            .filter(|i| !current.contains_key(i))
            .collect();
        for i in missing {
            let digest = t
                .raw(oracle.map(|o| o.levels[depth][i].as_slice()), 64)
                .try_into()
                .unwrap();
            current.insert(i, digest);
        }
        current = current
            .keys()
            .copied()
            .filter(|i| i % 2 == 0)
            .map(|i| (i / 2, node(id, depth, &current[&i], &current[&(i + 1)])))
            .collect();
    }
    assert_eq!(current.len(), 1);
    assert!(current[&0] == root, "invalid Merkle opening");
    indices.iter().map(|i| values[i].clone()).collect()
}
