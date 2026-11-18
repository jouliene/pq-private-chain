// Included inside the frozen sparse-matrix module. The plan contains public data only.
use std::collections::{BTreeMap as Ordered, HashMap as Map};

const BLOCK: usize = 256;
const WIDTH: usize = 65536;
const PUB: usize = 50;
const WORDS: usize = 296448;

type Term = (u8, u8, u64);
#[derive(Default)]
pub(super) struct Plan {
    // A pattern is the polynomial in low row-index bits and the A/B/C mix.
    patterns: Vec<Vec<Term>>,
    // (row block, folded row or public sentinel), (pattern, destination run).
    tiles: Vec<(u16, u8, Vec<(u32, Vec<u32>)>)>,
}

impl Sparse {
    pub(super) fn plan(&self) -> Plan {
        let mut plan = Plan::default();
        let mut dictionary: Map<Vec<Term>, u32> = Map::new();
        let mut start = 0;
        for (h, rows) in self.rows.chunks(BLOCK).enumerate() {
            let mut columns: Ordered<u32, Vec<Term>> = Ordered::new();
            for (l, row) in rows.iter().enumerate() {
                for (j, &end) in row.iter().enumerate() {
                    for &(column, coeff) in &self.terms[start..end as usize] {
                        columns.entry(column).or_default().push((
                            l as u8,
                            j as u8,
                            coeff.as_canonical_u64(),
                        ));
                    }
                    start = end as usize;
                }
            }
            let mut tiles: Ordered<u8, Ordered<u32, Vec<u32>>> = Ordered::new();
            for (column, pattern) in columns {
                let column = column as usize;
                let (q, dest) = if column < PUB {
                    (16, column)
                } else {
                    ((column - PUB) / WIDTH, (column - PUB) % WIDTH)
                };
                let id = *dictionary.entry(pattern).or_insert_with_key(|key| {
                    let id = plan.patterns.len() as u32;
                    plan.patterns.push(key.clone());
                    id
                });
                tiles
                    .entry(q as u8)
                    .or_default()
                    .entry(id)
                    .or_default()
                    .push(dest as u32);
            }
            for (q, runs) in tiles {
                plan.tiles.push((h as u16, q, runs.into_iter().collect()));
            }
        }
        plan
    }
}

fn eq_basis(point: &[E]) -> Vec<E> {
    let mut weights = vec![E::ONE];
    for &x in point {
        let n = weights.len();
        weights.resize(2 * n, E::ZERO);
        for j in 0..n {
            let right = weights[j] * x;
            weights[j] -= right;
            weights[j + n] = right;
        }
    }
    weights
}

fn challenge_words(instance: &[u8]) -> Vec<F> {
    assert_eq!(instance.len(), 528);
    let mut hash = Shake::v256();
    hash.update(b"CP03/CFW/public-matrix-component/v1");
    hash.update(instance);
    let mut data = [0u8; 1536];
    hash.finalize(&mut data);
    data.chunks_exact(8)
        .map(|x| u64::from_le_bytes(x.try_into().unwrap()))
        .filter(|&x| x < 0xffffffff00000001)
        .map(F::from_u64)
        .collect()
}

fn digest_outputs(public: &[E], private: &[E]) -> String {
    let mut hash = Shake::v256();
    for value in public.iter().chain(private) {
        for c in <E as BasedVectorSpace<F>>::as_basis_coefficients_slice(value) {
            hash.update(&c.as_canonical_u64().to_le_bytes());
        }
    }
    let mut data = [0; 32];
    hash.finalize(&mut data);
    data.iter().map(|x| format!("{x:02x}")).collect()
}

impl Plan {
    pub(super) fn counts(&self) -> Value {
        json!({"dictionary_patterns": self.patterns.len(),
               "dictionary_terms":self.patterns.iter().map(Vec::len).sum::<usize>(),
               "tiles": self.tiles.len(),
               "tile_pattern_products": self.tiles.iter().map(|x| x.2.len()).sum::<usize>(),
               "column_additions": self.tiles.iter().flat_map(|x| &x.2).map(|x| x.1.len()).sum::<usize>()})
    }
    pub(super) fn eval(&self, data: &[u8]) -> Value {
        let cpu = cpu_time();
        let t = Instant::now();
        let words = challenge_words(data);
        let e = |offset| E::from_basis_coefficients_fn(|i| words[offset + i]);
        let alpha: Vec<E> = (0..21).map(|i| e(i * 5)).collect();
        let rho = e(105);
        let beta = &words[110..114];
        let gamma: Vec<E> = (0..4).map(|i| e(114 + i * 5)).collect();
        let (public, private, pattern_cpu, matrix_cpu) = self.apply(&alpha, rho, beta, &gamma);
        let cpu_s = cpu_time() - cpu;
        let wall = t.elapsed().as_secs_f64();
        json!({"thread_cpu_s":cpu_s,"wall_s":wall,"pattern_cpu_s":pattern_cpu,
               "through_tile_matrix_cpu_s":matrix_cpu,"public_and_fold_shake256_32":digest_outputs(&public,&private)})
    }
    pub(super) fn apply(
        &self,
        alpha: &[E],
        rho: E,
        beta: &[F],
        gamma: &[E],
    ) -> (Vec<E>, Vec<E>, f64, f64) {
        let cpu = cpu_time();
        let low = eq_basis(&alpha[..8]);
        let high = eq_basis(&alpha[8..]);
        let fold = eq_basis(&gamma);
        let mixes = [E::ONE, rho, rho.square()];
        let weighted: Vec<[E; 3]> = low.iter().map(|&x| mixes.map(|m| m * x)).collect();
        let vals: Vec<E> = self
            .patterns
            .iter()
            .map(|pat| {
                pat.iter().fold(E::ZERO, |s, &(l, j, c)| {
                    s + weighted[l as usize][j as usize] * F::from_u64(c)
                })
            })
            .collect();
        let pattern_cpu = cpu_time() - cpu;
        let mut public = vec![E::ZERO; PUB];
        let mut private = vec![E::ZERO; WIDTH];
        for (h, q, runs) in &self.tiles {
            let (out, scale) = if *q == 16 {
                (&mut public, high[*h as usize])
            } else {
                (&mut private, high[*h as usize] * fold[*q as usize])
            };
            for (id, dests) in runs {
                let term = scale * vals[*id as usize];
                for &dest in dests {
                    out[dest as usize] += term;
                }
            }
        }
        let matrix_cpu = cpu_time() - cpu;
        // Geometric guard splits into whole live rows and one partial row.
        let full = WORDS / WIDTH;
        let partial = WORDS % WIDTH;
        for (j, &base) in beta.iter().enumerate() {
            let stride = base.exp_u64(WIDTH as u64);
            let r = rho.exp_u64(4 + j as u64);
            let mut power = F::ONE;
            let mut total = E::ZERO;
            for &weight in &fold[..full] {
                total += weight * power;
                power *= stride;
            }
            let prefix = r * (total + fold[full] * power);
            let suffix = r * total;
            power = base;
            for x in &mut private[..partial] {
                *x += prefix * power;
                power *= base;
            }
            for x in &mut private[partial..] {
                *x += suffix * power;
                power *= base;
            }
        }
        (public, private, pattern_cpu, matrix_cpu)
    }
}
