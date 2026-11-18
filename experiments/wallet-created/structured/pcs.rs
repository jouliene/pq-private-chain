use super::*;
use crate::oracle::{Oracle, commit, open};
use tape::Draw;

const Q: [usize; 4] = [53, 38, 30, 31];
const N: [usize; 4] = [1 << 21, 1 << 19, 1 << 17, 1 << 17];
const MAIN: [usize; 4] = [65536, 4096, 256, 256];
const AUX: [usize; 4] = [8, 5, 3, 37];

fn fold_rows(values: &mut Vec<E>, width: usize, g: E) {
    let half = values.len() / 2;
    for i in 0..half {
        let j = (i / width) * 2 * width + i % width;
        values[i] = values[j] + (values[j + width] - values[j]) * g;
    }
    values.truncate(half);
}

struct Stage {
    main: Vec<E>,
    aux: Vec<E>,
    masks: Vec<E>,
    seeds: Vec<E>,
    sigma: Vec<E>,
    oracle: Oracle,
}
impl Stage {
    fn new(i: usize, main: Vec<E>, aux: Vec<E>, rng: &mut Draw) -> Self {
        let k = if i == 3 { 0 } else { 4 };
        let width = 1 << k;
        assert_eq!(main.len(), width * MAIN[i]);
        assert_eq!(aux.len(), width * AUX[i]);
        let sigma = if k == 0 {
            vec![]
        } else {
            rng.fields(2 * (k + 1))
        };
        let mut masks = vec![];
        if k != 0 {
            for r in 0..width {
                for j in 0..2 {
                    let mut value = E::ZERO;
                    for t in 0..=k {
                        if (t..k).all(|b| (r >> b) & 1 == 1) {
                            value += sigma[2 * t + j];
                        }
                    }
                    masks.push(value);
                }
            }
        }
        let nr = Q[i] + 1;
        let seeds = rng.fields(width * nr);
        let mut rows = Vec::new();
        for r in 0..width {
            let mut row = seeds[r * nr..(r + 1) * nr].to_vec();
            if k != 0 {
                row.extend_from_slice(&masks[r * 2..r * 2 + 2]);
            }
            row.extend_from_slice(&main[r * MAIN[i]..(r + 1) * MAIN[i]]);
            row.extend_from_slice(&aux[r * AUX[i]..(r + 1) * AUX[i]]);
            rows.push(row);
        }
        let oracle = Oracle::new(i as u8, N[i], &rows, rng);
        Self {
            main,
            aux,
            masks,
            seeds,
            sigma,
            oracle,
        }
    }
}
pub struct Start(Option<Stage>, [u8; 64]);
pub fn start(t: &mut Tape, s: Option<&outer::Secret>, rng: &mut Option<Draw>) -> Start {
    let data = s.map(|z| Stage::new(0, z.msg.clone(), z.aux.clone(), rng.as_mut().unwrap()));
    let root = commit(t, 0, data.as_ref().map(|v| &v.oracle));
    Start(data, root)
}

fn batch_coefficients(form: &[E], message: &[E], width: usize, out: &mut [E; 3]) {
    // Coefficients of the dot product of the interpolated two rows.
    for start in (0..message.len()).step_by(2 * width) {
        for j in 0..width {
            let a = form[start + j];
            let b = message[start + j];
            let da = form[start + width + j] - a;
            let db = message[start + width + j] - b;
            out[0] += a * b;
            out[1] += a * db + b * da;
            out[2] += da * db;
        }
    }
}
#[derive(Clone, Copy)]
struct Geom {
    scale: E,
    ratio: E,
}
impl Geom {
    fn fix(&mut self, width: usize, gamma: &[E]) {
        let mut stride = self.ratio.exp_u64(width as u64);
        for &g in gamma {
            self.scale *= E::ONE + g * (stride - E::ONE);
            stride = stride.square();
        }
    }
    fn add_to(&self, buf: &mut [E]) {
        let mut v = self.scale;
        for x in buf {
            *x += v;
            v *= self.ratio;
        }
    }
}
fn folded_value(v: &[E], weights: &[E]) -> E {
    dot(v, weights)
}

pub fn execute(
    t: &mut Tape,
    plan: Option<&matrix::Plan>,
    mut claim: outer::Claim,
    public: &[F],
    initial: Start,
    rng: &mut Option<Draw>,
) {
    let Start(mut stage, mut root) = initial;
    let mut main_form = claim.dense.take().unwrap_or_default();
    let mut aux_form = claim.aux;
    let mut pending: Vec<Geom> = Vec::new();
    let mut target = claim.target;
    let mut initial_check = None;
    for i in 0..3 {
        let prefix = format!("stage-{i}");
        let m = MAIN[i];
        let a = AUX[i];
        let nr = Q[i] + 1;
        let mask_sum = stage
            .as_ref()
            .map(|s| vec![outer::mask_sum(&s.sigma, &[], 4, 3)]);
        let mu = t.fields(&format!("{prefix}-mask-sum"), mask_sum.as_deref(), 1)[0];
        let epsilon = t.draw(&format!("{prefix}-mask-mix")).field();
        target = mu + epsilon * target;
        if i == 0 && t.proving {
            target -= epsilon * claim.public_charge.unwrap();
        }
        let mut gamma = vec![];
        for bit in 0..4 {
            let cs = stage.as_ref().map(|s| {
                let mut coefficients = [E::ZERO; 3];
                batch_coefficients(&main_form, &s.main, m, &mut coefficients);
                batch_coefficients(&aux_form, &s.aux, a, &mut coefficients);
                let mut values = [E::ZERO; 3];
                for (j, v) in values.iter_mut().enumerate() {
                    let x = E::from_usize(j);
                    gamma.push(x);
                    *v = outer::mask_sum(&s.sigma, &gamma, 4, 3)
                        + epsilon * horner(&coefficients, x);
                    gamma.pop();
                }
                interpolate(&values)
            });
            let coeff = t.fields(&format!("{prefix}-polynomial-{bit}"), cs.as_deref(), 3);
            let got = coeff[0] + coeff.iter().copied().sum::<E>();
            if i == 0 && bit == 0 && !t.proving {
                initial_check = Some((target, got, epsilon));
            } else {
                assert!(target == got, "inner sumcheck");
            }
            let g = t.draw(&format!("{prefix}-point-{bit}")).field();
            gamma.push(g);
            target = horner(&coeff, g);
            if i != 0 || t.proving {
                fold_rows(&mut main_form, m, g);
            }
            fold_rows(&mut aux_form, a, g);
            if let Some(s) = stage.as_mut() {
                fold_rows(&mut s.main, m, g);
                fold_rows(&mut s.aux, a, g);
                fold_rows(&mut s.seeds, nr, g);
                fold_rows(&mut s.masks, 2, g);
            }
        }
        if i == 0 && !t.proving {
            let (p, main, _, _) = plan
                .unwrap()
                .apply(&claim.alpha, claim.rho, &claim.beta, &gamma);
            let subtraction: E = p.iter().zip(public).map(|(&v, &w)| v * w).sum();
            let (before, got, mix) = initial_check.unwrap();
            assert!(before - mix * subtraction == got, "public half");
            main_form = main;
        }
        for x in &mut main_form {
            *x *= epsilon;
        }
        for term in &mut pending {
            term.fix(m, &gamma);
            term.scale *= epsilon;
        }
        for v in &mut aux_form {
            *v *= epsilon;
        }
        aux_form.push(E::ONE);
        aux_form.push(gamma.iter().copied().sum());
        aux_form.resize(a + 2 + nr, E::ZERO);
        let width_next = if i == 2 { 1 } else { 16 };
        let next_a = AUX[i + 1] * width_next;
        let pad = next_a - aux_form.len();
        assert!(pad >= 1);
        let next = stage.as_ref().map(|s| {
            let mut aux = s.aux.clone();
            aux.extend_from_slice(&s.masks);
            aux.extend_from_slice(&s.seeds);
            aux.extend(rng.as_mut().unwrap().fields(pad));
            Stage::new(i + 1, s.main.clone(), aux, rng.as_mut().unwrap())
        });
        let next_root = commit(t, (i + 1) as u8, next.as_ref().map(|z| &z.oracle));
        let mut coin = t.draw(&format!("{prefix}-ood-vector"));
        let x = coin.field();
        let mut pad_weights = coin.fields(pad);
        while pad_weights.iter().all(|&v| v == E::ZERO) {
            pad_weights = coin.fields(pad);
        }
        let mut ood_tail = powers(x, aux_form.len());
        let xmain = x.exp_u64(m as u64);
        for v in &mut ood_tail {
            *v *= xmain;
        }
        ood_tail.extend_from_slice(&pad_weights);
        let answer = next
            .as_ref()
            .map(|s| vec![horner(&s.main, x) + dot(&ood_tail, &s.aux)]);
        let ans = t.fields(&format!("{prefix}-ood-answer"), answer.as_deref(), 1)[0];
        let mut sampling = t.draw(&format!("{prefix}-queries-and-batch"));
        let indices: Vec<_> = (0..Q[i]).map(|_| sampling.index(N[i])).collect();
        let mix = powers(sampling.field(), Q[i] + 2);
        let values = open(
            t,
            i as u8,
            root,
            N[i],
            16,
            &indices,
            stage.as_ref().map(|s| &s.oracle),
        );
        let weights = eq(&gamma);
        target += mix[1] * ans;
        aux_form.resize(next_a, E::ZERO);
        for (v, &u) in aux_form.iter_mut().zip(&ood_tail) {
            *v += mix[1] * u;
        }
        pending.push(Geom {
            scale: mix[1],
            ratio: x,
        });
        let omega = F::two_adic_generator(N[i].ilog2() as usize);
        for (h, (&idx, row)) in indices.iter().zip(values).enumerate() {
            let z = omega.exp_u64(idx as u64);
            let weight = mix[h + 2];
            target += weight * folded_value(&row, &weights);
            let z_before = z.exp_u64((nr + 2) as u64);
            pending.push(Geom {
                scale: weight * z_before,
                ratio: E::from(z),
            });
            let mut pos = z_before * z.exp_u64(m as u64);
            for v in &mut aux_form[..a] {
                *v += weight * pos;
                pos *= z;
            }
            pos = z.exp_u64(nr as u64);
            for v in &mut aux_form[a..a + 2] {
                *v += weight * pos;
                pos *= z;
            }
            pos = F::ONE;
            for v in &mut aux_form[a + 2..a + 2 + nr] {
                *v += weight * pos;
                pos *= z;
            }
        }
        if t.proving || i == 2 {
            for term in pending.drain(..) {
                term.add_to(&mut main_form);
            }
        }
        stage = next;
        root = next_root;
    }
    let mut form = main_form;
    form.extend_from_slice(&aux_form);
    assert_eq!(form.len(), 293);
    let fresh = if t.proving {
        let rand = rng.as_mut().unwrap();
        let b = rand.fields(form.len());
        let seed = rand.fields(Q[3] + 1);
        let mut coeff = seed;
        coeff.extend_from_slice(&b);
        let o = Oracle::new(4, N[3], &[coeff.clone()], rand);
        Some((coeff, o))
    } else {
        None
    };
    let fresh_root = commit(t, 4, fresh.as_ref().map(|(_, o)| o));
    let nr = Q[3] + 1;
    let masked = fresh.as_ref().map(|(v, _)| vec![dot(&form, &v[nr..])]);
    let mask = t.fields("base-mask-target", masked.as_deref(), 1)[0];
    let delta = t.draw("base-challenge").field();
    let data = fresh.as_ref().map(|(v, _)| {
        let s = stage.as_ref().unwrap();
        let msg = s.seeds.iter().chain(&s.main).chain(&s.aux);
        msg.zip(v).map(|(&x, &b)| b + delta * x).collect::<Vec<_>>()
    });
    let combined = t.fields("base-blinded-codeword", data.as_deref(), nr + form.len());
    assert!(
        dot(&form, &combined[nr..]) == mask + delta * target,
        "terminal linear form"
    );
    let mut coin = t.draw("base-sample");
    let idx: Vec<_> = (0..Q[3]).map(|_| coin.index(N[3])).collect();
    let left = open(t, 3, root, N[3], 1, &idx, stage.as_ref().map(|z| &z.oracle));
    let right = open(
        t,
        4,
        fresh_root,
        N[3],
        1,
        &idx,
        fresh.as_ref().map(|(_, o)| o),
    );
    let omega = F::two_adic_generator(N[3].ilog2() as usize);
    for ((i, l), r) in idx.into_iter().zip(left).zip(right) {
        assert!(
            horner(&combined, E::from(omega.exp_u64(i as u64))) == r[0] + delta * l[0],
            "terminal RS check"
        );
    }
    t.end();
}
