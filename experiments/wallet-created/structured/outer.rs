use super::*;
use tape::Draw;
const K: usize = OUTER_ROUNDS;

// Sum U on all Boolean extensions of prefix, including a zero-length suffix.
pub fn mask_sum(sigma: &[E], prefix: &[E], k: usize, d: usize) -> E {
    let remaining = k - prefix.len();
    let mut powers = vec![E::ZERO; d - 1];
    for &x in prefix {
        let mut p = x;
        for a in &mut powers[1..] {
            *a += p;
            p *= x;
        }
    }
    let half = F::TWO.inverse();
    let mut sum = E::ZERO;
    for i in 0..=k {
        let forced = k - i.max(prefix.len());
        let free = remaining - forced;
        let suffix: E = prefix[i.min(prefix.len())..].iter().copied().product();
        let factor = suffix * F::from_usize(1 << free);
        let mean = F::from_usize(forced) + F::from_usize(free) * half;
        for j in 0..d - 1 {
            let m = if j == 0 {
                E::ONE
            } else {
                powers[j] + E::from(mean)
            };
            sum += sigma[i * (d - 1) + j] * factor * m;
        }
    }
    sum
}

pub fn mask_weights(point: &[E], degree: usize) -> Vec<E> {
    let mut exps = vec![E::ONE];
    for e in 1..degree - 1 {
        exps.push(point.iter().map(|x| x.exp_u64(e as u64)).sum());
    }
    (0..=point.len())
        .flat_map(|i| {
            let s: E = point[i..].iter().copied().product();
            exps.iter().map(move |&p| p * s)
        })
        .collect()
}

// On each round, the outer unmasked polynomial factors into three linear
// polynomials. Only the final round has a nonzero terminal masking polynomial.
fn values_at_points(rows: &[Vec<E>; 3], basis: &[E], terminal: &[E], last: bool) -> [E; 6] {
    let mut v = [E::ZERO; 6];
    for pair in 0..rows[0].len() / 2 {
        let i = 2 * pair;
        let mut y = [rows[0][i], rows[1][i], rows[2][i], basis[i]];
        let delta = [
            rows[0][i + 1] - y[0],
            rows[1][i + 1] - y[1],
            rows[2][i + 1] - y[2],
            basis[i + 1] - y[3],
        ];
        for (x, a) in v.iter_mut().enumerate().take(if last { 6 } else { 4 }) {
            let mut z = y;
            if last {
                let mask = F::from_usize(x * x - x);
                for j in 0..3 {
                    z[j] += terminal[j] * mask;
                }
            }
            *a += (z[0] * z[1] - z[2]) * z[3];
            for j in 0..4 {
                y[j] += delta[j];
            }
        }
    }
    if !last {
        // Degree at most three before adding the independent degree-five mask.
        let coeff = interpolate(&v[..4]);
        v[4] = horner(&coeff, E::from_u8(4));
        v[5] = horner(&coeff, E::from_u8(5));
    }
    v
}

pub struct Secret {
    guard_words: usize,
    pub msg: Vec<E>,
    pub aux: Vec<E>,
    pub inner: Vec<E>,
    pub outer: Vec<E>,
    pub blind: Vec<F>,
}
impl Secret {
    pub fn new(assigned: &[F], public_len: usize, guard_words: usize, rng: &mut Draw) -> Self {
        assert!(public_len <= assigned.len() && assigned.len() - public_len <= MAIN_WORDS);
        assert!(guard_words <= assigned.len() - public_len);
        let mut msg: Vec<E> = assigned[public_len..]
            .iter()
            .copied()
            .map(E::from)
            .collect();
        msg.resize(MAIN_WORDS, E::ZERO);
        let inner = rng.fields(3);
        let outer = rng.fields(5 * (K + 1));
        let blind: Vec<_> = (0..4).map(|_| rng.base()).collect();
        let mut aux = inner.clone();
        aux.extend_from_slice(&outer);
        aux.extend(blind.iter().copied().map(E::from));
        aux.resize(16 * 8, E::ZERO);
        Self {
            msg,
            aux,
            inner,
            guard_words,
            outer,
            blind,
        }
    }
}
pub struct Claim {
    pub alpha: Vec<E>,
    pub rho: E,
    pub beta: Vec<F>,
    pub target: E,
    pub public_charge: Option<E>,
    pub aux: Vec<E>,
    pub dense: Option<Vec<E>>,
}
pub fn execute(
    t: &mut Tape,
    matrix: &Sparse,
    assigned: &[F],
    public: &[F],
    s: Option<&Secret>,
) -> Claim {
    let mu = s.map(|z| vec![mask_sum(&z.outer, &[], K, 6)]);
    let mut target = t.fields("outer-mask-cube-sum", mu.as_deref(), 1)[0];
    let mut bc = t.draw("four-base-guards");
    let beta: Vec<_> = (0..4).map(|_| bc.base()).collect();
    let bytes = s.map(|z| {
        let mut bytes = Vec::new();
        for (j, &b) in beta.iter().enumerate() {
            let y = assigned[public.len()..public.len() + z.guard_words]
                .iter()
                .rev()
                .fold(F::ZERO, |v, &w| v * b + w)
                * b
                + z.blind[j];
            bytes.extend_from_slice(&y.as_canonical_u64().to_le_bytes());
        }
        bytes
    });
    let guards: Vec<E> = t
        .message("guard-replies", bytes.as_deref(), 32)
        .chunks_exact(8)
        .map(|bytes| {
            let n = u64::from_le_bytes(bytes.try_into().unwrap());
            assert!(n < 0xffffffff00000001);
            E::from_u64(n)
        })
        .collect();
    let mut coins = t.draw("outer-zerocheck");
    let epsilon = coins.field();
    let tau = coins.fields(K);
    let mut alpha = Vec::new();
    let mut rows = s.map(|_| matrix.row_values(assigned));
    let mut basis = s.map(|_| eq(&tau));
    for j in 0..K {
        let coeff = s.map(|z| {
            let mut vals = values_at_points(
                rows.as_ref().unwrap(),
                basis.as_ref().unwrap(),
                &z.inner,
                j + 1 == K,
            );
            for (n, v) in vals.iter_mut().enumerate() {
                alpha.push(E::from_usize(n));
                *v = *v * epsilon + mask_sum(&z.outer, &alpha, K, 6);
                alpha.pop();
            }
            interpolate(&vals)
        });
        let c = t.fields(&format!("outer-polynomial-{j}"), coeff.as_deref(), 6);
        assert!(
            c[0] + c.iter().copied().sum::<E>() == target,
            "outer sumcheck"
        );
        let mut draw = t.draw(&format!("outer-point-{j}"));
        let mut x = draw.field();
        if j + 1 == K {
            while x == E::ZERO || x == E::ONE {
                x = draw.field();
            }
        }
        target = horner(&c, x);
        alpha.push(x);
        if let Some(v) = rows.as_mut() {
            for a in v {
                fold_adjacent(a, x);
            }
        }
        if let Some(a) = basis.as_mut() {
            fold_adjacent(a, x);
        }
    }
    let van = alpha[K - 1].square() - alpha[K - 1];
    let vs = s.map(|z| {
        (0..3)
            .map(|j| rows.as_ref().unwrap()[j][0] + z.inner[j] * van)
            .collect::<Vec<_>>()
    });
    let v = t.fields("outer-masked-terminals", vs.as_deref(), 3);
    let rho = t.draw("outer-batch").field();
    let mix = powers(rho, 8);
    let eqvalue: E = tau
        .iter()
        .zip(&alpha)
        .map(|(&a, &b)| a * b + (E::ONE - a) * (E::ONE - b))
        .product();
    target = dot(&mix[..3], &v)
        + mix[3] * (target - epsilon * (v[0] * v[1] - v[2]) * eqvalue)
        + dot(&mix[4..], &guards);
    // Public-half subtraction is performed once at the first fold, when the
    // structured verifier computes its public coefficients. The prover also
    // needs the unfolded private form for its inner sumcheck.
    let mut public_charge = None;
    let dense = s.map(|z| {
        let mut all = matrix.dense_form(&alpha, rho);
        let public_dot: E = all[..public.len()]
            .iter()
            .zip(public)
            .map(|(&x, &p)| x * p)
            .sum();
        let mut form = all.split_off(public.len());
        form.resize(MAIN_WORDS, E::ZERO);
        for (j, &b) in beta.iter().enumerate() {
            let mut p = b;
            for dst in &mut form[..z.guard_words] {
                *dst += mix[4 + j] * p;
                p *= b;
            }
        }
        // The auxiliary sumcheck uses the public part subtracted before its
        // rounds. Both parties independently derive it without a claimed hint.
        public_charge = Some(public_dot);
        form
    });
    let mut aux: Vec<E> = mix[..3].iter().map(|v| *v * van).collect();
    aux.extend(mask_weights(&alpha, 6).into_iter().map(|x| mix[3] * x));
    aux.extend_from_slice(&mix[4..]);
    aux.resize(128, E::ZERO);
    Claim {
        alpha,
        rho,
        beta,
        target,
        public_charge,
        aux,
        dense,
    }
}
