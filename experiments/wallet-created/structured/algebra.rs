use super::*;
pub(super) fn eq(xs: &[E]) -> Vec<E> {
    let mut v = vec![E::ONE];
    for &x in xs {
        let n = v.len();
        v.resize(2 * n, E::ZERO);
        for i in 0..n {
            let y = v[i] * x;
            v[i] -= y;
            v[n + i] = y;
        }
    }
    v
}
pub(super) fn powers(x: E, n: usize) -> Vec<E> {
    let mut v = vec![E::ONE; n];
    for i in 1..n {
        v[i] = v[i - 1] * x;
    }
    v
}
pub(super) fn horner(c: &[E], x: E) -> E {
    c.iter().rev().fold(E::ZERO, |v, &a| v * x + a)
}
pub(super) fn dot(a: &[E], b: &[E]) -> E {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b).map(|(&x, &y)| x * y).sum()
}
pub(super) fn interpolate(input: &[E]) -> Vec<E> {
    let mut ds = input.to_vec();
    let mut form = vec![F::ONE];
    let mut out = vec![E::ZERO; ds.len()];
    for i in 0..input.len() {
        for (j, &c) in form.iter().enumerate() {
            out[j] += ds[0] * c;
        }
        for j in 1..ds.len() {
            ds[j - 1] = ds[j] - ds[j - 1];
        }
        ds.pop();
        let mut next = vec![F::ZERO; form.len() + 1];
        for (j, &c) in form.iter().enumerate() {
            next[j] -= c * F::from_usize(i);
            next[j + 1] += c;
        }
        let inv = F::from_usize(i + 1).inverse();
        for c in &mut next {
            *c *= inv;
        }
        form = next;
    }
    out
}
pub(super) fn fold_adjacent(v: &mut Vec<E>, x: E) {
    for i in 0..v.len() / 2 {
        let lo = v[2 * i];
        v[i] = lo + (v[2 * i + 1] - lo) * x;
    }
    v.truncate(v.len() / 2);
}
