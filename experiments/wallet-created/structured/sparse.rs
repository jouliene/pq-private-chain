impl Sparse {
    pub(super) fn row_values(&self, z: &[F]) -> [Vec<E>; 3] {
        let mut output: [Vec<E>; 3] = std::array::from_fn(|_| Vec::with_capacity(1 << 21));
        let mut at = 0;
        for row in &self.rows {
            for j in 0..3 {
                let end = row[j] as usize;
                let sum: F = self.terms[at..end]
                    .iter()
                    .map(|&(col, c)| z[col as usize] * c)
                    .sum();
                output[j].push(E::from(sum));
                at = end;
            }
        }
        for v in &mut output {
            v.resize(1 << 21, E::ZERO);
        }
        output
    }
    pub(super) fn dense_form(&self, alpha: &[E], rho: E) -> Vec<E> {
        let eq = eq_basis(alpha);
        let mix = [E::ONE, rho, rho.square()];
        let mut out = vec![E::ZERO; 50 + 612532];
        let mut at = 0;
        for (row, w) in self.rows.iter().zip(eq) {
            for j in 0..3 {
                let end = row[j] as usize;
                let s = w * mix[j];
                for &(c, k) in &self.terms[at..end] {
                    out[c as usize] += s * k;
                }
                at = end;
            }
        }
        out
    }
}
