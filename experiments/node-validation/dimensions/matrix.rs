//! Measure a reusable public sparse-matrix representation and the verifier's
//! statement-specific outer linear-form construction before verification of any PCS.
use super::{F, Form};
use p3_field::{
    BasedVectorSpace, PrimeCharacteristicRing, PrimeField64, extension::BinomialExtensionField,
};
use serde_json::{Value, json};
use std::time::Instant;
use tiny_keccak::{Hasher, Shake};

type E = BinomialExtensionField<F, 5>;

pub(super) fn cpu_time() -> f64 {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // CLOCK_THREAD_CPUTIME_ID covers this single-threaded kernel, excluding scheduler waits.
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut t) },
        0
    );
    t.tv_sec as f64 + t.tv_nsec as f64 * 1e-9
}

#[derive(Default)]
pub struct Sparse {
    rows: Vec<[u32; 3]>,
    terms: Vec<(u32, F)>,
}
impl Sparse {
    pub fn add(&mut self, forms: [&Form; 3]) {
        let mut ends = [0; 3];
        for (i, f) in forms.iter().enumerate() {
            for (&column, &value) in &f.0 {
                self.terms.push((column.try_into().unwrap(), value));
            }
            ends[i] = self.terms.len().try_into().unwrap();
        }
        self.rows.push(ends);
    }
    pub fn measure(&self, instance: &[u8]) -> Value {
        assert_eq!(self.rows.len(), 614387);
        assert_eq!(instance.len(), 528);
        let t = Instant::now();
        let cpu_start = cpu_time();
        let mut shake = Shake::v256();
        shake.update(b"CP03/CFW/public-matrix-component/v1");
        shake.update(instance);
        let mut bytes = [0u8; 1536];
        shake.finalize(&mut bytes);
        let mut words = bytes
            .chunks_exact(8)
            .map(|w| u64::from_le_bytes(w.try_into().unwrap()))
            .filter(|&w| w < 0xffffffff00000001);
        let mut draw = || E::from_basis_coefficients_fn(|_| F::from_u64(words.next().unwrap()));
        // A 2*ell square verifier matrix. Only its first rows have nonzero entries.
        let mut equality = vec![E::ONE];
        for _ in 0..21 {
            let alpha = draw();
            let count = equality.len();
            let size = (count * 2).min(self.rows.len());
            equality.resize(size, E::ZERO);
            for i in 0..count {
                let right = equality[i] * alpha;
                equality[i] -= right;
                if i + count < size {
                    equality[i + count] = right;
                }
            }
        }
        let rho = draw();
        let mix = [E::ONE, rho, rho * rho];
        // Omit the known zero padding of the public half. It has zero coefficients.
        let mut form = vec![E::ZERO; 50 + 612532];
        let basis_s = t.elapsed().as_secs_f64();
        let mut start = 0;
        for (row, &eq) in self.rows.iter().zip(&equality) {
            for j in 0..3 {
                let scaled = eq * mix[j];
                let end = row[j] as usize;
                for &(col, c) in &self.terms[start..end] {
                    form[col as usize] += scaled * c;
                }
                start = end;
            }
        }
        assert_eq!(start, self.terms.len());
        let contraction_s = t.elapsed().as_secs_f64();
        let contraction_cpu = cpu_time() - cpu_start;
        // CFW guarded map: four base seeds bind the first 296448 witness wires.
        // The first three batching coefficients are 1, rho and rho^2; the fourth
        // is for the outer mask, subsequent powers are for the four subfield sums.
        let betas: [F; 4] = core::array::from_fn(|_| F::from_u64(words.next().unwrap()));
        let mut powers = betas;
        let mixes = core::array::from_fn::<_, 4, _>(|i| rho.exp_u64((i + 4) as u64));
        // Separate public prefix, store only the real private half and its zero padding.
        let mut private = vec![E::ZERO; 1 << 20];
        private[..612532].copy_from_slice(&form[50..]);
        for elem in &mut private[..296448] {
            for i in 0..4 {
                *elem += mixes[i] * powers[i];
                powers[i] *= betas[i];
            }
        }
        let mut active = private.len();
        // Interleave 16 rows of 2^16 columns. Fold adjacent rows in row-index bit order.
        // Only the main witness contribution is timed here. Mask and OOD entries are extra.
        for _ in 0..4 {
            let gamma = <E as BasedVectorSpace<F>>::from_basis_coefficients_fn(|_| {
                F::from_u64(words.next().unwrap())
            });
            for group in 0..active / (2 * 65536) {
                for j in 0..65536 {
                    let a = private[2 * group * 65536 + j];
                    let b = private[(2 * group + 1) * 65536 + j];
                    private[group * 65536 + j] = a + (b - a) * gamma;
                }
            }
            active /= 2;
        }
        assert_eq!(active, 65536);
        let stage_cpu = cpu_time() - cpu_start;
        let stage_wall = t.elapsed().as_secs_f64();
        let mut h = Shake::v256();
        for e in form.iter().chain(&private[..active]) {
            for c in <E as BasedVectorSpace<F>>::as_basis_coefficients_slice(e) {
                h.update(&c.as_canonical_u64().to_le_bytes());
            }
        }
        let mut out = [0u8; 32];
        h.finalize(&mut out);
        json!({"basis_and_contract_seconds":contraction_s,"basis_seconds":basis_s,"basis_and_contract_cpu_s":contraction_cpu,
            "through_guard_and_main_fold_cpu_s":stage_cpu,"through_guard_and_main_fold_wall_s":stage_wall,
          "combined_sparse_matrix_terms":start,"nonpadding_output_capacity":form.len(),
          "digest":"SHAKE256/32","combined_form_hex":out.iter().map(|x|format!("{x:02x}")).collect::<String>(),
          "prepared_matrix_used_bytes":self.rows.len()*size_of::<[u32;3]>()+self.terms.len()*size_of::<(u32,F)>(),
          "prepared_matrix_allocated_bytes":self.rows.capacity()*size_of::<[u32;3]>()+self.terms.capacity()*size_of::<(u32,F)>(),
          "postcheck_digest_outside_measured_interval":true})
    }
}
