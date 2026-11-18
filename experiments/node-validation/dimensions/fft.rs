//! Two full-length first-stage RS row encodings in the salted-burst geometry.
use super::F;
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use serde_json::{Value, json};
use std::time::Instant;
use tiny_keccak::{Hasher, Shake};

pub fn measure() -> Value {
    const LOG_N: usize = 21;
    const N: usize = 1 << LOG_N;
    const D: usize = 65600;
    let dft = Radix2DitParallel::<F>::default();
    let mut results = Vec::new();
    for row in 0..2u8 {
        // Public diagnostic coefficients. EF5 evaluations on a base subgroup are
        // five base transforms. This tests the real size without handling wallet secrets.
        let mut xof = Shake::v256();
        xof.update(b"CP03/CFW/first-rs-row");
        xof.update(&[row]);
        let mut seeds = vec![0u8; D * 5 * 8];
        xof.finalize(&mut seeds);
        let coeffs: Vec<_> = seeds
            .chunks_exact(8)
            .map(|w| F::from_u64(u64::from_le_bytes(w.try_into().unwrap())))
            .collect();
        let mut mat = vec![F::ZERO; N * 5];
        mat[..D * 5].copy_from_slice(&coeffs);
        let t = Instant::now();
        let cpu = super::matrix::cpu_time();
        let output = dft.dft_batch_padded(
            RowMajorMatrix::new(mat, 5),
            LOG_N - D.next_power_of_two().ilog2() as usize,
        );
        let elapsed = t.elapsed().as_secs_f64();
        let used = super::matrix::cpu_time() - cpu;
        assert_eq!(output.height(), N);
        let mut values = Vec::new();
        for i in [0, 1, 1919, N - 1] {
            let point = F::two_adic_generator(LOG_N).exp_u64(i as u64);
            let mut expected = [F::ZERO; 5];
            for c in coeffs.chunks_exact(5).rev() {
                for j in 0..5 {
                    expected[j] = expected[j] * point + c[j];
                }
            }
            for (j, e) in expected.iter().enumerate() {
                assert_eq!(output.get(i, j).unwrap(), *e);
            }
            values.push(expected.map(|v| v.as_canonical_u64()));
        }
        results.push(json!({"row":row, "fft_cpu_s":used, "fft_wall_s":elapsed, "horner_point_checks":values}));
    }
    json!({"n":N,"polynomial_coefficients":D,"extension_bytes":40,"row_output_bytes":N*40,
           "first_stage_rows":16,"single_thread":true,"runs":results})
}
