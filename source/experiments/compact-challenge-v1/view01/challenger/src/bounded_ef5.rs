//! Experimental fixed-two sampler policy for the pinned Goldilocks X^5-3 power basis.
//! The caller MUST draw both candidates with the real Fixed(2) transcript operation.
//! This selector consumes no entropy and must never be used as a retry loop.
use p3_field::{ExtensionField, PrimeField64};
use thiserror::Error;

/// Bound into BOTH changed protocol seeds; incompatible with the scalar profiles.
pub const BOUNDED_EF5_POLICY: &[u8] = b"PQPC/bounded-ef5/v1\0Goldilocks/X^5-3/power-01234/Fixed2/first-outside-Fp/abort-both/no-retry";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum BoundedChallengeError {
    #[error("bounded EF5 policy requires the pinned Goldilocks X^5-3 power basis")]
    UnsupportedAlgebra,
    #[error("both fixed EF5 challenge candidates belong to the base field")]
    BothCandidatesInBaseField,
}

/// This is deliberately NOT a policy for arbitrary extension bases or composite degrees.
/// Actual source identity includes the modulus, reducer, degree and ordered power basis.
/// The field implementation and its AlgebraIdentity remain trusted compiled inputs.
pub fn select_bounded_ef5<F, EF>(candidates: [EF; 2]) -> Result<EF, BoundedChallengeError>
where
    F: PrimeField64,
    EF: ExtensionField<F>,
{
    if F::ORDER_U64 != 18_446_744_069_414_584_321
        || EF::DIMENSION != 5
        || EF::algebra_id().as_slice() != b"p3-power-basis-v1:X^5-3"
    {
        return Err(BoundedChallengeError::UnsupportedAlgebra);
    }
    // The vector draw has ALREADY consumed both candidates, including all ten coefficients.
    // In this exact basis, 1 spans Fp. Degree 5 is prime, so every other element has degree 5.
    candidates.into_iter().find(|value| {
        value.as_basis_coefficients_slice()[1..].iter().any(|c| *c != F::ZERO)
    }).ok_or(BoundedChallengeError::BothCandidatesInBaseField)
}
