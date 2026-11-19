// Distinct proof commitment and transcript profile. The monetary circuit is unchanged.
use plonky2::field::extension::quadratic::QuadraticExtension;
use plonky2::hash::keccak::KeccakHash;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct C;
impl GenericConfig<2> for C {
    type F = qnero_circuit::F;
    type FE = QuadraticExtension<Self::F>;
    type Hasher = KeccakHash<32>;
    type InnerHasher = <PoseidonGoldilocksConfig as GenericConfig<2>>::InnerHasher;
}
pub type Proof = ProofWithPublicInputs<qnero_circuit::F, C, 2>;
