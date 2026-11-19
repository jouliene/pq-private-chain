//! TKN1 private two-lane spend relation.
use anyhow::{anyhow, ensure, Context, Result};
use plonky2::field::types::Field;
use plonky2::fri::FriReductionStrategy;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::{
    circuit_builder::CircuitBuilder,
    circuit_data::{CircuitData, VerifierCircuitData},
};
use plonky2::util::serialization::DefaultGateSerializer;
use qnero_aggregator::Proof;
use qnero_circuit::{
    circuit::{build_constraints, SpendTargets},
    config::qnero_leaf_zk_circuit_config,
    convert::digest_to_hashout,
    note_gadget::hash_with_domain,
    witness::{fill_witness, SpendWitness},
    C, D, F,
};
use qnero_notes::{Digest, Felt};
use std::{fs, path::Path};

pub const OPEN: Felt = Felt::new(0x544b4e310001);
pub type Verifier = VerifierCircuitData<F, C, D>;
struct Targets {
    base: SpendTargets,
    token: [Target; 4],
    raw: [HashOutTarget; 4],
}
pub fn typed(token: u64, raw: Digest) -> Digest {
    Digest::hash_felts(OPEN, &[&[Felt::new(token)], raw.felts()])
}

fn circuit() -> (CircuitBuilder<F, D>, Targets) {
    let mut c = qnero_leaf_zk_circuit_config();
    c.num_wires = 135;
    c.num_routed_wires = 60;
    c.security_bits = 128;
    c.num_challenges = 2;
    c.fri_config.rate_bits = 5;
    c.fri_config.cap_height = 4;
    c.fri_config.num_query_rounds = 26;
    c.fri_config.proof_of_work_bits = 0;
    c.fri_config.reduction_strategy = FriReductionStrategy::ConstantArityBits(2, 3);
    assert!(c.zero_knowledge);
    let mut b = CircuitBuilder::new(c);
    let base = SpendTargets::new(&mut b);
    build_constraints(&base, &mut b);
    let zero = b.zero();
    let fee = b.constant(F::from_canonical_u64(3));
    b.connect(base.fee, fee);

    let token = std::array::from_fn(|_| b.add_virtual_target());
    let raw = std::array::from_fn(|_| b.add_virtual_hash());
    for (i, r) in [
        base.inputs[0].r,
        base.inputs[1].r,
        base.outputs[0].r,
        base.outputs[1].r,
    ]
    .into_iter()
    .enumerate()
    {
        b.range_check(token[i], 62);
        let typed = hash_with_domain(&mut b, OPEN, &[&[token[i]], &raw[i].elements]);
        b.connect_hashes(typed, r);
    }
    for (i, input) in base.inputs.iter().enumerate() {
        let dummy_tokens = b.mul(token[i], input.is_dummy.target);
        b.connect(dummy_tokens, zero);
    }
    let input = b.add(token[0], token[1]);
    let output = b.add(token[2], token[3]);
    b.connect(input, output);
    (b, Targets { base, token, raw })
}
fn bytes(v: &Verifier) -> Result<Vec<u8>> {
    ensure!(
        v.common.config.zero_knowledge
            && v.common.fri_params.leaf_hiding
            && v.common.num_public_inputs == 26
            && D == 2,
        "suite"
    );
    v.to_bytes(&DefaultGateSerializer)
        .map_err(|_| anyhow!("verifier encoding"))
}
pub fn register(dir: &Path) -> Result<()> {
    let (b, _) = circuit();
    let gates = b.num_gates();
    let v = b.build_verifier::<C>();
    fs::create_dir(dir)?;
    fs::write(dir.join("token.vk"), bytes(&v)?)?;
    println!("{{\"suite\":\"TKN1\",\"gates_before_blinding\":{},\"degree_bits\":{},\"folds\":{:?},\"public_inputs\":26}}",gates,v.common.degree_bits(),v.common.fri_params.reduction_arity_bits);
    Ok(())
}
pub fn load(dir: &Path) -> Result<Verifier> {
    let v = circuit().0.build_verifier::<C>();
    ensure!(
        bytes(&v)? == fs::read(dir.join("token.vk"))?,
        "operator registration"
    );
    Ok(v)
}
pub struct WalletProver {
    targets: Targets,
    data: CircuitData<F, C, D>,
}
impl WalletProver {
    pub fn new(dir: &Path) -> Result<Self> {
        let (b, targets) = circuit();
        let data = b.build::<C>();
        ensure!(
            bytes(&data.verifier_data())? == fs::read(dir.join("token.vk"))?,
            "wallet registration"
        );
        Ok(Self { targets, data })
    }
    pub fn prove(&self, w: &SpendWitness, opened: [(u64, Digest); 4]) -> Result<Proof> {
        w.validate()?;
        let mut witness = PartialWitness::new();
        fill_witness(&mut witness, w, &self.targets.base)
            .map_err(|_| anyhow!("base assignment"))?;
        for (i, (value, r)) in opened.into_iter().enumerate() {
            witness.set_target(self.targets.token[i], F::from_canonical_u64(value))?;
            witness.set_hash_target(self.targets.raw[i], digest_to_hashout(&r))?;
        }
        self.data
            .prove(witness)
            .map_err(|_| anyhow!("proof construction"))
    }
}
pub fn verify(v: &Verifier, raw: &[u8]) -> Result<Proof> {
    let p = Proof::from_bytes(raw.to_vec(), &v.common).context("proof encoding")?;
    ensure!(
        p.to_bytes() == raw && p.public_inputs.len() == 26,
        "proof shape"
    );
    v.verify(p.clone()).context("proof verification")?;
    Ok(p)
}
