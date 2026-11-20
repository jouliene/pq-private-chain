//! MNG1 supply-change relation over shared AST1 notes.
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

pub const OPEN: Felt = Felt::new(0x415354310001);
pub type Verifier = VerifierCircuitData<F, C, D>;
struct Targets {
    base: SpendTargets,
    token: [Target; 4],
    raw: [HashOutTarget; 4],
    asset_id: HashOutTarget,
    delta: Target,
}
pub fn typed(id: Digest, token: u64, raw: Digest) -> Digest {
    Digest::hash_felts(OPEN, &[id.felts(), &[Felt::new(token)], raw.felts()])
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

    let asset_id = b.add_virtual_hash();
    for limb in asset_id.elements {
        b.range_check(limb, 63);
    }
    let public_id = b.add_virtual_hash_public_input();
    let delta = b.add_virtual_public_input();
    let delta_bits = b.split_le(delta, 63);
    let burning = delta_bits[62];
    let flag = b.mul_const(F::from_canonical_u64(1 << 62), burning.target);
    let magnitude = b.sub(delta, flag);
    let transfer = b.is_equal(magnitude, zero);
    let active = b.not(transfer);
    let empty_burn = b.mul(transfer.target, burning.target);
    b.connect(empty_burn, zero);
    let nonnegative = b.not(burning);
    let issuing = b.and(active, nonnegative);
    let mint = b.mul(issuing.target, magnitude);
    let burn = b.mul(burning.target, magnitude);
    for (public, private) in public_id.elements.into_iter().zip(asset_id.elements) {
        let effective = b.mul(active.target, private);
        b.connect(public, effective);
    }
    let dummy_issuer = b.mul(issuing.target, base.inputs[0].is_dummy.target);
    b.connect(dummy_issuer, zero);
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
        let empty = b.is_equal(token[i], zero);
        let note_id = asset_id.elements.map(|limb| b.select(empty, zero, limb));
        let typed = hash_with_domain(&mut b, OPEN, &[&note_id, &[token[i]], &raw[i].elements]);
        b.connect_hashes(typed, r);
    }
    for (i, input) in base.inputs.iter().enumerate() {
        let dummy_tokens = b.mul(token[i], input.is_dummy.target);
        b.connect(dummy_tokens, zero);
    }
    let input = b.add(token[0], token[1]);
    let output = b.add(token[2], token[3]);
    let issued_inputs = b.mul(issuing.target, input);
    b.connect(issued_inputs, zero);
    let available = b.add(input, mint);
    let allocated = b.add(output, burn);
    b.connect(available, allocated);
    let no_tokens = b.is_equal(available, zero);
    let zero_id = qnero_circuit::gadgets::digests_are_equal(&mut b, asset_id.elements, [zero; 4]);
    b.connect(no_tokens.target, zero_id.target);
    (
        b,
        Targets {
            base,
            token,
            raw,
            asset_id,
            delta,
        },
    )
}
fn bytes(v: &Verifier) -> Result<Vec<u8>> {
    ensure!(
        v.common.config.zero_knowledge
            && v.common.fri_params.leaf_hiding
            && v.common.num_public_inputs == 31
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
    fs::write(dir.join("managed.vk"), bytes(&v)?)?;
    println!("{{\"suite\":\"MNG1\",\"gates_before_blinding\":{},\"degree_bits\":{},\"folds\":{:?},\"public_inputs\":31}}",gates,v.common.degree_bits(),v.common.fri_params.reduction_arity_bits);
    Ok(())
}
pub fn load(dir: &Path) -> Result<Verifier> {
    let v = circuit().0.build_verifier::<C>();
    ensure!(
        bytes(&v)? == fs::read(dir.join("managed.vk"))?,
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
            bytes(&data.verifier_data())? == fs::read(dir.join("managed.vk"))?,
            "wallet registration"
        );
        Ok(Self { targets, data })
    }
    pub fn prove(
        &self,
        w: &SpendWitness,
        opened: [(u64, Digest); 4],
        asset_id: Digest,
        delta: u64,
    ) -> Result<Proof> {
        w.validate()?;
        let mut witness = PartialWitness::new();
        fill_witness(&mut witness, w, &self.targets.base)
            .map_err(|_| anyhow!("base assignment"))?;
        witness.set_hash_target(self.targets.asset_id, digest_to_hashout(&asset_id))?;
        witness.set_target(self.targets.delta, F::from_canonical_u64(delta))?;
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
        p.to_bytes() == raw && p.public_inputs.len() == 31,
        "proof shape"
    );
    v.verify(p.clone()).context("proof verification")?;
    Ok(p)
}

include!("checks.inc");
