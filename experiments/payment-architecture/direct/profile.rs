//! Direct, blinded 2-in/2-out payment. The registered object is the spend circuit itself.
use anyhow::{anyhow, ensure, Context, Result};
use plonky2::fri::FriReductionStrategy;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_data::{CircuitData, VerifierCircuitData};
use plonky2::util::serialization::DefaultGateSerializer;
use qnero_aggregator::Proof;
use qnero_circuit::circuit::{QneroSpendCircuit, SpendTargets};
use qnero_circuit::config::qnero_leaf_zk_circuit_config;
use qnero_circuit::witness::{fill_witness, SpendWitness};
use qnero_circuit::{C, D, F};
use std::{fs, path::Path};

pub type Verifier = VerifierCircuitData<F, C, D>;

fn circuit() -> Result<QneroSpendCircuit> {
    let mut config = qnero_leaf_zk_circuit_config();
    config.num_wires = 135;
    config.num_routed_wires = 60;
    config.security_bits = 128;
    config.num_challenges = 2;
    config.fri_config.rate_bits = 5;
    config.fri_config.cap_height = 4;
    config.fri_config.num_query_rounds = 26;
    config.fri_config.proof_of_work_bits = 0;
    config.fri_config.reduction_strategy = FriReductionStrategy::ConstantArityBits(2, 3);
    ensure!(config.zero_knowledge, "a public spend proof requires row blinding");
    QneroSpendCircuit::new(config)
}

fn bytes(v: &Verifier) -> Result<Vec<u8>> {
    ensure!(v.common.config.zero_knowledge && v.common.fri_params.leaf_hiding
        && v.common.num_public_inputs == 26 && D == 2, "direct proof privacy/statement profile");
    v.to_bytes(&DefaultGateSerializer).map_err(|_| anyhow!("verifier encoding"))
}

pub fn register(dir: &Path) -> Result<()> {
    // No witness or wallet is used to derive the public verification program.
    let c = circuit()?;
    let gates = c.num_gates();
    let v = c.build_verifier();
    fs::create_dir(dir)?;
    fs::write(dir.join("direct.vk"), bytes(&v)?)?;
    println!("{{\"suite\":\"DLF1\",\"gates_before_blinding\":{},\"degree_bits\":{},\"public_inputs\":26,\"wires\":135,\"routed\":60,\"rate_bits\":5,\"queries\":26,\"cap_height\":4,\"folds\":{:?},\"row_blinding\":true,\"leaf_hiding\":true}}",
        gates, v.common.degree_bits(), v.common.fri_params.reduction_arity_bits);
    Ok(())
}

pub fn load(dir: &Path) -> Result<Verifier> {
    let v = circuit()?.build_verifier();
    ensure!(bytes(&v)? == fs::read(dir.join("direct.vk"))?, "source-derived verifier mismatch");
    Ok(v)
}

pub struct WalletProver {
    targets: SpendTargets,
    data: CircuitData<F, C, D>,
}

impl WalletProver {
    pub fn new(dir: &Path) -> Result<Self> {
        let c = circuit()?;
        let targets = c.targets();
        let data = c.build();
        ensure!(bytes(&data.verifier_data())? == fs::read(dir.join("direct.vk"))?,
            "wallet circuit differs from source registration");
        Ok(Self { targets, data })
    }
    pub fn prove_spend(&self, witness: &SpendWitness) -> Result<Proof> {
        witness.validate()?;
        let mut assigned = PartialWitness::new();
        fill_witness(&mut assigned, witness, &self.targets)
            .map_err(|_| anyhow!("direct wallet witness assignment"))?;
        self.data.prove(assigned).map_err(|_| anyhow!("direct proof construction failed"))
    }
}

pub fn verify(v: &Verifier, raw: &[u8]) -> Result<Proof> {
    let proof = Proof::from_bytes(raw.to_vec(), &v.common).context("proof encoding")?;
    ensure!(proof.to_bytes() == raw && proof.public_inputs.len() == 26, "noncanonical direct proof");
    v.verify(proof.clone()).context("invalid complete direct proof")?;
    Ok(proof)
}
