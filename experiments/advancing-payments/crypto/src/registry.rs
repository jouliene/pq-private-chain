use crate::codec::{Meter, TAG};
use anyhow::{anyhow, ensure, Result};
use blake2::{Blake2b512, Digest as _};
use plonky2::field::types::Field;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use plonky2::util::serialization::DefaultGateSerializer;
use qnero_aggregator::artifacts::{
    canonical_leaf_verifier_data, canonical_private_batch_verifier_data, serialize_verifier_data,
};
use qnero_aggregator::recursive::add_recursive_verifiers;
use qnero_aggregator::{Proof, C, D, F};
use qnero_circuit::config::qnero_private_batch_circuit_config;
use std::{fs, path::Path};

pub type Verifier = VerifierCircuitData<F, C, D>;
const NAMES: [&str; 5] = ["leaf", "wallet", "outer2", "outer3", "outer4"];
pub fn outer(
    inner: &Verifier,
    k: usize,
) -> Result<(CircuitBuilder<F, D>, Vec<ProofWithPublicInputsTarget<D>>)> {
    ensure!((2..=4).contains(&k), "outer arity");
    check(inner, 1)?;
    let mut builder = CircuitBuilder::<F, D>::new(qnero_private_batch_circuit_config());
    let targets = add_recursive_verifiers(&mut builder, &inner.common, &inner.verifier_only, k)?;
    for value in [TAG, k as u64] {
        let tag = builder.constant(F::from_canonical_u64(value));
        builder.register_public_input(tag);
    }
    for t in &targets {
        ensure!(t.public_inputs.len() == 26, "wallet PI");
        builder.register_public_inputs(&t.public_inputs);
    }
    Ok((builder, targets))
}
fn check(v: &Verifier, k: usize) -> Result<()> {
    let c = &v.common.config;
    let fri = &c.fri_config;
    ensure!(
        D == 2
            && c.security_bits == 128
            && c.num_challenges == 2
            && fri.num_query_rounds == 43
            && fri.proof_of_work_bits == 0
            && fri.rate_bits == 3
            && fri.cap_height == 4,
        "proof profile"
    );
    ensure!(
        c.zero_knowledge == (k != 0) && v.common.fri_params.leaf_hiding == (k != 0),
        "hiding profile"
    );
    ensure!(
        c.num_wires == if k == 0 { 143 } else { 135 }
            && c.num_routed_wires == if k == 0 { 80 } else { 60 },
        "wire profile"
    );
    ensure!(
        v.common.num_public_inputs == if k < 2 { 26 } else { 2 + 26 * k },
        "public inputs"
    );
    ensure!(v.common.fri_params.config == *fri, "FRI profile mismatch");
    Ok(())
}
fn parts(v: &Verifier) -> Result<[Vec<u8>; 3]> {
    Ok([
        serialize_verifier_data(v, "APV2")?,
        v.common
            .to_bytes(&DefaultGateSerializer)
            .map_err(|_| anyhow!("common serialization"))?,
        v.verifier_only
            .to_bytes()
            .map_err(|_| anyhow!("verifier-only serialization"))?,
    ])
}
fn manifest_line(v: &Verifier, k: usize, b: &[Vec<u8>; 3]) -> String {
    format!("{{\"name\":\"{}\",\"arity\":{},\"degree_bits\":{},\"public_inputs\":{},\"wires\":{},\"routed\":{},\"hiding\":{},\"vk_blake2b512\":\"{:x}\",\"common_blake2b512\":\"{:x}\",\"only_blake2b512\":\"{:x}\"}}",
        NAMES[k],k,v.common.degree_bits(),v.common.num_public_inputs,v.common.config.num_wires,
        v.common.config.num_routed_wires,v.common.config.zero_knowledge,Blake2b512::digest(&b[0]),
        Blake2b512::digest(&b[1]),Blake2b512::digest(&b[2]))
}
fn store(dir: &Path, v: &Verifier, k: usize) -> Result<String> {
    check(v, k)?;
    let b = parts(v)?;
    for (ext, data) in ["vk", "common", "only"].into_iter().zip(&b) {
        fs::write(dir.join(format!("{}.{}", NAMES[k], ext)), data)?;
    }
    Ok(manifest_line(v, k, &b))
}
pub fn register(dir: &Path) -> Result<()> {
    // Caller supplies an empty, private registration directory before deployment.
    if !dir.exists() {
        fs::create_dir(dir)?;
    }
    ensure!(
        fs::read_dir(dir)?.next().is_none(),
        "registration directory not empty"
    );
    let meter = Meter::start();
    let leaf = canonical_leaf_verifier_data();
    let mut layers = vec![store(dir, &leaf, 0)?];
    let single = canonical_private_batch_verifier_data(&leaf, 1)?;
    layers.push(store(dir, &single, 1)?);
    for k in 2..=4 {
        let (c, _) = outer(&single, k)?;
        layers.push(store(dir, &c.build_verifier::<C>(), k)?);
    }
    let data=format!("{{\"suite\":\"APV2\",\"security_bits\":128,\"extension_degree\":2,\"challenges\":2,\"query_rounds\":43,\"rate_bits\":3,\"cap_height\":4,\"grinding_bits\":0,\"layers\":[{}]}}",layers.join(","));
    fs::write(dir.join("profile.json"), data.as_bytes())?;
    println!("{data}");
    meter.finish("registration");
    Ok(())
}
pub fn compare(dir: &Path, k: usize, v: &Verifier) -> Result<()> {
    check(v, k)?;
    let b = parts(v)?;
    for (ext, bytes) in ["vk", "common", "only"].into_iter().zip(&b) {
        ensure!(
            fs::read(dir.join(format!("{}.{}", NAMES[k], ext)))? == *bytes,
            "registered verifier bytes"
        );
    }
    let manifest = fs::read_to_string(dir.join("profile.json"))?;
    ensure!(
        manifest.contains(&manifest_line(v, k, &b)),
        "operator registration mismatch"
    );
    Ok(())
}
pub fn load(dir: &Path, k: usize) -> Result<Verifier> {
    ensure!(k < 5, "unregistered size");
    let raw = fs::read(dir.join(format!("{}.vk", NAMES[k])))?;
    let v = Verifier::from_bytes(raw, &DefaultGateSerializer)
        .map_err(|_| anyhow!("operator verifier encoding"))?;
    compare(dir, k, &v)?;
    Ok(v)
}
pub fn verify(v: &Verifier, raw: &[u8]) -> Result<Proof> {
    let proof =
        Proof::from_bytes(raw.to_vec(), &v.common).map_err(|_| anyhow!("proof encoding"))?;
    ensure!(proof.to_bytes() == raw, "noncanonical proof");
    v.verify(proof.clone())
        .map_err(|_| anyhow!("invalid proof"))?;
    Ok(proof)
}
