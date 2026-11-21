mod legacy;
#[path = "../../../../../advancing-note/proof/src/note.rs"]
mod n7note;
mod note;
mod relation;
#[path = "../../../../../advancing-note/proof/src/sponge.rs"]
mod sponge;
mod oracle {
    include!(concat!(env!("OUT_DIR"), "/oracle.rs"));
}
mod public {
    include!(concat!(env!("OUT_DIR"), "/public.rs"));
}

use anyhow::{Result, bail, ensure};
use note::{DeriveRequest, Statement, Witness};
use oracle::{C, Proof};
use serde_json::json;
use std::{env, fs, io, path::Path, time::Instant};

type F = plonky2::field::goldilocks_field::GoldilocksField;
type Verifier = plonky2::plonk::circuit_data::VerifierCircuitData<F, C, 4>;
const REGISTERED: &[u8] = include_bytes!("../registered.vk");

fn peak_rss() -> Option<u64> {
    fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find(|line| line.starts_with("VmHWM:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn registration_id() -> String {
    use sha3::Digest;
    format!("{:x}", sha3::Sha3_384::digest(REGISTERED))
}

fn verify_body(fixed_vk: &Verifier, statement: &Statement, path: &Path) -> Result<(usize, usize)> {
    let mut vk = fixed_vk.clone();
    let binding = public::bind(
        &mut vk.common,
        fixed_vk.verifier_only.circuit_digest,
        statement,
    )?;
    vk.verifier_only.circuit_digest = binding;
    let mut file = fs::File::open(path)?;
    let mut raw = Vec::new();
    use std::io::Read;
    (&mut file).take(1024 * 1024 + 1).read_to_end(&mut raw)?;
    ensure!((1..=1024 * 1024).contains(&raw.len()), "proof length");
    let proof = Proof::from_bytes(raw.clone(), &vk.common)?;
    ensure!(
        proof.public_inputs.is_empty() && proof.to_bytes() == raw,
        "noncanonical proof"
    );
    let domain = 1usize << vk.common.fri_params.lde_bits();
    ensure!(
        proof
            .proof
            .opening_proof
            .query_round_proofs
            .indices
            .iter()
            .all(|&index| index < domain),
        "query index range"
    );
    let expanded = proof.decompress(&binding, &vk.common)?;
    let expanded_bytes = expanded.to_bytes().len();
    ensure!(
        expanded.clone().compress(&binding, &vk.common)?.to_bytes() == raw,
        "noncanonical compressed openings"
    );
    vk.verify(expanded)?;
    Ok((raw.len(), expanded_bytes))
}

fn run() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    let stdin = io::stdin();
    match args.first().map(String::as_str) {
        Some("derive") if args.len() == 1 => {
            let request: DeriveRequest = serde_json::from_reader(stdin.lock())?;
            let statement = Statement::derive(
                request.bridge_context,
                request.c_input_nullifiers,
                &request.witness,
            )?;
            println!("{}", serde_json::to_string(&statement)?);
        }
        Some("generate-vk") if args.len() == 2 => {
            let (builder, _) = relation::circuit()?;
            let gates = builder.num_gates();
            let vk = builder.build::<C>().verifier_data();
            let raw = vk
                .to_bytes(&public::Registrations)
                .map_err(|_| anyhow::anyhow!("verifier registration encoding"))?;
            fs::write(&args[1], &raw)?;
            println!(
                "{}",
                json!({
                    "registered_bytes": raw.len(),
                    "degree_bits": vk.common.degree_bits(),
                    "gates_before_blinding": gates,
                    "gates": vk.common.gates.iter().map(|gate| gate.0.id()).collect::<Vec<_>>(),
                })
            );
        }
        Some("prove") if args.len() == 3 => {
            let statement: Statement = serde_json::from_slice(&fs::read(&args[1])?)?;
            statement.check()?;
            let witness: Witness = serde_json::from_reader(stdin.lock())
                .map_err(|_| anyhow::anyhow!("witness format"))?;
            let start = Instant::now();
            let (builder, targets) = relation::circuit()?;
            let gates = builder.num_gates();
            let mut data = builder.build::<C>();
            ensure!(
                data.verifier_data()
                    .to_bytes(&public::Registrations)
                    .map_err(|_| anyhow::anyhow!("verifier registration encoding"))?
                    == REGISTERED,
                "fixed verifier registration mismatch"
            );
            let binding = public::bind(
                &mut data.common,
                data.verifier_only.circuit_digest,
                &statement,
            )?;
            data.prover_only.circuit_digest = binding;
            data.verifier_only.circuit_digest = binding;
            let prepare = start.elapsed();
            let assignment = targets.assign(&statement, &witness)?;
            let work = Instant::now();
            let proof = data
                .prove(assignment)
                .map_err(|_| anyhow::anyhow!("unsatisfied bridge relation"))?;
            let expanded = proof.to_bytes().len();
            let encoded = data.compress(proof.clone())?.to_bytes();
            data.verify(proof)?;
            fs::write(&args[2], &encoded)?;
            println!(
                "{}",
                json!({
                    "role": "prove",
                    "degree_bits": data.common.degree_bits(),
                    "gates_before_blinding": gates,
                    "public_inputs": public::WORDS,
                    "stock_public_inputs": 0,
                    "proof_bytes": encoded.len(),
                    "expanded_proof_bytes": expanded,
                    "registered_vk_sha3_384": registration_id(),
                    "peak_rss_kib": peak_rss(),
                    "preparation_ms": prepare.as_secs_f64() * 1000.0,
                    "operation_ms": work.elapsed().as_secs_f64() * 1000.0,
                })
            );
        }
        Some("verify") if args.len() == 3 => {
            let start = Instant::now();
            let vk = Verifier::from_bytes(REGISTERED.to_vec(), &public::Registrations)
                .map_err(|_| anyhow::anyhow!("verifier registration encoding"))?;
            ensure!(
                vk.common.num_public_inputs == 0
                    && vk.common.config.zero_knowledge
                    && vk.common.fri_params.leaf_hiding,
                "suite"
            );
            let prepare = start.elapsed();
            let statement: Statement = serde_json::from_slice(&fs::read(&args[1])?)?;
            let work = Instant::now();
            let (proof_bytes, expanded_proof_bytes) =
                verify_body(&vk, &statement, Path::new(&args[2]))?;
            println!(
                "{}",
                json!({
                    "role": "verify",
                    "accepted": true,
                    "proof_bytes": proof_bytes,
                    "expanded_proof_bytes": expanded_proof_bytes,
                    "degree_bits": vk.common.degree_bits(),
                    "public_inputs": public::WORDS,
                    "registered_vk_sha3_384": registration_id(),
                    "preparation_ms": prepare.as_secs_f64() * 1000.0,
                    "operation_ms": work.elapsed().as_secs_f64() * 1000.0,
                    "peak_rss_kib": peak_rss(),
                })
            );
        }
        _ => bail!(
            "c2n7-bridge derive | generate-vk PATH | prove STATEMENT PROOF | verify STATEMENT PROOF"
        ),
    }
    Ok(())
}

fn main() {
    std::panic::set_hook(Box::new(|_| eprintln!("C2N7 backend rejected execution")));
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
