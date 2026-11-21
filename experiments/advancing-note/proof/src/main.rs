mod note;
mod oracle;
mod public;
mod relation;
mod sponge;

use anyhow::{Result, bail, ensure};
use note::{Op, Statement, Witness};
use oracle::{C, Proof};
use serde_json::json;
use std::{
    env, fs,
    io::{self, BufRead, Write},
    path::Path,
    time::Instant,
};

fn peak_rss() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find(|line| line.starts_with("VmHWM:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

type F = plonky2::field::goldilocks_field::GoldilocksField;
type Verifier = plonky2::plonk::circuit_data::VerifierCircuitData<F, C, 4>;
const REGISTERED: &[u8] = include_bytes!("../registered.vk");

fn registration_id() -> String {
    use sha3::Digest;
    format!("{:x}", sha3::Sha3_384::digest(REGISTERED))
}
fn monotonic_ns() -> Result<u64> {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // Linux CLOCK_MONOTONIC is shared with Python time.monotonic_ns().
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) } == 0,
        "monotonic clock"
    );
    Ok(t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64)
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    statement: Statement,
    proof: std::path::PathBuf,
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
    let length = raw.len();
    ensure!((1..=1024 * 1024).contains(&length), "proof length");
    let proof = Proof::from_bytes(raw.clone(), &vk.common)?;
    ensure!(
        proof.public_inputs.is_empty() && proof.to_bytes() == raw,
        "noncanonical proof"
    );
    let indices = &proof.proof.opening_proof.query_round_proofs.indices;
    let domain = 1usize << vk.common.fri_params.lde_bits();
    ensure!(
        indices.iter().all(|&index| index < domain),
        "query index range"
    );
    let expanded = proof.decompress(&binding, &vk.common)?;
    let expanded_bytes = expanded.to_bytes().len();
    ensure!(
        expanded.clone().compress(&binding, &vk.common)?.to_bytes() == raw,
        "noncanonical compressed openings"
    );
    vk.verify(expanded)?;
    Ok((length, expanded_bytes))
}
fn checked_verify(vk: &Verifier, s: &Statement, path: &Path) -> Result<(usize, usize)> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| verify_body(vk, s, path)))
        .map_err(|_| anyhow::anyhow!("malformed proof"))?
}
fn run() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    let stdin = io::stdin();
    match args.first().map(String::as_str) {
        Some("eval") if args.len() == 1 => {
            let op: Op = serde_json::from_reader(stdin.lock())?;
            println!("{}", serde_json::to_string(&op.eval()?)?);
        }
        Some("eval-batch") if args.len() == 1 => {
            let ops: Vec<Op> = serde_json::from_reader(stdin.lock())?;
            let results = ops.into_iter().map(Op::eval).collect::<Result<Vec<_>>>()?;
            println!("{}", serde_json::to_string(&results)?);
        }
        Some("eval-stream") if args.len() == 1 => {
            let mut out = io::stdout().lock();
            for line in stdin.lock().lines() {
                let op: Op = serde_json::from_str(&line?)?;
                serde_json::to_writer(&mut out, &op.eval()?)?;
                writeln!(out)?;
                out.flush()?;
            }
        }
        Some("generate-vk") if args.len() == 2 => {
            let (b, _) = relation::circuit()?;
            let gates = b.num_gates();
            let vk = b.build::<C>().verifier_data();
            let raw = vk
                .to_bytes(&public::Registrations)
                .map_err(|_| anyhow::anyhow!("verifier registration encoding"))?;
            fs::write(&args[1], &raw)?;
            println!(
                "{}",
                json!({"registered_bytes":raw.len(),"degree_bits":vk.common.degree_bits(),"gates_before_blinding":gates,"gates":vk.common.gates.iter().map(|g|g.0.id()).collect::<Vec<_>>() })
            );
        }
        Some("prove") if args.len() == 3 => {
            let s: Statement = serde_json::from_slice(&fs::read(&args[1])?)?;
            s.check()?;
            let w: Witness = serde_json::from_reader(stdin.lock())
                .map_err(|_| anyhow::anyhow!("witness format"))?;
            let start = Instant::now();
            let (b, t) = relation::circuit()?;
            let gates = b.num_gates();
            let mut data = b.build::<C>();
            ensure!(
                data.verifier_data()
                    .to_bytes(&public::Registrations)
                    .map_err(|_| anyhow::anyhow!("verifier registration encoding"))?
                    == REGISTERED,
                "fixed verifier registration mismatch"
            );
            let binding = public::bind(&mut data.common, data.verifier_only.circuit_digest, &s)?;
            data.prover_only.circuit_digest = binding;
            data.verifier_only.circuit_digest = binding;
            let prepare = start.elapsed();
            let assignment = t
                .assign(&s, &w)
                .map_err(|_| anyhow::anyhow!("witness assignment"))?;
            let work = Instant::now();
            if let Some(marker) = env::var_os("N7_PROVE_MARKER") {
                fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(marker)?
                    .write_all(b"proving\n")?;
            }
            let prove_start_ns = monotonic_ns()?;
            let proof = data
                .prove(assignment)
                .map_err(|_| anyhow::anyhow!("unsatisfied relation"))?;
            let prove_end_ns = monotonic_ns()?;
            let expanded = proof.to_bytes().len();
            let encoded = data.compress(proof.clone())?.to_bytes();
            data.verify(proof)
                .map_err(|_| anyhow::anyhow!("produced proof failed"))?;
            fs::write(&args[2], &encoded)?;
            println!(
                "{}",
                json!({"role":"prove","degree_bits":data.common.degree_bits(),"gates_before_blinding":gates,
                "folds":data.common.fri_params.reduction_arity_bits,"public_inputs":49,"stock_public_inputs":0,"proof_bytes":encoded.len(),
                "expanded_proof_bytes":expanded,"registered_vk_sha3_384":registration_id(),"peak_rss_kib":peak_rss(),
                "preparation_ms":prepare.as_secs_f64()*1000.0,"operation_ms":work.elapsed().as_secs_f64()*1000.0,
                "prove_start_ns":prove_start_ns,"prove_end_ns":prove_end_ns})
            );
        }
        Some(role @ ("verify" | "verify-stream"))
            if (role == "verify" && args.len() == 3)
                || (role == "verify-stream" && args.len() == 1) =>
        {
            let start = Instant::now();
            let vk = Verifier::from_bytes(REGISTERED.to_vec(), &public::Registrations)
                .map_err(|_| anyhow::anyhow!("verifier registration encoding"))?;
            ensure!(
                vk.common.num_public_inputs == 0
                    && vk.common.config.zero_knowledge
                    && vk.common.fri_params.leaf_hiding,
                "suite"
            );
            let prepare = start.elapsed().as_secs_f64() * 1000.0;
            let id = registration_id();
            if role == "verify" {
                let s: Statement = serde_json::from_slice(&fs::read(&args[1])?)?;
                let work = Instant::now();
                let (len, expanded) = checked_verify(&vk, &s, Path::new(&args[2]))?;
                println!(
                    "{}",
                    json!({"role":role,"accepted":true,"proof_bytes":len,"expanded_proof_bytes":expanded,
                    "degree_bits":vk.common.degree_bits(),"folds":vk.common.fri_params.reduction_arity_bits,"public_inputs":49,
                    "registered_vk_sha3_384":id,"preparation_ms":prepare,"operation_ms":work.elapsed().as_secs_f64()*1000.0,"peak_rss_kib":peak_rss()})
                );
            } else {
                let mut out = io::stdout().lock();
                writeln!(
                    out,
                    "{}",
                    json!({"ready":true,"registered_vk_sha3_384":id,"preparation_ms":prepare,"peak_rss_kib":peak_rss()})
                )?;
                out.flush()?;
                for line in stdin.lock().lines() {
                    let work = Instant::now();
                    let line = line?;
                    let result = serde_json::from_str::<Request>(&line)
                        .ok()
                        .and_then(|r| checked_verify(&vk, &r.statement, &r.proof).ok());
                    writeln!(
                        out,
                        "{}",
                        json!({"accepted":result.is_some(),"proof_bytes":result.map(|v|v.0),"expanded_proof_bytes":result.map(|v|v.1),
                        "operation_ms":work.elapsed().as_secs_f64()*1000.0,"peak_rss_kib":peak_rss(),"registered_vk_sha3_384":id})
                    )?;
                    out.flush()?;
                }
            }
        }
        _ => bail!(
            "n7p2 eval | eval-batch | eval-stream | generate-vk PATH | prove STATEMENT PROOF | verify STATEMENT PROOF | verify-stream"
        ),
    }
    Ok(())
}
fn main() {
    // A failed upstream witness generator or malformed proof must not print a wire value.
    std::panic::set_hook(Box::new(|_| eprintln!("N7P2 backend rejected execution")));
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
