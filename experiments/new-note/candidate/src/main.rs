mod note;
mod oracle;
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
        Some(role @ ("prove" | "verify")) if args.len() == 3 => {
            let s: Statement = serde_json::from_slice(&fs::read(&args[1])?)?;
            s.check()?;
            let path = Path::new(&args[2]);
            if role == "verify" {
                let len = fs::metadata(path)?.len();
                ensure!((1..=1024 * 1024).contains(&len), "proof length");
            }
            let start = Instant::now();
            let (builder, targets) = relation::circuit(&s)?;
            let gates = builder.num_gates();
            let data = builder.build::<C>();
            let prepare = start.elapsed();
            ensure!(
                data.common.num_public_inputs == 0
                    && data.common.config.zero_knowledge
                    && data.common.fri_params.leaf_hiding,
                "suite"
            );
            let work = Instant::now();
            let expanded_bytes;
            if role == "prove" {
                let w: Witness = serde_json::from_reader(stdin.lock())
                    .map_err(|_| anyhow::anyhow!("witness format"))?;
                let assignment = targets
                    .assign(&s, &w)
                    .map_err(|_| anyhow::anyhow!("witness assignment"))?;
                // Backend errors can contain concrete witness values. Keep diagnostics private.
                let proof = data
                    .prove(assignment)
                    .map_err(|_| anyhow::anyhow!("unsatisfied relation"))?;
                expanded_bytes = proof.to_bytes().len();
                let encoded = data.compress(proof.clone())?.to_bytes();
                data.verify(proof)
                    .map_err(|_| anyhow::anyhow!("produced proof failed"))?;
                fs::write(path, encoded)?;
            } else {
                let raw = fs::read(path)?;
                let proof = Proof::from_bytes(raw.clone(), &data.common)?;
                ensure!(
                    proof.public_inputs.is_empty() && proof.to_bytes() == raw,
                    "noncanonical proof"
                );
                let indices = &proof.proof.opening_proof.query_round_proofs.indices;
                let domain = 1usize << data.common.fri_params.lde_bits();
                ensure!(
                    indices.iter().all(|&index| index < domain),
                    "query index range"
                );
                // The upstream decompressor assumes consistent selections and paths; contain
                // a failed lookup within this disposable public verifier. All dimensions
                // originate in the fixed relation; sibling lengths are single octets.
                let expanded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    data.decompress(proof)
                }))
                .map_err(|_| anyhow::anyhow!("malformed compressed openings"))??;
                expanded_bytes = expanded.to_bytes().len();
                ensure!(
                    data.compress(expanded.clone())?.to_bytes() == raw,
                    "noncanonical compressed openings"
                );
                data.verify(expanded)?;
            }
            println!(
                "{}",
                json!({"role":role,"degree_bits":data.common.degree_bits(),"gates_before_blinding":gates,
                "folds":data.common.fri_params.reduction_arity_bits,"public_inputs":0,"proof_bytes":fs::metadata(path)?.len(),
                "expanded_proof_bytes":expanded_bytes,"peak_rss_kib":peak_rss(),"preparation_ms":prepare.as_secs_f64()*1000.0,"operation_ms":work.elapsed().as_secs_f64()*1000.0})
            );
        }
        _ => bail!(
            "n7p1 eval | eval-batch | eval-stream | prove STATEMENT PROOF | verify STATEMENT PROOF"
        ),
    }
    Ok(())
}
fn main() {
    // A failed upstream witness generator or malformed proof must not print a wire value.
    std::panic::set_hook(Box::new(|_| eprintln!("N7P1 backend rejected execution")));
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
