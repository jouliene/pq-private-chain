mod codec;
mod registry;
mod wallet;

use anyhow::{anyhow, ensure, Context, Result};
use codec::{effects, encode, packet, read_frame, write_frame, Meter};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use qnero_circuit::header::{HeaderInputs, DIGEST_LOGS_SIZE};
use qnero_circuit::merkle::{empty_digest, hash_node, CommitmentTree};
use qnero_notes::Digest;
use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::path::Path;

fn words(raw: &[u8]) -> Result<Vec<Digest>> {
    ensure!(raw.len() % 32 == 0, "word framing");
    raw.chunks_exact(32)
        .map(|x| Ok(Digest::from_slice(x)?))
        .collect()
}

fn header(raw: &[u8]) -> Result<HeaderInputs> {
    ensure!(raw.len() == 132, "header length");
    HeaderInputs::new(
        Digest::from_slice(&raw[..32])?,
        u32::from_le_bytes(raw[32..36].try_into()?),
        raw[36..68].try_into()?,
        raw[68..100].try_into()?,
        Digest::from_slice(&raw[100..])?,
        &[0; DIGEST_LOGS_SIZE],
    )
}

fn hash_request(cmd: &[u8]) -> Result<Vec<u8>> {
    let (&op, body) = cmd.split_first().context("empty hash command")?;
    let answer = match op {
        b'H' => header(body)?.block_hash(),
        b'R' => {
            let leaves = words(body)?;
            if leaves.is_empty() {
                empty_digest()
            } else {
                CommitmentTree::new(&leaves, CommitmentTree::depth_for(leaves.len())?)?.root()
            }
        }
        b'N' => {
            let children: [Digest; 4] = words(body)?
                .try_into()
                .map_err(|_| anyhow!("quaternary children"))?;
            hash_node(&children)
        }
        _ => anyhow::bail!("hash command"),
    };
    Ok(answer.to_bytes().to_vec())
}

fn service(
    r: &mut impl Read,
    w: &mut impl Write,
    label: &str,
    mut f: impl FnMut(&[u8]) -> Result<Vec<u8>>,
) -> Result<()> {
    loop {
        let cmd = read_frame(r)?;
        if cmd.is_empty() {
            return Ok(());
        }
        let meter = Meter::start();
        let reply = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&cmd)));
        let (ok, bytes) = match reply {
            Ok(Ok(x)) => (true, x),
            _ => (false, vec![b'0']),
        };
        if label != "hash" {
            meter.finish(if ok { label } else { "rejected" });
        }
        write_frame(w, &bytes)?;
    }
}

fn builder(dir: &Path, arity: usize, r: &mut impl Read, w: &mut impl Write) -> Result<()> {
    ensure!((2..=4).contains(&arity), "builder arity");
    let meter = Meter::start();
    let inner = registry::load(dir, 1)?;
    let (builder, targets) = registry::outer(&inner, arity)?;
    let compiled = builder.build::<qnero_aggregator::C>();
    registry::compare(dir, arity, &compiled.verifier_data())?;
    meter.finish("builder_setup");
    write_frame(w, b"READY")?;
    loop {
        let first = read_frame(r)?;
        if first.is_empty() {
            return Ok(());
        }
        let mut inputs = vec![first];
        for _ in 1..arity {
            inputs.push(read_frame(r)?);
        }
        let meter = Meter::start();
        let combined =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Vec<u8>> {
                let mut witness = PartialWitness::new();
                let mut ciphertexts = Vec::new();
                let mut nullifiers = HashSet::new();
                let mut commitments = HashSet::new();
                for (bytes, target) in inputs.iter().zip(&targets) {
                    let p = packet(bytes)?;
                    ensure!(p.arity == 1, "only wallet submissions");
                    let proof = registry::verify(&inner, p.proof)?;
                    let rows = effects(&p, &proof)?;
                    for nf in rows[36..100].chunks_exact(32) {
                        ensure!(nullifiers.insert(nf.to_vec()), "conflicting input");
                    }
                    for cm in rows[100..164].chunks_exact(32) {
                        ensure!(commitments.insert(cm.to_vec()), "conflicting output");
                    }
                    witness.set_proof_with_pis_target(target, &proof)?;
                    ciphertexts.extend_from_slice(p.cts);
                }
                Ok(encode(arity, &compiled.prove(witness)?, &ciphertexts))
            }));
        match combined {
            Ok(Ok(bytes)) => {
                meter.finish("builder_aggregate");
                write_frame(w, &bytes)?;
            }
            _ => {
                meter.finish("builder_rejected");
                write_frame(w, b"0")?;
            }
        }
    }
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    let mode = args.get(1).and_then(|s| s.to_str()).context("role")?;
    if mode != "register" {
        std::panic::set_hook(Box::new(|_| {}));
    }
    let (mut r, mut w) = (io::stdin().lock(), io::stdout().lock());
    if mode == "hash" {
        return service(&mut r, &mut w, "hash", hash_request);
    }
    let dir = Path::new(args.get(2).context("operator key directory")?);
    match mode {
        "register" => registry::register(dir),
        "verify" => {
            let meter = Meter::start();
            let keys = (1..=4)
                .map(|k| registry::load(dir, k))
                .collect::<Result<Vec<_>>>()?;
            meter.finish("verifier_setup");
            service(&mut r, &mut w, "public_verify", |bytes| {
                let p = packet(bytes)?;
                let proof = registry::verify(&keys[p.arity - 1], p.proof)?;
                let mut reply = vec![b'1'];
                reply.extend(effects(&p, &proof)?);
                Ok(reply)
            })
        }
        "builder" => builder(
            dir,
            args.get(3)
                .and_then(|s| s.to_str())
                .context("arity")?
                .parse()?,
            &mut r,
            &mut w,
        ),
        "wallet" => wallet::actor(
            dir,
            Path::new(args.get(3).context("private backup path")?),
            args.get(4)
                .and_then(|s| s.to_str())
                .context("wallet mode")?,
            &mut r,
            &mut w,
        ),
        _ => anyhow::bail!("unknown role"),
    }
}
