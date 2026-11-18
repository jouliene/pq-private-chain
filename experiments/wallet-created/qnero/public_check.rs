// Installed as an example of qnero-verifier (no wallet or prover dependencies).
use anyhow::{ensure, Result};
use qnero_verifier::{chain::ct_digest, QneroPrivateBatchVerifier};
use qp_plonky2_verifier::field::types::PrimeField64;
use qp_plonky2_verifier::F;
use std::{env, fs, path::Path, time::Instant};

fn digest(limbs: &[F; 4]) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (dst, elem) in bytes.chunks_exact_mut(8).zip(limbs) {
        dst.copy_from_slice(&elem.to_canonical_u64().to_le_bytes());
    }
    bytes
}

// This experiment emits the three small SCALE compact modes only.
fn compact(cursor: &mut &[u8]) -> Result<usize> {
    let first = *cursor.first().ok_or_else(|| anyhow::anyhow!("missing length"))?;
    let n = match first & 3 { 0 => 1, 1 => 2, 2 => 4, _ => anyhow::bail!("oversized length") };
    let mut raw = [0; 4];
    raw[..n].copy_from_slice(take(cursor, n)?);
    let value = (u32::from_le_bytes(raw) >> 2) as usize;
    ensure!(n == 1 || value >= if n == 2 { 64 } else { 16384 }, "nonminimal SCALE length");
    Ok(value)
}
fn take<'a>(cursor: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    ensure!(cursor.len() >= n, "truncated extrinsic");
    let (head, rest) = cursor.split_at(n);
    *cursor = rest;
    Ok(head)
}
fn blob<'a>(cursor: &mut &'a [u8]) -> Result<&'a [u8]> {
    let n = compact(cursor)?;
    take(cursor, n)
}

fn main() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    ensure!(args.len() == 3, "public_check PUBLIC_DIRECTORY positive|controls");
    let dir = Path::new(&args[1]);
    // Caller independently pins this exact file to the compiled upstream
    // release Blake2b-256 digest before mounting it read-only in this process.
    let vk = fs::read(dir.join("private-verifier.bin"))?;
    let bytes = fs::read(dir.join("payment.scale"))?;
    let anchor = fs::read(dir.join("anchor.bin"))?;
    let commitments = fs::read(dir.join("commitments.bin"))?;
    let mut c: &[u8] = &bytes;
    let body_len = compact(&mut c)?;
    ensure!(body_len == c.len());
    ensure!(take(&mut c, 3)? == [4, 24, 0]);
    let proof = blob(&mut c)?;
    ensure!(compact(&mut c)? == 1);
    let ct1 = blob(&mut c)?;
    let ct2 = blob(&mut c)?;
    ensure!(c.is_empty() && ct1.len() == 1792 && ct2.len() == 1792);
    let start = Instant::now();
    let verifier = QneroPrivateBatchVerifier::from_artifact_bytes(&vk, 6)?;
    let load = start.elapsed().as_secs_f64();
    let start = Instant::now();
    let public = verifier.verify_proof_bytes(proof)?;
    let verify = start.elapsed().as_secs_f64();
    ensure!(public.slots.len() == 6 && !public.is_padding());
    ensure!(public.block_number.to_canonical_u64() == 2 && digest(&public.block_hash) == anchor[..]);
    let real = public.slots.iter().filter(|s| !s.is_padding()).collect::<Vec<_>>();
    ensure!(real.len() == 1 && real[0].fee.to_canonical_u64() == 8);
    ensure!(digest(&real[0].ct_digest) == ct_digest(&[ct1, ct2]));
    let cms = real[0].commitments.iter().flat_map(digest).collect::<Vec<_>>();
    ensure!(cms == commitments);
    let all_nullifiers = public.slots.iter().flat_map(|s| s.nullifiers.iter().map(digest))
        .collect::<std::collections::BTreeSet<_>>();
    ensure!(all_nullifiers.len() == 12);
    match args[2].as_str() {
        "positive" => println!("{{\"private_verification_passed\":true,\"load_elapsed_s\":{load},\"verify_elapsed_s\":{verify},\"distinct_published_nullifiers\":12,\"real_slots\":1,\"padding_slots\":5}}"),
        "controls" => {
            let mut corrupted = proof.to_vec();
            corrupted[0] ^= 1;
            ensure!(verifier.verify_proof_bytes(&corrupted).is_err());
            let mut damaged_ct = ct1.to_vec();
            damaged_ct[0] ^= 1;
            ensure!(digest(&real[0].ct_digest) != ct_digest(&[&damaged_ct, ct2]));
            println!("{{\"corrupt_proof_rejected\":true,\"changed_ciphertext_digest_mismatch\":true}}");
        }
        _ => anyhow::bail!("unknown mode"),
    }
    Ok(())
}
