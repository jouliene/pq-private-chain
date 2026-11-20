// Offline research codec for complete, locally verified K384 proof specimens.
mod config;

use anyhow::{ensure, Context, Result};
use config::{Proof, C};
use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::plonk::proof::CompressedProofWithPublicInputs;
use plonky2::util::serialization::DefaultGateSerializer;
use qnero_circuit::{D, F};
use std::{env, fs, path::Path};

const SPECIMEN_LIMIT: u64 = 2 * 1024 * 1024;

fn read(path: &str) -> Result<Vec<u8>> {
    let file = Path::new(path);
    let meta = fs::metadata(file)?;
    ensure!(
        meta.is_file() && meta.len() <= SPECIMEN_LIMIT,
        "specimen size"
    );
    Ok(fs::read(file)?)
}

fn main() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 5,
        "expected encode|decode registered-vk input output"
    );
    // The harness pins this public key to the registered candidate before launching us.
    let key_bytes = read(&args[2])?;
    let key = VerifierCircuitData::<F, C, D>::from_bytes(key_bytes, &DefaultGateSerializer)
        .map_err(|_| anyhow::anyhow!("invalid verifier data"))?;
    ensure!(
        matches!(key.common.num_public_inputs, 31 | 34)
            && key.common.config.zero_knowledge
            && key.common.fri_params.leaf_hiding
            && key.common.config.fri_config.num_query_rounds == 64,
        "unexpected candidate key"
    );
    let input = read(&args[3])?;
    let digest = &key.verifier_only.circuit_digest;
    let common = &key.common;
    let output = match args[1].as_str() {
        "encode" => {
            let full = Proof::from_bytes(input.clone(), common).context("full decoding")?;
            ensure!(full.to_bytes() == input, "noncanonical full proof");
            key.verify(full.clone()).context("full verification")?;
            let small = full.compress(digest, common)?;
            let recovered = small.clone().decompress(digest, common)?;
            ensure!(recovered.to_bytes() == input, "full proof round trip");
            small.to_bytes()
        }
        "decode" => {
            let small =
                CompressedProofWithPublicInputs::<F, C, D>::from_bytes(input.clone(), common)
                    .context("compressed decoding")?;
            ensure!(
                small.to_bytes() == input,
                "noncanonical compressed encoding"
            );
            let full = small.decompress(digest, common)?;
            key.verify(full.clone())
                .context("reconstructed proof verification")?;
            ensure!(
                full.clone().compress(digest, common)?.to_bytes() == input,
                "noncanonical query map"
            );
            full.to_bytes()
        }
        _ => anyhow::bail!("unknown mode"),
    };
    fs::write(&args[4], output)?;
    Ok(())
}
