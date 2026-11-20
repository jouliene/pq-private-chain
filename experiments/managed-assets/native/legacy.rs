// Historical AST1 proof verification uses the published, operator-selected key.
use crate::registry::Verifier;
use anyhow::{anyhow, ensure, Result};
use plonky2::util::serialization::DefaultGateSerializer;

pub fn registered() -> Result<Verifier> {
    let encoded = include_bytes!("legacy_ast1.vk");
    let verifier = Verifier::from_bytes(encoded.to_vec(), &DefaultGateSerializer)
        .map_err(|_| anyhow!("compiled AST1 verifier encoding"))?;
    let roundtrip = verifier
        .to_bytes(&DefaultGateSerializer)
        .map_err(|_| anyhow!("compiled AST1 verifier serialization"))?;
    ensure!(
        roundtrip == encoded
            && verifier.common.num_public_inputs == 31
            && verifier.common.config.zero_knowledge
            && verifier.common.fri_params.leaf_hiding,
        "compiled AST1 verifier"
    );
    Ok(verifier)
}
