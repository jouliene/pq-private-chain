//! Installed code authority is compile-time. Neither genesis nor bodies select programs.
use crate::{
    Error, Result,
    encoding::{Id, blob, h64, raw_sha3},
};
use compact_all_payments_v3::registry::{PROFILE, PROGRAMS, Registry};
use cp03_history::genesis::TrustedGenesisSyntaxConfig;
use cp03_source_provider::PreparedSourceVerifier;
use std::sync::atomic::{AtomicU64,Ordering};
const MANIFEST: &[u8] = include_bytes!("../../../docs/architecture/CP_PROTOCOL_03.json");
const NETWORK_MANIFEST: &[u8] = include_bytes!("../../../docs/architecture/CP_NETWORK_04.json");
fn hex(bytes: &Id) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
/// Compiled operator-approved contract; no genesis/body-selected manifest or IDs.
fn installed_protocol_manifest(version: u16) -> Result<&'static [u8]> {
    let (bytes, format) = match version {
        3 => (MANIFEST, "PQPC-CP03-RESEARCH-PROTOCOL-01"),
        4 => (NETWORK_MANIFEST, "PQPC-CP04-NETWORK-RESEARCH-PROTOCOL-01"),
        _ => return Err(Error::Identity),
    };
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| Error::ProtocolManifestUnavailable)?;
    let proof = &value["proof"];
    if value["format"].as_str() != Some(format)
        || proof["profile_id"].as_str() != Some(hex(&raw_sha3(PROFILE)).as_str())
    {
        return Err(Error::Identity);
    }
    let programs = proof["program_ids"].as_array().ok_or(Error::Identity)?;
    if programs.len() != PROGRAMS.len()
        || PROGRAMS.iter().enumerate().any(|(n, bytes)| {
            programs[n].as_str() != Some(hex(&raw_sha3(bytes)).as_str())
        })
    {
        return Err(Error::Identity);
    }
    if version == 4 {
        let base_id = h64(b"PROTOCOL", &blob(MANIFEST)?)?;
        if value["base_payment_protocol_id"].as_str() != Some(hex(&base_id).as_str())
            || value["state"]["block_body_count_min"].as_str() != Some("0")
            || value["state"]["block_body_count_max"].as_str() != Some("128")
            || value["state"]["complete_encoded_block_bytes_max"].as_str() != Some("268435456")
            || value["synthetic_sources"]["source_count_max"].as_str() != Some("128")
            || value["network_adapter"]["header_fixed_bytes"].as_str() != Some("216")
        { return Err(Error::Identity); }
    }
    Ok(bytes)
}
pub(crate) struct Installed {
    pub syntax: TrustedGenesisSyntaxConfig,
    pub registry: Registry,
    source_verifier: PreparedSourceVerifier,
    pub version: u16,
    pub proof_attempts: AtomicU64,
    pub source_signature_attempts: AtomicU64,
}
impl Installed {
    pub fn syntax(chain: [u8; 32]) -> Result<TrustedGenesisSyntaxConfig> {
        Self::syntax_for_version(chain, 3)
    }
    pub fn syntax_for_version(chain: [u8; 32], version: u16) -> Result<TrustedGenesisSyntaxConfig> {
        let manifest = installed_protocol_manifest(version)?;
        Ok(TrustedGenesisSyntaxConfig {
            chain,
            protocol: h64(b"PROTOCOL", &blob(manifest)?)?,
            profile: raw_sha3(PROFILE),
            programs: PROGRAMS.map(raw_sha3),
        })
    }
    pub fn load(chain: [u8; 32]) -> Result<Self> {
        Self::load_for_version(chain, 3)
    }
    pub fn load_for_version(chain: [u8; 32], version: u16) -> Result<Self> {
        let syntax = Self::syntax_for_version(chain, version)?;
        let registry = Registry::prepare_public().map_err(|_| Error::Proof)?;
        let source_verifier = PreparedSourceVerifier::prepare()
            .map_err(|_| Error::SourceSignatureProviderUnavailable)?;
        Ok(Self { syntax, registry, source_verifier, version,
            proof_attempts:AtomicU64::new(0),source_signature_attempts:AtomicU64::new(0) })
    }
}
pub(crate) const SOURCE_CONTEXT: &[u8] = b"PQCHAIN-CP3-SOURCE";
/// Narrow pure-ML-DSA-87 provider boundary. No signature-only admission or Boolean verifier.
/// Exact embedded native worker. Operational failure never becomes invalidity or acceptance.
pub(crate) fn verify_source_signature(
    installed: &Installed,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    if public_key.len() != 2592
        || signature.len() != 4627
        || message.len() != 314
        || SOURCE_CONTEXT.len() != 18
    {
        return Err(Error::Source);
    }
    let _=installed.source_signature_attempts.fetch_update(Ordering::Relaxed,Ordering::Relaxed,|n|Some(n.saturating_add(1)));
    match installed.source_verifier.verify(public_key, message, signature) {
        Ok(true) => Ok(()),
        Ok(false) => Err(Error::Source),
        Err(_) => Err(Error::SourceSignatureProviderUnavailable),
    }
}
pub(crate) fn claim_message(
    chain: &[u8; 32],
    source: &[u8; 48],
    credit: u64,
    profile: &Id,
    program: &Id,
    statement: &[u8],
) -> Result<Vec<u8>> {
    let mut message = crate::encoding::tag(b"CLAIM-AUTH")?;
    message.extend(chain);
    message.push(3);
    message.extend(source);
    message.extend(0u64.to_le_bytes());
    message.extend(credit.to_le_bytes());
    message.extend(0u32.to_le_bytes());
    message.extend(profile);
    message.extend(program);
    message.extend(h64(b"STATEMENT", &blob(statement)?)?);
    if message.len() != 314 {
        return Err(Error::Source);
    }
    Ok(message)
}
