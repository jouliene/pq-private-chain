//! Version03 framing around the unchanged canonical inner codec.
use crate::{Error, registry::Identities};
use compact_arity_v3::statement::{Arity, Statement};
use compact_proof_v1::{
    codec, hash,
    shape::TrustedShape,
    types::{Challenger, Proof, Val},
};
use p3_challenger::HashChallenger;
use p3_field::PrimeField64;

pub const MAX_ENVELOPE: usize = 2_097_152;
pub const MAX_STATEMENT: usize = 528;
pub const HEADER: usize = 206;
pub const TAG: &[u8] = b"PQPC/CP-FRI/03/FRAME";
pub const CONTEXT: &[u8] = b"PQPC/CP-P2-03/RESEARCH-PAYMENT";
pub const MAGIC: &[u8; 8] = b"CPFRI003";
pub const INNER_CAP: usize = 8 * 1024 * 1024;

pub struct Frame {
    bytes: Vec<u8>,
    digest: [u8; 64],
    ids: Identities,
    arity: Arity,
    public_values: Vec<Val>,
}
impl Frame {
    /// Canonical parser is mandatory even for a caller that already parsed once.
    /// Shape-only frontend bytes/projection cannot enter the verifier otherwise.
    pub(crate) fn new(ids: &Identities, expected: Arity, statement: &[u8]) -> Result<Self, Error> {
        if statement.len() > MAX_STATEMENT {
            return Err(Error::Statement);
        }
        let parsed = Statement::parse(statement).map_err(|_| Error::Statement)?;
        if parsed.arity != expected {
            return Err(Error::Identity);
        }
        let public_values = parsed.projection().map_err(|_| Error::Statement)?;
        if public_values.len() != expected.public_fields()
            || parsed.bytes().map_err(|_| Error::Statement)? != statement
        {
            return Err(Error::Statement);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(
                2 + TAG.len() + 2 + 5 * 64 + 8 + statement.len() + 8 * public_values.len(),
            )
            .map_err(|_| Error::Resource)?;
        bytes.extend((TAG.len() as u16).to_le_bytes());
        bytes.extend(TAG);
        bytes.extend(3u16.to_le_bytes());
        bytes.extend(ids.profile);
        bytes.extend(ids.program);
        bytes.extend(hash::sha3_512(CONTEXT));
        bytes.extend(ids.preprocessing);
        bytes.extend(ids.preprocessing_commitment);
        bytes.extend((statement.len() as u32).to_le_bytes());
        bytes.extend(statement);
        bytes.extend((public_values.len() as u32).to_le_bytes());
        for value in &public_values {
            bytes.extend(value.as_canonical_u64().to_le_bytes());
        }
        let digest = hash::sha3_512(&bytes);
        Ok(Self {
            bytes,
            digest,
            ids: ids.clone(),
            arity: expected,
            public_values,
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn digest(&self) -> &[u8; 64] {
        &self.digest
    }
    pub fn public_values(&self) -> &[Val] {
        &self.public_values
    }
    pub fn arity(&self) -> Arity {
        self.arity
    }
    pub fn challenger(&self) -> Challenger {
        Challenger::new(HashChallenger::new(
            self.bytes.clone(),
            hash::TranscriptHash,
        ))
    }
    pub(crate) fn encode(&self, shape: &TrustedShape, proof: &Proof) -> Result<Vec<u8>, Error> {
        let payload = codec::encode(shape, proof).map_err(|_| Error::Encode)?;
        let length = HEADER.checked_add(payload.len()).ok_or(Error::Resource)?;
        if payload.len() > INNER_CAP || length > MAX_ENVELOPE {
            return Err(Error::ProofTooLarge);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| Error::Resource)?;
        bytes.extend(MAGIC);
        bytes.extend(3u16.to_le_bytes());
        bytes.extend(self.ids.profile);
        bytes.extend(self.ids.program);
        bytes.extend(self.digest);
        bytes.extend(
            u32::try_from(payload.len())
                .map_err(|_| Error::Encode)?
                .to_le_bytes(),
        );
        bytes.extend(payload);
        Ok(bytes)
    }
    pub(crate) fn decode(&self, shape: &TrustedShape, bytes: &[u8]) -> Result<Proof, Error> {
        if bytes.len() > MAX_ENVELOPE {
            return Err(Error::ProofTooLarge);
        }
        if bytes.len() < HEADER || &bytes[..8] != MAGIC || bytes[8..10] != 3u16.to_le_bytes() {
            return Err(Error::Decode);
        }
        if bytes[10..74] != self.ids.profile
            || bytes[74..138] != self.ids.program
            || bytes[138..202] != self.digest
        {
            return Err(Error::Identity);
        }
        let count =
            u32::from_le_bytes(bytes[202..206].try_into().map_err(|_| Error::Decode)?) as usize;
        if count > INNER_CAP || HEADER.checked_add(count) != Some(bytes.len()) {
            return Err(Error::Decode);
        }
        codec::decode(shape, &bytes[HEADER..]).map_err(|_| Error::Decode)
    }
}
