//! Root-frozen framing. No identifier, program or AIR projection is trusted from a proof.
use p3_field::PrimeField64;

use crate::codec::{Error, MODULUS};
use crate::shape::TrustedShape;
use crate::types::{Challenger, Proof, Val};
use crate::{codec, hash};
use p3_challenger::HashChallenger;

const FRAME_TAG: &[u8] = b"PQPC/CP-FRI/01/FRAME";
const ENVELOPE_MAGIC: &[u8; 8] = b"CPFRI001";
const ENVELOPE_HEADER: usize = 206;
pub const MAX_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
pub const STATEMENT_BYTES: usize = 528;
pub const PUBLIC_VALUES: usize = 49;
const MAX_AMOUNT: u64 = 1_840_960_000_000_000;

#[derive(Clone, Debug)]
pub struct TrustedIdentities {
    pub profile: [u8; 64],
    pub program: [u8; 64],
    pub preprocessing: [u8; 64],
    pub preprocessing_commitment: [u8; 64],
}

pub struct Frame {
    bytes: Vec<u8>,
    digest: [u8; 64],
    profile: [u8; 64],
    program: [u8; 64],
    public_values: [Val; PUBLIC_VALUES],
}

fn u64_at(bytes: &[u8], at: usize) -> Result<u64, Error> {
    let value = bytes
        .get(at..at.checked_add(8).ok_or(Error::Overflow)?)
        .ok_or(Error::Truncated)?;
    Ok(u64::from_le_bytes(
        value.try_into().map_err(|_| Error::Truncated)?,
    ))
}

/// Parses the fixed CP-P2-01 transfer statement and derives its only AIR projection.
pub fn parse_statement(bytes: &[u8; STATEMENT_BYTES]) -> Result<[Val; PUBLIC_VALUES], Error> {
    if &bytes[..8] != b"CP-P2-01"
        || bytes[8..10] != 1u16.to_le_bytes()
        || bytes[10..13] != [2, 2, 1]
        || bytes[13..16] != [0; 3]
    {
        return Err(Error::NonCanonical);
    }
    let fee = u64_at(bytes, 336)?;
    let count = u64_at(bytes, 408)?;
    if fee > MAX_AMOUNT
        || count == 0
        || count > (1u64 << 40)
        || u64_at(bytes, 416)? != 0
        || u64_at(bytes, 424)? != 0
        || bytes[80..144] == bytes[144..208]
    {
        return Err(Error::NonCanonical);
    }
    let mut values = [Val::new(0); PUBLIC_VALUES];
    for (i, part) in bytes[16..48].chunks(7).enumerate() {
        let mut word = [0; 8];
        word[..part.len()].copy_from_slice(part);
        values[i] = Val::new(u64::from_le_bytes(word));
    }
    for i in 0..32 {
        let word = u64_at(bytes, 80 + i * 8)?;
        if word >= MODULUS {
            return Err(Error::NonCanonical);
        }
        values[5 + i] = Val::new(word);
    }
    values[37] = Val::new(fee);
    for i in 0..8 {
        let word = u64_at(bytes, 344 + i * 8)?;
        if word >= MODULUS {
            return Err(Error::NonCanonical);
        }
        values[38 + i] = Val::new(word);
    }
    values[46] = Val::new(count);
    // Credit/debit occupy47/48 and were checked to equal zero above.
    Ok(values)
}

impl Frame {
    pub fn new(ids: &TrustedIdentities, statement: &[u8; STATEMENT_BYTES]) -> Result<Self, Error> {
        let public_values = parse_statement(statement)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(2 + FRAME_TAG.len() + 2 + 5 * 64 + 4 + STATEMENT_BYTES + 4 + 49 * 8)
            .map_err(|_| Error::Allocation)?;
        bytes.extend_from_slice(
            &u16::try_from(FRAME_TAG.len())
                .map_err(|_| Error::Overflow)?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(FRAME_TAG);
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&ids.profile);
        bytes.extend_from_slice(&ids.program);
        bytes.extend_from_slice(&hash::sha3_512(b"PQPC/CP-P2-01/RESEARCH-TRANSFER"));
        bytes.extend_from_slice(&ids.preprocessing);
        bytes.extend_from_slice(&ids.preprocessing_commitment);
        bytes.extend_from_slice(&(STATEMENT_BYTES as u32).to_le_bytes());
        bytes.extend_from_slice(statement);
        bytes.extend_from_slice(&(PUBLIC_VALUES as u32).to_le_bytes());
        for value in public_values {
            bytes.extend_from_slice(&value.as_canonical_u64().to_le_bytes());
        }
        let digest = hash::sha3_512(&bytes);
        Ok(Self {
            bytes,
            digest,
            profile: ids.profile,
            program: ids.program,
            public_values,
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn digest(&self) -> &[u8; 64] {
        &self.digest
    }
    pub fn public_values(&self) -> &[Val; PUBLIC_VALUES] {
        &self.public_values
    }
    /// Start a fresh challenger for EVERY prove/verify operation; never reuse sessions.
    /// HashChallenger's initial input buffer contains all frame bytes before any challenge.
    pub fn challenger(&self) -> Challenger {
        Challenger::new(HashChallenger::new(
            self.bytes.clone(),
            hash::TranscriptHash,
        ))
    }
}

pub fn encode_envelope(
    frame: &Frame,
    shape: &TrustedShape,
    proof: &Proof,
) -> Result<Vec<u8>, Error> {
    let payload = codec::encode(shape, proof)?;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(Error::Limit);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(
            ENVELOPE_HEADER
                .checked_add(payload.len())
                .ok_or(Error::Overflow)?,
        )
        .map_err(|_| Error::Allocation)?;
    bytes.extend_from_slice(ENVELOPE_MAGIC);
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&frame.profile);
    bytes.extend_from_slice(&frame.program);
    bytes.extend_from_slice(&frame.digest);
    bytes.extend_from_slice(
        &u32::try_from(payload.len())
            .map_err(|_| Error::Overflow)?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

pub fn decode_envelope(frame: &Frame, shape: &TrustedShape, bytes: &[u8]) -> Result<Proof, Error> {
    if bytes.len() > ENVELOPE_HEADER + MAX_PAYLOAD_BYTES {
        return Err(Error::Limit);
    }
    if bytes.len() < ENVELOPE_HEADER {
        return Err(Error::Truncated);
    }
    if &bytes[..8] != ENVELOPE_MAGIC || bytes[8..10] != 1u16.to_le_bytes() {
        return Err(Error::NonCanonical);
    }
    if bytes[10..74] != frame.profile
        || bytes[74..138] != frame.program
        || bytes[138..202] != frame.digest
    {
        return Err(Error::Identity);
    }
    let count = usize::try_from(u32::from_le_bytes(
        bytes[202..206].try_into().map_err(|_| Error::Truncated)?,
    ))
    .map_err(|_| Error::Overflow)?;
    if count > MAX_PAYLOAD_BYTES {
        return Err(Error::Limit);
    }
    if bytes.len() != ENVELOPE_HEADER.checked_add(count).ok_or(Error::Overflow)? {
        return Err(Error::NonCanonical);
    }
    codec::decode(shape, &bytes[ENVELOPE_HEADER..])
}
