//! Transport hash encodings only. Statement/body/genesis parsing is shared unchanged.
use crate::{Error, Result};
use compact_arities_v3::permutation::P;
use tiny_keccak::{Hasher, Sha3, Shake};
pub type Digest = [u64; 8];
pub type Id = [u8; 64];
pub fn fields(b: &[u8]) -> Result<Digest> {
    if b.len() != 64 {
        return Err(Error::Codec);
    }
    let v = core::array::from_fn(|i| u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap()));
    if v.iter().any(|x| *x >= P) {
        return Err(Error::Codec);
    }
    Ok(v)
}
pub fn field_bytes(v: &Digest) -> Vec<u8> {
    v.iter().flat_map(|v| v.to_le_bytes()).collect()
}
pub fn id(b: Vec<u8>) -> Result<Id> {
    b.try_into().map_err(|_| Error::State)
}
pub fn integer(v: u64) -> Result<i64> {
    i64::try_from(v).map_err(|_| Error::Accounting)
}
pub fn natural(v: i64) -> Result<u64> {
    u64::try_from(v).map_err(|_| Error::State)
}
pub fn tag(label: &[u8]) -> Result<Vec<u8>> {
    let mut v = b"PQPC/CP3/".to_vec();
    v.extend(label);
    let n = u16::try_from(v.len()).map_err(|_| Error::Codec)?;
    let mut out = n.to_le_bytes().to_vec();
    out.extend(v);
    Ok(out)
}
pub fn blob(v: &[u8]) -> Result<Vec<u8>> {
    let mut out = u32::try_from(v.len())
        .map_err(|_| Error::Capacity)?
        .to_le_bytes()
        .to_vec();
    out.extend(v);
    Ok(out)
}
pub fn raw_sha3(v: &[u8]) -> Id {
    let mut h = Sha3::v512();
    h.update(v);
    let mut out = [0; 64];
    h.finalize(&mut out);
    out
}
pub fn h64(label: &[u8], payload: &[u8]) -> Result<Id> {
    let mut h = Sha3::v512();
    h.update(&tag(label)?);
    h.update(payload);
    let mut out = [0; 64];
    h.finalize(&mut out);
    Ok(out)
}
pub fn receipt(chain: &[u8; 32], core: &Digest, ordinal: u16, envelope: &[u8]) -> Result<[u8; 48]> {
    if ordinal > 1 || envelope.len() != 2164 {
        return Err(Error::Receipt);
    }
    let mut h = Shake::v256();
    h.update(&tag(b"RECEIPT")?);
    h.update(chain);
    h.update(&field_bytes(core));
    h.update(&ordinal.to_le_bytes());
    h.update(&blob(envelope)?);
    let mut out = [0; 48];
    h.finalize(&mut out);
    Ok(out)
}
