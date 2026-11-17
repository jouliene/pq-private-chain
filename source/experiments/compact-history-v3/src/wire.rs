use std::io::Read;
use tiny_keccak::{Hasher, Sha3};
pub type Id = [u8;64];
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error { Length, Truncated, Header, Canonical, Statement, Chain, Identity, Sequence, Capacity, Endpoint, Poisoned, State, Io, NativeHistoryHash(crate::NativeHistoryHashError) }
pub type Result<T> = core::result::Result<T,Error>;
pub(crate) struct Cursor<'a> { pub b: &'a [u8], pub at: usize }
impl<'a> Cursor<'a> {
    pub fn new(b: &'a [u8]) -> Self { Self { b, at: 0 } }
    pub fn take(&mut self,n:usize) -> Result<&'a [u8]> {
        let end=self.at.checked_add(n).ok_or(Error::Length)?;
        let value=self.b.get(self.at..end).ok_or(Error::Truncated)?;self.at=end;Ok(value)
    }
    pub fn array<const N:usize>(&mut self) -> Result<[u8;N]> { Ok(self.take(N)?.try_into().unwrap()) }
    pub fn u16(&mut self)->Result<u16>{Ok(u16::from_le_bytes(self.array()?))}
    pub fn u32(&mut self)->Result<u32>{Ok(u32::from_le_bytes(self.array()?))}
    pub fn u64(&mut self)->Result<u64>{Ok(u64::from_le_bytes(self.array()?))}
    pub fn blob(&mut self,max:usize)->Result<&'a [u8]>{let n=self.u32()? as usize;if n>max{return Err(Error::Length)}self.take(n)}
    pub fn end(&self)->Result<()>{if self.at==self.b.len(){Ok(())}else{Err(Error::Length)}}
}
pub(crate) fn hash_blob(label:&[u8],b:&[u8],suffix:&[u8])->Result<Id>{
    // Fixed public PROOF role only; BODY and reduced scans retain tiny-keccak.
    if label == b"PROOF" {
        if !suffix.is_empty() { return Err(Error::Length) }
        return crate::native_sha3::proof(b).map_err(|error| match error {
            crate::NativeHistoryHashError::Length => Error::Length,
            other => Error::NativeHistoryHash(other),
        })
    }
    let n=u32::try_from(b.len()).map_err(|_|Error::Length)?;
    let mut tag=b"PQPC/CP3/".to_vec();tag.extend(label);
    let len=u16::try_from(tag.len()).map_err(|_|Error::Length)?;
    let mut h=Sha3::v512();h.update(&len.to_le_bytes());h.update(&tag);h.update(&n.to_le_bytes());h.update(b);h.update(suffix);
    let mut out=[0;64];h.finalize(&mut out);Ok(out)
}
pub(crate) fn append_blob(out:&mut Vec<u8>,b:&[u8])->Result<()> {out.extend(u32::try_from(b.len()).map_err(|_|Error::Length)?.to_le_bytes());out.extend(b);Ok(())}
pub fn bounded_read<R:std::io::Read>(reader:R,max:usize)->Result<Vec<u8>> {
    let limit=max.checked_add(1).ok_or(Error::Length)?;
    let mut b=Vec::new();reader.take(limit as u64).read_to_end(&mut b).map_err(|_|Error::Io)?;
    if b.len()>max{return Err(Error::Length)}Ok(b)
}
