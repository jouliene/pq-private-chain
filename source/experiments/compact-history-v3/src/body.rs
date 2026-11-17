//! Shared prefix parser. Neither full nor reduced objects certify payment validity.
use compact_arities_v3::statement::Statement;
use crate::{wire::{Cursor,hash_blob,append_blob},*};
const ENVELOPE_HEADER:&[u8;8]=b"CPR3\x03\x01\0\0";
#[derive(Debug)]
pub struct UnverifiedPrefix<'a>{raw:&'a [u8],statement:Statement,statement_bytes:&'a [u8],envelopes:[&'a [u8];2],authorization:&'a [u8],proof_len:usize}
impl<'a> UnverifiedPrefix<'a>{
    pub fn raw(&self)->&'a [u8]{self.raw}
    pub fn statement(&self)->&Statement{&self.statement}
    pub fn statement_bytes(&self)->&'a [u8]{self.statement_bytes}
    pub fn envelopes(&self)->[&'a [u8];2]{self.envelopes}
    pub fn authorization(&self)->&'a [u8]{self.authorization}
    pub fn declared_proof_length(&self)->usize{self.proof_len}
}
fn prefix_from<'a>(r:&mut Cursor<'a>)->Result<UnverifiedPrefix<'a>>{
    let start=r.at;
    if r.take(8)?!=b"CPBODY03"||r.u16()?!=3{return Err(Error::Header)}
    let statement_len=r.u16()? as usize;
    let proof_len=r.u32()? as usize;
    let auth_len=r.u16()? as usize;
    if r.u16()?!=0{return Err(Error::Header)}
    if ![448,464,528].contains(&statement_len)||!(1..=PROOF_CAP).contains(&proof_len)||![0,4627].contains(&auth_len){return Err(Error::Length)}
    let statement_bytes=r.take(statement_len)?;
    let statement=Statement::parse(statement_bytes).map_err(|_|Error::Statement)?;
    if auth_len!=if statement.arity.n()==0{4627}else{0}{return Err(Error::Length)}
    let envelopes=[r.take(2164)?,r.take(2164)?];
    if envelopes.iter().any(|e|&e[..8]!=ENVELOPE_HEADER){return Err(Error::Header)}
    let authorization=r.take(auth_len)?;
    let raw=&r.b[start..r.at];
    if raw.len()!=[9423,4812,4876][statement.arity.n()]{return Err(Error::Length)}
    Ok(UnverifiedPrefix{raw,statement,statement_bytes,envelopes,authorization,proof_len})
}
pub fn parse_prefix(b:&[u8])->Result<UnverifiedPrefix<'_>>{
    if b.len()>PREFIX_MAX{return Err(Error::Length)}
    let mut r=Cursor::new(b);let prefix=prefix_from(&mut r)?;r.end()?;Ok(prefix)
}
#[derive(Debug)]
pub struct UnverifiedFullBody<'a>{prefix:UnverifiedPrefix<'a>,proof:&'a [u8],proof_digest:Id,id:Id}
impl<'a> UnverifiedFullBody<'a>{
    pub fn prefix(&self)->&UnverifiedPrefix<'a>{&self.prefix}
    pub fn proof(&self)->&'a [u8]{self.proof}
    pub fn proof_digest(&self)->Id{self.proof_digest}
    pub fn body_id(&self)->Id{self.id}
    pub fn reduced_bytes(&self)->Result<Vec<u8>>{
        let mut b=b"CPSCAN03".to_vec();append_blob(&mut b,self.prefix.raw)?;b.extend(self.proof_digest);Ok(b)
    }
}
pub fn parse_full(b:&[u8])->Result<UnverifiedFullBody<'_>>{
    if b.len()>BODY_MAX{return Err(Error::Length)}
    let mut r=Cursor::new(b);let prefix=prefix_from(&mut r)?;
    let proof=r.take(prefix.proof_len)?;r.end()?;
    let proof_digest=hash_blob(b"PROOF",proof,&[])?;
    let id=hash_blob(b"BODY",prefix.raw,&proof_digest)?;
    Ok(UnverifiedFullBody{prefix,proof,proof_digest,id})
}
#[derive(Debug)]
pub struct UnverifiedReduced<'a>{prefix:UnverifiedPrefix<'a>,proof_digest:Id,id:Id}
impl<'a> UnverifiedReduced<'a>{
    pub fn prefix(&self)->&UnverifiedPrefix<'a>{&self.prefix}
    pub fn proof_digest(&self)->Id{self.proof_digest}
    pub fn body_id(&self)->Id{self.id}
}
pub fn parse_reduced(b:&[u8])->Result<UnverifiedReduced<'_>>{
    if b.len()>REDUCED_MAX{return Err(Error::Length)}
    let mut r=Cursor::new(b);if r.take(8)?!=b"CPSCAN03"{return Err(Error::Header)}
    let prefix=parse_prefix(r.blob(PREFIX_MAX)?)?;
    let proof_digest=r.array()?;r.end()?;
    if b.len()!=[9499,4888,4952][prefix.statement.arity.n()]{return Err(Error::Length)}
    let id=hash_blob(b"BODY",prefix.raw,&proof_digest)?;
    Ok(UnverifiedReduced{prefix,proof_digest,id})
}
pub fn read_full<R:std::io::Read>(reader:R)->Result<Vec<u8>>{let b=crate::wire::bounded_read(reader,BODY_MAX)?;parse_full(&b)?;Ok(b)}
pub fn read_reduced<R:std::io::Read>(reader:R)->Result<Vec<u8>>{let b=crate::wire::bounded_read(reader,REDUCED_MAX)?;parse_reduced(&b)?;Ok(b)}
/// Canonical transport construction only. This does not admit or verify the opaque proof.
pub fn encode_unverified_full(statement:&[u8],envelopes:[&[u8];2],authorization:&[u8],proof:&[u8])->Result<Vec<u8>>{
    if ![448,464,528].contains(&statement.len())||envelopes.iter().any(|e|e.len()!=2164)||![0,4627].contains(&authorization.len())||!(1..=PROOF_CAP).contains(&proof.len()){return Err(Error::Length)}
    let mut b=b"CPBODY03".to_vec();b.extend(3u16.to_le_bytes());b.extend((statement.len() as u16).to_le_bytes());b.extend((proof.len() as u32).to_le_bytes());b.extend((authorization.len() as u16).to_le_bytes());b.extend(0u16.to_le_bytes());
    b.extend(statement);for e in envelopes{b.extend(e)}b.extend(authorization);
    parse_prefix(&b)?;b.extend(proof);Ok(b)
}
