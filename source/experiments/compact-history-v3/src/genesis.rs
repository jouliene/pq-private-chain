//! Genesis canonical syntax under caller-owned installed identities, not issuance approval.
use compact_arities_v3::statement::MAX;
use crate::{wire::{Cursor,hash_blob},*};
pub const GENESIS_MAX:usize=376+16*2648;
#[derive(Clone)]
pub struct TrustedGenesisSyntaxConfig{pub chain:[u8;32],pub protocol:Id,pub profile:Id,pub programs:[Id;3]}
#[derive(Debug)]
pub struct UnverifiedGenesisSyntax{id:Id,source_count:u16,total:u64}
impl UnverifiedGenesisSyntax{pub fn genesis_id(&self)->Id{self.id}pub fn source_count(&self)->u16{self.source_count}pub fn total(&self)->u64{self.total}}
pub fn parse_genesis(b:&[u8],trusted:&TrustedGenesisSyntaxConfig)->Result<UnverifiedGenesisSyntax>{
    if b.len()>GENESIS_MAX{return Err(Error::Length)}
    let mut r=Cursor::new(b);
    if r.take(8)?!=b"CPGEN003"||r.u16()?!=3||r.u16()?!=0{return Err(Error::Header)}
    if r.array::<32>()?!=trusted.chain{return Err(Error::Chain)}
    let total=r.u64()?;let count=r.u16()?;
    if total>MAX||!(1..=16).contains(&count)||r.u16()?!=1{return Err(Error::Canonical)}
    if r.array::<64>()?!=trusted.protocol||r.array::<64>()?!=trusted.profile{return Err(Error::Identity)}
    for id in trusted.programs{if r.array::<64>()?!=id{return Err(Error::Identity)}}
    let mut previous=None;let mut sum=0u64;
    for _ in 0..count{
        let source=r.array::<48>()?;
        if previous.is_some_and(|old|old>=source){return Err(Error::Canonical)}previous=Some(source);
        let amount=r.u64()?;
        if !(2_116_775..=MAX).contains(&amount){return Err(Error::Canonical)}
        sum=sum.checked_add(amount).ok_or(Error::Capacity)?;
        r.take(2592)?; // Raw ML-DSA-87 syntax only; no native signature/key verdict.
    }
    r.end()?;if sum!=total{return Err(Error::Canonical)}
    Ok(UnverifiedGenesisSyntax{id:hash_blob(b"GENESIS",b,&[])?,source_count:count,total})
}
