//! Genesis canonical syntax under caller-owned installed identities, not issuance approval.
use compact_arities_v3::statement::MAX;
use crate::{wire::{Cursor,hash_blob},*};
pub const LEGACY_GENESIS_MAX:usize=376+16*2648;
pub const GENESIS_MAX:usize=376+128*2648;
#[derive(Clone)]
pub struct TrustedGenesisSyntaxConfig{pub chain:[u8;32],pub protocol:Id,pub profile:Id,pub programs:[Id;3]}
#[derive(Debug)]
pub struct UnverifiedGenesisSyntax{id:Id,source_count:u16,total:u64,version:u16}
impl UnverifiedGenesisSyntax{pub fn genesis_id(&self)->Id{self.id}pub fn source_count(&self)->u16{self.source_count}pub fn total(&self)->u64{self.total}pub fn version(&self)->u16{self.version}}
/// Select only a fixed installed chain profile; this does not accept a manifest.
pub fn version(b:&[u8])->Result<u16>{
    match b.get(..12){
        Some(x)if x==b"CPGEN003\x03\x00\x00\x00"=>Ok(3),
        Some(x)if x==b"CPGEN004\x04\x00\x00\x00"=>Ok(4),
        _=>Err(Error::Header),
    }
}

#[cfg(test)]
mod network04_tests{
    use super::*;
    #[test]
    fn selected_genesis_profile_source_bounds(){
        let config=TrustedGenesisSyntaxConfig{chain:[7;32],protocol:[8;64],profile:[9;64],programs:[[10;64],[11;64],[12;64]]};
        let mut b=b"CPGEN004".to_vec();b.extend(4u16.to_le_bytes());b.extend(0u16.to_le_bytes());b.extend(config.chain);
        b.extend((128u64*2_116_775).to_le_bytes());b.extend(128u16.to_le_bytes());b.extend(1u16.to_le_bytes());
        b.extend(config.protocol);b.extend(config.profile);for p in config.programs{b.extend(p)}
        for i in 0..128u8{b.extend([i;48]);b.extend(2_116_775u64.to_le_bytes());b.extend([0;2592]);}
        assert_eq!(b.len(),GENESIS_MAX);assert_eq!(version(&b).unwrap(),4);
        assert!(parse_genesis_for_version(&b,&config,4).is_ok());
        assert!(parse_genesis(&b,&config).is_err());
        b[52..54].copy_from_slice(&129u16.to_le_bytes());assert!(parse_genesis_for_version(&b,&config,4).is_err());
    }
}
pub fn parse_genesis(b:&[u8],trusted:&TrustedGenesisSyntaxConfig)->Result<UnverifiedGenesisSyntax>{
    parse_genesis_for_version(b,trusted,3)
}
pub fn parse_genesis_for_version(b:&[u8],trusted:&TrustedGenesisSyntaxConfig,expected:u16)->Result<UnverifiedGenesisSyntax>{
    let (magic,max,count_max)=match expected{3=>(b"CPGEN003",LEGACY_GENESIS_MAX,16),4=>(b"CPGEN004",GENESIS_MAX,128),_=>return Err(Error::Header)};
    if b.len()>max{return Err(Error::Length)}
    let mut r=Cursor::new(b);
    if r.take(8)?!=magic||r.u16()?!=expected||r.u16()?!=0{return Err(Error::Header)}
    if r.array::<32>()?!=trusted.chain{return Err(Error::Chain)}
    let total=r.u64()?;let count=r.u16()?;
    if total>MAX||!(1..=count_max).contains(&count)||r.u16()?!=1{return Err(Error::Canonical)}
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
    Ok(UnverifiedGenesisSyntax{id:hash_blob(b"GENESIS",b,&[])?,source_count:count,total,version:expected})
}
