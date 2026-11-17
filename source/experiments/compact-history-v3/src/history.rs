//! Complete byte linkage relative to an independently supplied endpoint, not ledger validity.
use std::io::{Read,ErrorKind};
use compact_arities_v3::{permutation::P,statement::MAX};
use crate::{body::{self,UnverifiedReduced},wire::{Cursor,hash_blob},*};
#[derive(Debug)]
pub struct UnverifiedHeader<'a>{raw:&'a [u8],chain:[u8;32],parent:Id,height:u64,leaf_count:u64,body_ids:Vec<Id>,id:Id,version:u16,encoded_full_bytes:Option<u64>,root:[u64;8],fees:u64,liabilities:u64}
impl UnverifiedHeader<'_>{
    pub fn block_id(&self)->Id{self.id}
    pub fn height(&self)->u64{self.height}
    pub fn body_ids(&self)->&[Id]{&self.body_ids}
    pub fn raw(&self)->&[u8]{self.raw}
    pub fn leaf_count(&self)->u64{self.leaf_count}
    pub fn version(&self)->u16{self.version}
    pub fn encoded_full_bytes(&self)->Option<u64>{self.encoded_full_bytes}
}
pub fn parse_header(b:&[u8])->Result<UnverifiedHeader<'_>>{
    if b.len()>HEADER_MAX{return Err(Error::Length)}
    let mut r=Cursor::new(b);
    let magic=r.take(8)?;let version=r.u16()?;
    if !((magic==b"CPBLOCK3"&&version==3)||(magic==b"CPBLOCK4"&&version==4))||r.u16()?!=0{return Err(Error::Header)}
    if version==3&&b.len()>LEGACY_HEADER_MAX{return Err(Error::Length)}
    let chain=r.array()?;let parent=r.array()?;let height=r.u64()?;let count=r.u16()? as usize;
    if height==0||(version==3&&!(1..=LEGACY_BODY_COUNT_MAX).contains(&count))||(version==4&&count>NETWORK_BODY_COUNT_MAX)||r.u16()?!=0{return Err(Error::Canonical)}
    let leaf_count=r.u64()?;
    if leaf_count>CAPACITY{return Err(Error::Capacity)}
    let mut root=[0u64;8];for x in &mut root{*x=r.u64()?;if *x>=P{return Err(Error::Canonical)}}
    let fees=r.u64()?;let liabilities=r.u64()?;
    if fees>MAX||liabilities>MAX{return Err(Error::Canonical)}
    let encoded_full_bytes=if version==4{
        let n=r.u64()?;
        if n>NETWORK_BLOCK_MAX as u64||n<(12+b.len()+4*count)as u64{return Err(Error::Length)}
        Some(n)
    }else{None};
    let mut body_ids=Vec::with_capacity(count);
    for _ in 0..count{body_ids.push(r.array()?)}r.end()?;
    Ok(UnverifiedHeader{raw:b,chain,parent,height,leaf_count,body_ids,id:hash_blob(b"BLOCK",b,&[])?,version,encoded_full_bytes,root,fees,liabilities})
}
#[derive(Debug)]
pub struct UnverifiedScanBlock<'a>{header:UnverifiedHeader<'a>,records:Vec<UnverifiedReduced<'a>>}
impl<'a> UnverifiedScanBlock<'a>{
    pub fn header(&self)->&UnverifiedHeader<'a>{&self.header}
    pub fn records(&self)->&[UnverifiedReduced<'a>]{&self.records}
}
pub fn parse_scan_block(b:&[u8])->Result<UnverifiedScanBlock<'_>>{
    if b.len()>SCAN_BLOCK_MAX{return Err(Error::Length)}
    let mut r=Cursor::new(b);let magic=r.take(8)?;
    let header=parse_header(r.blob(HEADER_MAX)?)?;
    if !((magic==b"CPSBLK03"&&header.version==3)||(magic==b"CPSBLK04"&&header.version==4)){return Err(Error::Header)}
    if header.version==3&&b.len()>LEGACY_SCAN_BLOCK_MAX{return Err(Error::Length)}
    let mut records=Vec::with_capacity(header.body_ids.len());
    for expected in &header.body_ids{
        let record=body::parse_reduced(r.blob(REDUCED_MAX)?)?;
        if record.prefix().statement().chain!=header.chain{return Err(Error::Chain)}
        if &record.body_id()!=expected{return Err(Error::Identity)}
        records.push(record);
    }
    r.end()?;
    if header.version==4{
        let sizes=records.iter().map(|r|r.prefix().raw().len()+r.prefix().declared_proof_length()).collect::<Vec<_>>();
        if header.encoded_full_bytes!=Some(network_encoded_size(&sizes)?){return Err(Error::Length)}
    }
    Ok(UnverifiedScanBlock{header,records})
}
/// Operator configuration. Do not construct this from the archive server's response.
#[derive(Clone,Copy)]
pub struct TrustedScanEndpoint{pub chain:[u8;32],pub genesis_id:Id,pub expected_height:u64,pub expected_id:Id}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum Phase{Active,Eof,Finished,Poisoned}
/// Holds one complete checked transport block only. All wallet effects remain tentative.
#[derive(Debug)]
pub struct TentativeScanBlock{bytes:Vec<u8>,height:u64,id:Id}
impl TentativeScanBlock{
    pub fn raw(&self)->&[u8]{&self.bytes}
    pub fn parsed(&self)->Result<UnverifiedScanBlock<'_>>{parse_scan_block(&self.bytes)}
    pub fn height(&self)->u64{self.height}
    pub fn block_id(&self)->Id{self.id}
}
/// Only byte completeness/linkage under the supplied endpoint and hash-binding assumption.
/// Private fields prevent construction as a generic accepted-payment flag.
#[derive(Debug)]
pub struct CompleteHistoryLinkage{height:u64,id:Id,leaf_count:u64}
impl CompleteHistoryLinkage{pub fn height(&self)->u64{self.height}pub fn endpoint_id(&self)->Id{self.id}pub fn leaf_count(&self)->u64{self.leaf_count}}
pub struct ScanSession<R:Read>{reader:R,trusted:TrustedScanEndpoint,height:u64,id:Id,leaf_count:u64,phase:Phase,version:u16,prior_state:Option<([u64;8],u64,u64)>}
impl<R:Read> ScanSession<R>{
    pub fn new(reader:R,trusted:TrustedScanEndpoint)->Result<Self>{
        Self::new_for_version(reader,trusted,3)
    }
    pub fn new_for_version(reader:R,trusted:TrustedScanEndpoint,version:u16)->Result<Self>{
        if ![3,4].contains(&version){return Err(Error::Header)}
        if trusted.expected_height==0&&trusted.expected_id!=trusted.genesis_id{return Err(Error::Endpoint)}
        Ok(Self{reader,trusted,height:0,id:trusted.genesis_id,leaf_count:0,phase:Phase::Active,version,prior_state:None})
    }
    /// Bind the canonical genesis state reconstructed by the caller from its
    /// fixed chain profile and parsed genesis, never from the first peer header.
    pub fn with_genesis_state(mut self,root:[u64;8],liabilities:u64)->Result<Self>{
        if self.height!=0||self.phase!=Phase::Active||root.iter().any(|x|*x>=P)||liabilities>MAX{return Err(Error::State)}
        self.prior_state=Some((root,0,liabilities));Ok(self)
    }
    pub fn cursor(&self)->(u64,Id,u64){(self.height,self.id,self.leaf_count)}
    pub fn is_poisoned(&self)->bool{self.phase==Phase::Poisoned}
    /// Receipt helper/provider or consumer transaction failure must abort the whole epoch.
    pub fn abort(&mut self){self.phase=Phase::Poisoned;}
    fn next_inner(&mut self)->Result<Option<TentativeScanBlock>>{
        if self.phase==Phase::Poisoned{return Err(Error::Poisoned)}
        if self.phase!=Phase::Active{return Err(Error::State)}
        if self.version==4&&self.prior_state.is_none(){return Err(Error::State)}
        let mut prefix=[0u8;4];let mut have=0;
        while have<4{
            match self.reader.read(&mut prefix[have..]){
                Ok(0) if have==0=>{self.phase=Phase::Eof;return Ok(None)},
                Ok(0)=>return Err(Error::Truncated),
                Ok(n)=>{have+=n;},
                Err(e) if e.kind()==ErrorKind::Interrupted=>continue,
                Err(_)=>return Err(Error::Io),
            }
        }
        // Extra framed blocks cannot be consumed after the expected endpoint.
        if self.height>=self.trusted.expected_height{return Err(Error::Endpoint)}
        let len=u32::from_le_bytes(prefix) as usize;
        if len==0||len>if self.version==3{LEGACY_SCAN_BLOCK_MAX}else{SCAN_BLOCK_MAX}{return Err(Error::Length)}
        let mut bytes=vec![0;len];self.reader.read_exact(&mut bytes).map_err(|e|if e.kind()==ErrorKind::UnexpectedEof{Error::Truncated}else{Error::Io})?;
        let block=parse_scan_block(&bytes)?;
        let header=block.header();
        if header.version!=self.version{return Err(Error::Header)}
        if header.body_ids.is_empty()&&self.prior_state!=Some((header.root,header.fees,header.liabilities)){return Err(Error::Canonical)}
        if header.chain!=self.trusted.chain{return Err(Error::Chain)}
        let next=self.height.checked_add(1).ok_or(Error::Sequence)?;
        if header.height!=next||header.parent!=self.id{return Err(Error::Sequence)}
        let additions=(header.body_ids.len() as u64).checked_mul(2).ok_or(Error::Capacity)?;
        let leaves=self.leaf_count.checked_add(additions).ok_or(Error::Capacity)?;
        if leaves>CAPACITY||header.leaf_count!=leaves{return Err(Error::Capacity)}
        let id=header.id;
        let state=(header.root,header.fees,header.liabilities);
        if next==self.trusted.expected_height&&id!=self.trusted.expected_id{return Err(Error::Endpoint)}
        drop(block);
        // No callback or consumer mutation occurs before the whole bounded block passes.
        self.prior_state=Some(state);
        self.height=next;self.id=id;self.leaf_count=leaves;
        Ok(Some(TentativeScanBlock{bytes,height:next,id}))
    }
    pub fn next_block(&mut self)->Result<Option<TentativeScanBlock>>{
        match self.next_inner(){Ok(v)=>Ok(v),Err(e)=>{self.phase=Phase::Poisoned;Err(e)}}
    }
    pub fn finish(&mut self)->Result<CompleteHistoryLinkage>{
        let result=if self.phase==Phase::Poisoned{Err(Error::Poisoned)}
        else if self.phase!=Phase::Eof{Err(Error::State)}
        else if self.height!=self.trusted.expected_height||self.id!=self.trusted.expected_id{Err(Error::Endpoint)}
        else{Ok(CompleteHistoryLinkage{height:self.height,id:self.id,leaf_count:self.leaf_count})};
        match result{Ok(v)=>{self.phase=Phase::Finished;Ok(v)},Err(e)=>{self.phase=Phase::Poisoned;Err(e)}}
    }
}
/// Ledger-produced values remain unverified here; this builder checks only the wire contract.
pub struct UnverifiedBlockFields{pub chain:[u8;32],pub parent:Id,pub height:u64,pub leaf_count:u64,pub root:[u64;8],pub fee_escrow:u64,pub unconsumed_liabilities:u64,pub body_ids:Vec<Id>}
pub fn encode_unverified_header(v:&UnverifiedBlockFields)->Result<Vec<u8>>{
    if !(1..=16).contains(&v.body_ids.len()){return Err(Error::Length)}
    encode_header(v,3,None)
}
pub fn encode_network_header(v:&UnverifiedBlockFields,encoded_full_bytes:u64)->Result<Vec<u8>>{
    if v.body_ids.len()>NETWORK_BODY_COUNT_MAX{return Err(Error::Length)}
    encode_header(v,4,Some(encoded_full_bytes))
}
fn encode_header(v:&UnverifiedBlockFields,version:u16,encoded:Option<u64>)->Result<Vec<u8>>{
    let mut b=if version==3{b"CPBLOCK3".to_vec()}else{b"CPBLOCK4".to_vec()};b.extend(version.to_le_bytes());b.extend(0u16.to_le_bytes());b.extend(v.chain);b.extend(v.parent);b.extend(v.height.to_le_bytes());b.extend((v.body_ids.len() as u16).to_le_bytes());b.extend(0u16.to_le_bytes());b.extend(v.leaf_count.to_le_bytes());
    for x in v.root{b.extend(x.to_le_bytes())}b.extend(v.fee_escrow.to_le_bytes());b.extend(v.unconsumed_liabilities.to_le_bytes());if let Some(n)=encoded{b.extend(n.to_le_bytes())}for id in &v.body_ids{b.extend(id)}
    parse_header(&b)?;Ok(b)
}
pub fn encode_unverified_scan_block(header:&[u8],records:&[&[u8]])->Result<Vec<u8>>{
    let h=parse_header(header)?;
    if records.len()!=h.body_ids.len()||records.iter().any(|v|v.len()>REDUCED_MAX){return Err(Error::Length)}
    let mut b=if h.version==3{b"CPSBLK03".to_vec()}else{b"CPSBLK04".to_vec()};crate::wire::append_blob(&mut b,header)?;
    for r in records{crate::wire::append_blob(&mut b,r)?}parse_scan_block(&b)?;Ok(b)
}
/// Complete CPNET004 bytes: magic8 + header blob4 + header216+64n + n body blobs.
pub fn network_encoded_size(lengths:&[usize])->Result<u64>{
    if lengths.len()>NETWORK_BODY_COUNT_MAX||lengths.iter().any(|n|*n==0||*n>BODY_MAX){return Err(Error::Length)}
    let mut total=228u64.checked_add(68*lengths.len()as u64).ok_or(Error::Length)?;
    for n in lengths{total=total.checked_add(*n as u64).ok_or(Error::Length)?;}
    if total>NETWORK_BLOCK_MAX as u64{return Err(Error::Length)}Ok(total)
}
pub fn encode_network_block(header:&[u8],bodies:&[&[u8]])->Result<Vec<u8>>{
    let h=parse_header(header)?;
    if h.version!=4||h.body_ids.len()!=bodies.len()||h.encoded_full_bytes!=Some(network_encoded_size(&bodies.iter().map(|b|b.len()).collect::<Vec<_>>())?){return Err(Error::Length)}
    let mut out=b"CPNET004".to_vec();crate::wire::append_blob(&mut out,header)?;
    for (bytes,id)in bodies.iter().zip(&h.body_ids){
        let b=body::parse_full(bytes)?;
        if &b.body_id()!=id||b.prefix().statement().chain!=h.chain{return Err(Error::Identity)}
        crate::wire::append_blob(&mut out,bytes)?;
    }
    if Some(out.len()as u64)!=h.encoded_full_bytes{return Err(Error::Length)}Ok(out)
}
pub fn frame_unverified_scan_block(block:&[u8])->Result<Vec<u8>>{
    parse_scan_block(block)?;let mut b=Vec::with_capacity(block.len()+4);crate::wire::append_blob(&mut b,block)?;Ok(b)
}

#[cfg(test)]
mod network04_tests {
    use super::*;
    fn fields(ids:Vec<Id>)->UnverifiedBlockFields{
        UnverifiedBlockFields{chain:[7;32],parent:[9;64],height:1,leaf_count:0,root:[0;8],fee_escrow:0,unconsumed_liabilities:0,body_ids:ids}
    }
    #[test]
    fn empty_shape_and_exact_reduced_full_length(){
        let h=encode_network_header(&fields(vec![]),228).unwrap();
        assert_eq!(h.len(),216);assert_eq!(encode_network_block(&h,&[]).unwrap().len(),228);
        let scan=encode_unverified_scan_block(&h,&[]).unwrap();
        assert_eq!(scan.len(),228);assert_eq!(parse_scan_block(&scan).unwrap().header().version(),4);
        let mut bad=h.clone();bad[208..216].copy_from_slice(&229u64.to_le_bytes());
        assert!(encode_unverified_scan_block(&bad,&[]).is_err());
        assert!(encode_unverified_header(&fields(vec![])).is_err());
    }
    #[test]
    fn independent_count_and_byte_caps(){
        assert_eq!(network_encoded_size(&[]).unwrap(),228);
        assert!(network_encoded_size(&vec![BODY_MAX;128]).is_err());
        assert!(network_encoded_size(&vec![1;129]).is_err());
        assert!(network_encoded_size(&vec![1;128]).is_ok());
        let mut h=encode_network_header(&fields(vec![]),228).unwrap();
        h[..8].copy_from_slice(b"CPBLOCK3");assert!(parse_header(&h).is_err());
    }
    #[test]
    fn version_selected_before_empty_stream_acceptance(){
        let trusted=TrustedScanEndpoint{chain:[7;32],genesis_id:[9;64],expected_height:1,expected_id:[0;64]};
        let h=encode_network_header(&fields(vec![]),228).unwrap();
        let frame=frame_unverified_scan_block(&encode_unverified_scan_block(&h,&[]).unwrap()).unwrap();
        let mut old=ScanSession::new(std::io::Cursor::new(&frame),trusted).unwrap();
        assert!(old.next_block().is_err());
        let mut unbound=ScanSession::new_for_version(std::io::Cursor::new(&frame),trusted,4).unwrap();
        assert!(unbound.next_block().is_err());
    }
}
