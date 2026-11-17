//! Complete byte linkage relative to an independently supplied endpoint, not ledger validity.
use std::io::{Read,ErrorKind};
use compact_arities_v3::{permutation::P,statement::MAX};
use crate::{body::{self,UnverifiedReduced},wire::{Cursor,hash_blob},*};
#[derive(Debug)]
pub struct UnverifiedHeader<'a>{raw:&'a [u8],chain:[u8;32],parent:Id,height:u64,leaf_count:u64,body_ids:Vec<Id>,id:Id}
impl UnverifiedHeader<'_>{
    pub fn block_id(&self)->Id{self.id}
    pub fn height(&self)->u64{self.height}
    pub fn body_ids(&self)->&[Id]{&self.body_ids}
    pub fn raw(&self)->&[u8]{self.raw}
    pub fn leaf_count(&self)->u64{self.leaf_count}
}
pub fn parse_header(b:&[u8])->Result<UnverifiedHeader<'_>>{
    if b.len()>HEADER_MAX{return Err(Error::Length)}
    let mut r=Cursor::new(b);
    if r.take(8)?!=b"CPBLOCK3"||r.u16()?!=3||r.u16()?!=0{return Err(Error::Header)}
    let chain=r.array()?;let parent=r.array()?;let height=r.u64()?;let count=r.u16()? as usize;
    if height==0||!(1..=16).contains(&count)||r.u16()?!=0{return Err(Error::Canonical)}
    let leaf_count=r.u64()?;
    if leaf_count>CAPACITY{return Err(Error::Capacity)}
    for _ in 0..8{if r.u64()?>=P{return Err(Error::Canonical)}}
    if r.u64()?>MAX||r.u64()?>MAX{return Err(Error::Canonical)}
    let mut body_ids=Vec::with_capacity(count);
    for _ in 0..count{body_ids.push(r.array()?)}r.end()?;
    Ok(UnverifiedHeader{raw:b,chain,parent,height,leaf_count,body_ids,id:hash_blob(b"BLOCK",b,&[])?})
}
#[derive(Debug)]
pub struct UnverifiedScanBlock<'a>{header:UnverifiedHeader<'a>,records:Vec<UnverifiedReduced<'a>>}
impl<'a> UnverifiedScanBlock<'a>{
    pub fn header(&self)->&UnverifiedHeader<'a>{&self.header}
    pub fn records(&self)->&[UnverifiedReduced<'a>]{&self.records}
}
pub fn parse_scan_block(b:&[u8])->Result<UnverifiedScanBlock<'_>>{
    if b.len()>SCAN_BLOCK_MAX{return Err(Error::Length)}
    let mut r=Cursor::new(b);if r.take(8)?!=b"CPSBLK03"{return Err(Error::Header)}
    let header=parse_header(r.blob(HEADER_MAX)?)?;
    let mut records=Vec::with_capacity(header.body_ids.len());
    for expected in &header.body_ids{
        let record=body::parse_reduced(r.blob(REDUCED_MAX)?)?;
        if record.prefix().statement().chain!=header.chain{return Err(Error::Chain)}
        if &record.body_id()!=expected{return Err(Error::Identity)}
        records.push(record);
    }
    r.end()?;Ok(UnverifiedScanBlock{header,records})
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
pub struct ScanSession<R:Read>{reader:R,trusted:TrustedScanEndpoint,height:u64,id:Id,leaf_count:u64,phase:Phase}
impl<R:Read> ScanSession<R>{
    pub fn new(reader:R,trusted:TrustedScanEndpoint)->Result<Self>{
        if trusted.expected_height==0&&trusted.expected_id!=trusted.genesis_id{return Err(Error::Endpoint)}
        Ok(Self{reader,trusted,height:0,id:trusted.genesis_id,leaf_count:0,phase:Phase::Active})
    }
    pub fn cursor(&self)->(u64,Id,u64){(self.height,self.id,self.leaf_count)}
    pub fn is_poisoned(&self)->bool{self.phase==Phase::Poisoned}
    /// Receipt helper/provider or consumer transaction failure must abort the whole epoch.
    pub fn abort(&mut self){self.phase=Phase::Poisoned;}
    fn next_inner(&mut self)->Result<Option<TentativeScanBlock>>{
        if self.phase==Phase::Poisoned{return Err(Error::Poisoned)}
        if self.phase!=Phase::Active{return Err(Error::State)}
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
        if len==0||len>SCAN_BLOCK_MAX{return Err(Error::Length)}
        let mut bytes=vec![0;len];self.reader.read_exact(&mut bytes).map_err(|e|if e.kind()==ErrorKind::UnexpectedEof{Error::Truncated}else{Error::Io})?;
        let block=parse_scan_block(&bytes)?;
        let header=block.header();
        if header.chain!=self.trusted.chain{return Err(Error::Chain)}
        let next=self.height.checked_add(1).ok_or(Error::Sequence)?;
        if header.height!=next||header.parent!=self.id{return Err(Error::Sequence)}
        let additions=(header.body_ids.len() as u64).checked_mul(2).ok_or(Error::Capacity)?;
        let leaves=self.leaf_count.checked_add(additions).ok_or(Error::Capacity)?;
        if leaves>CAPACITY||header.leaf_count!=leaves{return Err(Error::Capacity)}
        let id=header.id;
        if next==self.trusted.expected_height&&id!=self.trusted.expected_id{return Err(Error::Endpoint)}
        drop(block);
        // No callback or consumer mutation occurs before the whole bounded block passes.
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
    let mut b=b"CPBLOCK3".to_vec();b.extend(3u16.to_le_bytes());b.extend(0u16.to_le_bytes());b.extend(v.chain);b.extend(v.parent);b.extend(v.height.to_le_bytes());b.extend((v.body_ids.len() as u16).to_le_bytes());b.extend(0u16.to_le_bytes());b.extend(v.leaf_count.to_le_bytes());
    for x in v.root{b.extend(x.to_le_bytes())}b.extend(v.fee_escrow.to_le_bytes());b.extend(v.unconsumed_liabilities.to_le_bytes());for id in &v.body_ids{b.extend(id)}
    parse_header(&b)?;Ok(b)
}
pub fn encode_unverified_scan_block(header:&[u8],records:&[&[u8]])->Result<Vec<u8>>{
    if header.len()>HEADER_MAX||!(1..=16).contains(&records.len())||records.iter().any(|v|v.len()>REDUCED_MAX){return Err(Error::Length)}
    let mut b=b"CPSBLK03".to_vec();crate::wire::append_blob(&mut b,header)?;
    for r in records{crate::wire::append_blob(&mut b,r)?}parse_scan_block(&b)?;Ok(b)
}
pub fn frame_unverified_scan_block(block:&[u8])->Result<Vec<u8>>{
    parse_scan_block(block)?;let mut b=Vec::with_capacity(block.len()+4);crate::wire::append_blob(&mut b,block)?;Ok(b)
}
