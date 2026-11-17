//! Quiescent own-catalog readback; no SQL writes and no copied producer verdict.
use crate::fixture::{Inputs,Result,hex,need,read};
use ledger_cp03::{StoredBlock,history_codec};
use rusqlite::{Connection,OpenFlags};
use serde_json::{Value,json};
use std::{fs,os::unix::{ffi::OsStrExt,fs::MetadataExt},path::Path};
pub fn archive(i:&Inputs, blocks:&[StoredBlock],db:&Path,dir:&Path)->Result<Value>{
    let c=Connection::open_with_flags(db,OpenFlags::SQLITE_OPEN_READ_ONLY|OpenFlags::SQLITE_OPEN_NO_MUTEX).map_err(|_|"catalog open")?;
    let(catalog,genesis):(Vec<u8>,Vec<u8>)=c.query_row("SELECT catalog_id,genesis_id FROM body_cache,meta",[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|_|"catalog binding")?;
    need(catalog.len()==32 && genesis.len()==64,"catalog lengths")?;
    let dm=fs::metadata(db).map_err(|_|"db stat")?;let am=fs::metadata(dir).map_err(|_|"archive stat")?;
    let p=db.canonicalize().map_err(|_|"db canonical")?;let pb=p.as_os_str().as_bytes();
    let mut marker=b"CPBIND03".to_vec();marker.extend(3u16.to_le_bytes());marker.extend(0u16.to_le_bytes());marker.extend(i.chain);marker.extend(&genesis);marker.extend(&catalog);
    for n in[dm.dev(),dm.ino(),am.dev(),am.ino()]{marker.extend(n.to_le_bytes());}
    marker.extend((pb.len()as u32).to_le_bytes());marker.extend(pb);
    need(read(&dir.join("BINDING"),4272)?==marker,"exact own archive binding")?;
    let mut expected=b"CPARCH03".to_vec();expected.extend(3u16.to_le_bytes());expected.extend(0u16.to_le_bytes());expected.extend(i.chain);expected.extend(&genesis);expected.extend(&catalog);expected.extend(0u64.to_le_bytes());
    need(expected.len()==148,"segment header")?;
    let mut offsets=Vec::new();let mut ids=Vec::new();let mut lengths=Vec::new();
    for block in blocks {for full in &block.bodies {
        let p=history_codec::body::parse_full(full).map_err(|_|"archive expected body")?;
        offsets.push(expected.len()as u64);ids.push(p.body_id());lengths.push(full.len());
        expected.extend((full.len()as u32).to_le_bytes());expected.extend(p.body_id());expected.extend(full);
    }}
    need(ids.len()==32 && expected.len()<=64*1024*1024,"bounded single segment fixture")?;
    let segment=dir.join("segments/0000000000000000/0000000000000000.cpar");
    need(read(&segment,64*1024*1024)?==expected,"all32 genuine ordered archive records exact")?;
    let segments: i64=c.query_row("SELECT COUNT(*) FROM archive_segments",[],|r|r.get(0)).map_err(|_|"segment count")?;
    let end:(i64,i64,i64)=c.query_row("SELECT segment,committed_end,sealed FROM archive_segments",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|_|"segment row")?;
    need(segments==1 && end==(0,expected.len()as i64,0),"one exact segment catalog")?;
    let mut stmt=c.prepare("SELECT id,full_length,segment,record_offset FROM archive_objects ORDER BY record_offset").map_err(|_|"objects prepare")?;
    let rows=stmt.query_map([],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?)))
        .map_err(|_|"objects query")?.collect::<rusqlite::Result<Vec<_>>>().map_err(|_|"object row")?;
    need(rows.len()==32,"all32 object locators")?;
    for(j,(id,len,seg,at))in rows.iter().enumerate(){need(id.as_slice()==ids[j].as_slice() && *len==lengths[j]as i64 && *seg==0 && *at==offsets[j]as i64,"exact object locator")?;}
    let m=fs::metadata(segment).map_err(|_|"segment physical")?;
    Ok(json!({"own_binding_exact":true,"own_catalog_id":hex(&catalog),"all32_framed_bodies_exact":true,"objects":32,"record_offsets":offsets,
        "segment_logical_bytes":m.len(),"segment_allocated_512_byte_blocks":m.blocks(),"scope":"quiescent single-segment fixture; random catalogs not compared across independent ledgers"}))
}
