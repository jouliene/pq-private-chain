//! Operator-pinned public workload; all protocol admission uses the unchanged Ledger.
use ledger_cp03::{Head, StoredBlock, history_codec};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fs, io::Read, path::{Component, Path, PathBuf}};
pub type Result<T> = std::result::Result<T, String>;
pub fn need(ok: bool, why: &str) -> Result<()> { if ok { Ok(()) } else { Err(why.into()) } }
pub fn ledger<T>(r: ledger_cp03::Result<T>) -> Result<T> { r.map_err(|e|format!("Ledger({e:?})")) }
pub fn hex(b: &[u8]) -> String { b.iter().map(|v|format!("{v:02x}")).collect() }
pub fn sha(b: &[u8]) -> String { hex(&Sha256::digest(b)) }
pub fn read(p: &Path, cap: usize) -> Result<Vec<u8>> {
    need(fs::symlink_metadata(p).map_err(|_|"public metadata")?.is_file(), "public regular file")?;
    let mut b = Vec::new();
    fs::File::open(p).map_err(|_|"public open")?.take(cap as u64 + 1)
        .read_to_end(&mut b).map_err(|_|"public read")?;
    need(b.len() <= cap, "public byte cap")?; Ok(b)
}
pub fn public(root: &Path, item: &Value, cap: usize) -> Result<Vec<u8>> {
    let obj = item.as_object().ok_or("public entry")?;
    need(obj.len()==2 && obj.contains_key("path") && obj.contains_key("sha256"), "public entry fields")?;
    let name = item["path"].as_str().ok_or("public path")?;
    let rel = Path::new(name);
    need(!name.is_empty() && rel.components().all(|c| matches!(c, Component::Normal(_))), "normalized relative path")?;
    let mut p = root.to_path_buf();
    for part in rel.components() {
        p.push(part.as_os_str());
        need(!fs::symlink_metadata(&p).map_err(|_|"path component metadata")?.file_type().is_symlink(), "no public symlinks")?;
    }
    let b=read(&p,cap)?;
    need(Some(sha(&b).as_str())==item["sha256"].as_str(), "public SHA256")?; Ok(b)
}
pub struct Inputs {
    pub root: PathBuf, pub chain: [u8;32], pub genesis: Vec<u8>,
    pub rows: Vec<Value>, pub endpoint: Value, pub manifest_sha256: String,
}
pub fn inputs(path: &Path, approved_sha: &str) -> Result<Inputs> {
    need(path.is_absolute() && path.canonicalize().map_err(|_|"manifest path")? == path, "canonical public manifest path")?;
    let root=path.parent().ok_or("manifest parent")?.to_path_buf();
    let raw=read(path,1024*1024)?;
    need(sha(&raw)==approved_sha, "operator workload pin")?;
    let v: Value=serde_json::from_slice(&raw).map_err(|_|"manifest JSON")?;
    need(v["format"]=="CP03-DISTINCT-BLOCK-WORKLOAD01", "workload format")?;
    let chain=v["chain"].as_str().ok_or("chain")?;
    need(chain.len()==64 && chain.bytes().all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x)), "chain hex")?;
    let mut decoded=[0u8;32];
    for (i,x) in decoded.iter_mut().enumerate() { *x=u8::from_str_radix(&chain[2*i..2*i+2],16).map_err(|_|"chain decode")?; }
    let rows=v["blocks"].as_array().ok_or("block rows")?;
    need(rows.len()==2, "two blocks")?;
    for row in rows { need(row["bodies"].as_array().ok_or("body rows")?.len()==16, "sixteen bodies per block")?; }
    let endpoint=v["endpoint"].as_object().ok_or("endpoint")?;
    let names=["height","block_id","leaf_count","root_le","fee_escrow","unconsumed_liabilities"];
    need(endpoint.len()==names.len() && names.iter().all(|n|endpoint.get(*n).is_some_and(Value::is_string)), "endpoint exact fields")?;
    let genesis=public(&root,&v["genesis"],42744)?;
    need(genesis.starts_with(b"CPGEN003"), "genesis magic")?;
    Ok(Inputs{root,chain:decoded,genesis,rows:rows.clone(),endpoint:v["endpoint"].clone(),manifest_sha256:approved_sha.into()})
}
pub fn block(i: &Inputs, n: usize) -> Result<StoredBlock> {
    let row=&i.rows[n];
    let header=public(&i.root,&row["header"],history_codec::HEADER_MAX)?;
    let parsed=history_codec::history::parse_header(&header).map_err(|_|"header transport")?;
    need(parsed.height()==n as u64+1 && parsed.body_ids().len()==16, "block shape")?;
    let mut bodies=Vec::new(); let mut ids=HashSet::new(); let mut nfs=HashSet::new(); let mut sources=HashSet::new();
    let mut common=None;
    for entry in row["bodies"].as_array().ok_or("body rows")? {
        let b=public(&i.root,entry,history_codec::BODY_MAX)?;
        // Exercise the public bounded intake API, not merely the file loader.
        let b=ledger(ledger_cp03::Ledger::read_body(std::io::Cursor::new(b)))?;
        let p=history_codec::body::parse_full(&b).map_err(|_|"body transport")?;
        let s=p.prefix().statement();
        need(s.chain==i.chain && b.get(30)==Some(&(if n==0 {0} else {2})), "common chain and 0x2/2x2 arities")?;
        need(ids.insert(p.body_id()), "distinct genuine bodies")?;
        if n==0 { need(sources.insert(s.source_id.ok_or("credit source")?), "distinct credit sources")?; }
        else {
            for nf in &s.nullifiers { need(nfs.insert(*nf), "disjoint ordinary nullifiers")?; }
            let pair=(s.root,s.count);
            if let Some(old)=common { need(old==pair,"same ordinary anchor")?; } else { common=Some(pair); }
        }
        bodies.push(b);
    }
    need(bodies.len()==16 && bodies.iter().enumerate().all(|(j,b)|
        history_codec::body::parse_full(b).is_ok_and(|p|p.body_id()==parsed.body_ids()[j])), "ordered genuine body identities")?;
    if n==1 { need(nfs.len()==32, "thirty-two independent consumed identities")?; }
    Ok(StoredBlock{header,bodies})
}
pub fn head(h: Head) -> Value {
    let bytes: Vec<u8>=h.root.iter().flat_map(|v|v.to_le_bytes()).collect();
    json!({"height":h.height.to_string(),"block_id":hex(&h.id),"leaf_count":h.leaf_count.to_string(),
        "root_le":hex(&bytes),"fee_escrow":h.fees.to_string(),"unconsumed_liabilities":h.liabilities.to_string()})
}
