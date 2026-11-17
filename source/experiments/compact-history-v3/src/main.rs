//! PUBLIC non-admitted transport controls only; no proof verifier or private input API.
use std::{io::{Read,Cursor as IoCursor},path::Path,cell::Cell,rc::Rc};
use serde::Deserialize;
use serde_json::json;
use compact_history_v3::{body,genesis,history::{self,ScanSession,TrustedScanEndpoint},*};
#[derive(Deserialize)]
struct BodyVector{arity:usize,full:String,prefix:String,reduced:String,proof_digest:String,body_id:String}
#[derive(Deserialize)]
struct Bad{name:String,kind:String,bytes:String}
#[derive(Deserialize)]
struct BadHistory{name:String,stream:String,expected_cursor_height:u64,expected_error:String}
#[derive(Deserialize)]
struct Fixture{format:String,payments_admitted:bool,proof_verified:bool,private_material:bool,chain:String,installed_syntax_ids:Vec<String>,genesis:String,genesis_id:String,bodies:Vec<BodyVector>,headers:Vec<String>,header_ids:Vec<String>,blocks:Vec<String>,stream:String,malformed:Vec<Bad>,history_negatives:Vec<BadHistory>,max_credit_block:String,max_two_block:String}
fn hex(s:&str)->std::result::Result<Vec<u8>,String>{
    if s.len()%2!=0{return Err("hex length".into())}
    s.as_bytes().chunks_exact(2).map(|b|{
        let nib=|x|match x{b'0'..=b'9'=>Ok(x-b'0'),b'a'..=b'f'=>Ok(x-b'a'+10),_=>Err("hex canonicality".to_string())};
        Ok((nib(b[0])?<<4)|nib(b[1])?)
    }).collect()
}
fn arr<const N:usize>(s:&str)->std::result::Result<[u8;N],String>{hex(s)?.try_into().map_err(|_|"array length".into())}
fn checked(ok:bool,name:&str)->std::result::Result<(),String>{if ok{Ok(())}else{Err(name.to_string())}}
fn frame(b:&[u8])->Vec<u8>{let mut out=(b.len() as u32).to_le_bytes().to_vec();out.extend(b);out}
fn complete(bytes:&[u8],config:TrustedScanEndpoint)->Result<history::CompleteHistoryLinkage>{
    let mut session=ScanSession::new(IoCursor::new(bytes),config)?;
    while session.next_block()?.is_some(){}
    session.finish()
}
struct Counted{inner:IoCursor<Vec<u8>>,read:Rc<Cell<usize>>,fail_at:Option<usize>}
impl Read for Counted{
    fn read(&mut self,b:&mut[u8])->std::io::Result<usize>{
        if self.fail_at.is_some_and(|at|self.read.get()>=at){return Err(std::io::Error::other("public injected IO failure"))}
        let max=self.fail_at.map_or(b.len(),|at|b.len().min(at-self.read.get()));
        let n=self.inner.read(&mut b[..max])?;self.read.set(self.read.get()+n);Ok(n)
    }
}
fn run()->std::result::Result<serde_json::Value,String>{
    let args:Vec<_>=std::env::args().collect();if args.len()!=3||args[1]!="controls"{return Err("usage: compact-history-v3 controls PUBLIC_FIXTURE.json".into())}
    let file=std::fs::File::open(Path::new(&args[2])).map_err(|_|"fixture open")?;
    let mut raw=Vec::new();file.take(16*1024*1024+1).read_to_end(&mut raw).map_err(|_|"fixture read")?;
    checked(raw.len()<=16*1024*1024,"fixture cap")?;
    let f:Fixture=serde_json::from_slice(&raw).map_err(|_|"fixture JSON")?;
    checked(f.format=="CP03-NONADMITTED-TRANSPORT-FIXTURES-01"&&!f.payments_admitted&&!f.proof_verified&&!f.private_material,"fixture scope")?;
    let chain=arr(&f.chain)?;let genesis_id=arr(&f.genesis_id)?;
    checked(f.installed_syntax_ids.len()==5&&f.bodies.len()==4&&f.headers.len()==2&&f.header_ids.len()==2&&f.blocks.len()==2,"fixture fixed shape")?;
    let config=TrustedScanEndpoint{chain,genesis_id,expected_height:2,expected_id:arr(&f.header_ids[1])?};
    let spec=genesis::TrustedGenesisSyntaxConfig{chain,protocol:arr(&f.installed_syntax_ids[0])?,profile:arr(&f.installed_syntax_ids[1])?,programs:[arr(&f.installed_syntax_ids[2])?,arr(&f.installed_syntax_ids[3])?,arr(&f.installed_syntax_ids[4])?]};
    let genesis_bytes=hex(&f.genesis)?;let g=genesis::parse_genesis(&genesis_bytes,&spec).map_err(|_|"genesis syntax")?;
    checked(g.genesis_id()==genesis_id&&g.source_count()==1&&g.total()==5_000_000,"independent genesis hash")?;
    let mut checks=vec![json!({"name":"independent-canonical-genesis-hash","class":"syntax/hash-only"})];
    for v in &f.bodies{
        let bytes=hex(&v.full)?;let parsed=body::parse_full(&bytes).map_err(|_|"full syntax")?;
        checked(body::encode_unverified_full(parsed.prefix().statement_bytes(),parsed.prefix().envelopes(),parsed.prefix().authorization(),parsed.proof()).map_err(|_|"full encode")?==bytes,"independent full encoder bytes")?;
        let reduced=parsed.reduced_bytes().map_err(|_|"derive reduced")?;
        let short=body::parse_reduced(&reduced).map_err(|_|"reduced syntax")?;
        checked(parsed.prefix().statement().arity.n()==v.arity&&parsed.prefix().raw()==hex(&v.prefix)?&&reduced==hex(&v.reduced)?&&parsed.proof_digest()==arr(&v.proof_digest)?&&parsed.body_id()==arr(&v.body_id)?&&short.body_id()==parsed.body_id(),"independent full/reduced identity")?;
        checked(reduced.len()==[9499,4888,4952][v.arity],"exact reduced length")?;
        checked(body::read_full(IoCursor::new(&bytes)).map_err(|_|"full bounded reader")?==bytes&&body::read_reduced(IoCursor::new(&reduced)).map_err(|_|"reduced bounded reader")?==reduced,"bounded readers roundtrip")?;
        let mut changed=bytes.clone();let last=changed.len()-1;changed[last]^=1;
        checked(body::parse_full(&changed).map_err(|_|"changed opaque payload syntax")?.body_id()!=parsed.body_id(),"full recomputes actual opaque digest")?;
        checks.push(json!({"name":"full/reduced-independent-ID-and-length","arity":v.arity,"class":"syntax/hash-only","proof_validated":false}));
    }
    for (i,h) in f.headers.iter().enumerate(){let b=hex(h)?;let parsed=history::parse_header(&b).map_err(|_|"header syntax")?;checked(parsed.block_id()==arr(&f.header_ids[i])?,"independent block hash")?;}
    for (i,b) in f.blocks.iter().enumerate(){
        let bytes=hex(b)?;history::parse_scan_block(&bytes).map_err(|_|"valid scan block")?;
        let records=[hex(&f.bodies[2*i].reduced)?,hex(&f.bodies[2*i+1].reduced)?];
        let h=hex(&f.headers[i])?;
        checked(history::encode_unverified_scan_block(&h,&[&records[0],&records[1]]).map_err(|_|"scan encoder")?==bytes,"independent scan encoder bytes")?;
        checked(history::frame_unverified_scan_block(&bytes).map_err(|_|"frame encoder")?==frame(&bytes),"independent frame encoder bytes")?;
        let fields=history::UnverifiedBlockFields{chain,parent:if i==0{genesis_id}else{arr(&f.header_ids[i-1])?},height:(i+1) as u64,leaf_count:4*(i+1) as u64,root:[0;8],fee_escrow:0,unconsumed_liabilities:0,body_ids:vec![arr(&f.bodies[2*i].body_id)?,arr(&f.bodies[2*i+1].body_id)?]};
        checked(history::encode_unverified_header(&fields).map_err(|_|"header encoder")?==h,"independent header encoder bytes")?;
    }
    checks.push(json!({"name":"independent-header-and-scan-block","class":"syntax/hash-only"}));
    let stream=hex(&f.stream)?;let completed=complete(&stream,config).map_err(|_|"complete linkage")?;
    checked(completed.height()==2&&completed.endpoint_id()==config.expected_id&&completed.leaf_count()==8,"independent endpoint completion")?;
    checks.push(json!({"name":"complete-linkage-independent-endpoint","class":"endpoint-relative-linkage-only"}));
    for bad in &f.malformed{
        let b=hex(&bad.bytes)?;
        let result=match bad.kind.as_str(){"full"=>body::parse_full(&b).map(|_|()),"reduced"=>body::parse_reduced(&b).map(|_|()),"header"=>history::parse_header(&b).map(|_|()),"scan"=>history::parse_scan_block(&b).map(|_|()),"genesis"=>genesis::parse_genesis(&b,&spec).map(|_|()),_=>return Err("unknown malformed kind".into())};
        checked(result.is_err(),&bad.name)?;checks.push(json!({"name":bad.name,"class":"actual-parser-reject","error":format!("{:?}",result.unwrap_err())}));
    }
    for bad in &f.history_negatives{
        let data=hex(&bad.stream)?;let count=Rc::new(Cell::new(0));let reader=Counted{inner:IoCursor::new(data),read:count.clone(),fail_at:None};
        let mut session=ScanSession::new(reader,config).map_err(|_|"session config")?;
        let mut consumer_blocks=0;let mut error=None;
        loop{match session.next_block(){Ok(Some(_tentative))=>consumer_blocks+=1,Ok(None)=>break,Err(e)=>{error=Some(e);break}}}
        if error.is_none(){error=session.finish().err();}
        checked(error.is_some()&&session.is_poisoned()&&session.cursor().0==bad.expected_cursor_height&&consumer_blocks==bad.expected_cursor_height,&bad.name)?;
        checked(format!("{:?}",error.unwrap())==bad.expected_error,"specific history rejection class")?;
        let consumed=count.get();checked(session.next_block().is_err()&&count.get()==consumed&&session.finish().is_err(),"poison forbids skip and finish")?;
        checks.push(json!({"name":bad.name,"class":"actual-poisoned-session-reject","cursor_height":session.cursor().0,"consumer_tentative_blocks":consumer_blocks,"error":format!("{:?}",error.unwrap())}));
    }
    let wrong_id=TrustedScanEndpoint{expected_id:[255;64],..config};
    checked(complete(&stream,wrong_id).is_err(),"wrong independent endpoint ID")?;
    let wrong_height=TrustedScanEndpoint{expected_height:3,..config};
    checked(complete(&stream,wrong_height).is_err(),"wrong independent endpoint height")?;
    checks.push(json!({"name":"wrong-independent-endpoint-ID-height","class":"endpoint-relative-linkage-rejection"}));
    let first=frame(&hex(&f.blocks[0])?);
    checked(complete(&first,config).is_err(),"independent current endpoint rejects stale prefix")?;
    let server_chosen=TrustedScanEndpoint{expected_height:1,expected_id:arr(&f.header_ids[0])?,..config};
    checked(complete(&first,server_chosen).is_ok(),"explicit server-endpoint counterexample")?;
    checks.push(json!({"name":"server-chosen-stale-endpoint-counterexample","class":"expected-trust-counterexample","relative_linkage_succeeds":true,"current_history_established":false}));
    let mut mutable=config;let mut copied=ScanSession::new(IoCursor::new(&first),mutable).map_err(|_|"copy endpoint")?;
    mutable.expected_height=1;mutable.expected_id=arr(&f.header_ids[0])?;
    checked(mutable.expected_height==1,"mutate caller config fixture")?;
    while copied.next_block().map_err(|_|"copied config stream")?.is_some(){}
    checked(matches!(copied.finish(),Err(Error::Endpoint)),"session endpoint immutable copy")?;
    checks.push(json!({"name":"immutable-independent-endpoint-copy","class":"session-control"}));
    let zero=TrustedScanEndpoint{expected_height:0,expected_id:genesis_id,..config};
    checked(complete(&[],zero).is_ok()&&complete(&[0],zero).is_err(),"zero endpoint requires exact EOF")?;
    let mut premature=ScanSession::new(IoCursor::new(Vec::<u8>::new()),zero).map_err(|_|"zero config")?;
    checked(premature.finish().is_err()&&premature.is_poisoned(),"zero finish before EOF")?;
    let invalid_zero=TrustedScanEndpoint{expected_id:[255;64],..zero};checked(ScanSession::new(IoCursor::new(Vec::<u8>::new()),invalid_zero).is_err(),"wrong genesis zero endpoint")?;
    checks.push(json!({"name":"zero-endpoint-EOF-and-no-prefix-token","class":"session-control"}));
    let mut aborted=ScanSession::new(IoCursor::new(&stream),config).map_err(|_|"abort config")?;
    checked(aborted.next_block().map_err(|_|"first tentative")?.is_some(),"first tentative before external abort")?;aborted.abort();checked(aborted.finish().is_err()&&aborted.next_block().is_err(),"external operational abort poisons scan")?;
    checks.push(json!({"name":"external-consumer-operational-abort","class":"API-state-control-not-native-fault-test"}));
    let read=Rc::new(Cell::new(0));let mut io_session=ScanSession::new(Counted{inner:IoCursor::new(stream.clone()),read,fail_at:Some(5)},config).map_err(|_|"IO config")?;
    checked(matches!(io_session.next_block(),Err(Error::Io))&&io_session.cursor().0==0&&io_session.finish().is_err(),"IO fault poison")?;
    checks.push(json!({"name":"injected-reader-IO-failure","class":"IO-fault-control-not-crypto"}));
    let read=Rc::new(Cell::new(0));let mut oversized=ScanSession::new(Counted{inner:IoCursor::new(u32::MAX.to_le_bytes().to_vec()),read:read.clone(),fail_at:None},config).map_err(|_|"oversize config")?;
    checked(matches!(oversized.next_block(),Err(Error::Length))&&read.get()==4&&oversized.cursor().0==0,"oversize length before payload read")?;
    checks.push(json!({"name":"oversize-outer-before-allocation-read","class":"bounded-input-control"}));
    for (name,value,expected) in [("max-credit-scan-block",&f.max_credit_block,153292),("max-two-scan-block",&f.max_two_block,80540)]{
        let b=hex(value)?;let parsed=history::parse_scan_block(&b).map_err(|_|"max scan syntax")?;
        checked(b.len()==expected&&parsed.records().len()==16,"max scan exact lengths")?;
        let target=TrustedScanEndpoint{expected_height:1,expected_id:parsed.header().block_id(),..config};checked(complete(&frame(&b),target).is_ok(),"max scan cursor")?;
        checks.push(json!({"name":name,"class":"non-admitted-syntax-limit","bytes":b.len(),"framed_bytes":b.len()+4}));
    }
    let prefix=hex(&f.bodies[0].prefix)?;let mut max_full=prefix;max_full[12..16].copy_from_slice(&(PROOF_CAP as u32).to_le_bytes());max_full.resize(max_full.len()+PROOF_CAP,0);
    checked(max_full.len()==BODY_MAX&&body::parse_full(&max_full).is_ok(),"max opaque full-body syntax")?;
    max_full.push(0);checked(body::parse_full(&max_full).is_err()&&body::read_full(IoCursor::new(max_full)).is_err(),"max plus one full-body rejection")?;
    checks.push(json!({"name":"max-full-body-and-plus-one","class":"non-admitted-syntax-limit"}));
    Ok(json!({"status":"PUBLIC_CP03_TRANSPORT_CONTROLS_PASS","proof_verified":false,"payments_admitted":false,"private_material":false,"consensus_validity_verified":false,"root_state_verified":false,"recovery_complete":false,"checks":checks,"malformed_cases":f.malformed.len(),"history_negative_cases":f.history_negatives.len(),"qualification":"Only syntax/hash and byte linkage relative to independently supplied endpoint; stale-server-endpoint counterexample deliberately retained."}))
}
fn main(){match run(){Ok(v)=>println!("{}",v),Err(name)=>{eprintln!("PUBLIC_CP03_TRANSPORT_CONTROL_FAILED: {name}");std::process::exit(1)}}}
