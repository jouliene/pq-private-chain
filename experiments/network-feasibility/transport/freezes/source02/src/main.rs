//! One retained validating process. Commands contain byte identities, never fixture paths.
mod metrics;
mod wire;
use std::{io::{BufRead,Read,Write},path::PathBuf};
use ledger_cp03::{Ledger,CachePolicy};
use serde_json::{Value,json};
#[derive(Debug)]
pub struct Failure(String);
impl std::fmt::Display for Failure{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str(&self.0)}}
impl std::error::Error for Failure{}
impl From<&str> for Failure{fn from(e:&str)->Self{Self(e.to_string())}}
impl From<String> for Failure{fn from(e:String)->Self{Self(e)}}
macro_rules! convert{($($t:ty),*)=>{$(impl From<$t> for Failure{fn from(e:$t)->Self{Self(format!("{e:?}"))}})*};}
convert!(std::io::Error,serde_json::Error,std::array::TryFromSliceError,std::num::ParseIntError,std::num::TryFromIntError,ledger_cp03::Error,cp03_history::Error);
pub type Result<T>=std::result::Result<T,Failure>;
pub fn need(ok:bool,message:&str)->Result<()>{if !ok{return Err(message.to_string().into())}Ok(())}
fn unhex<const N:usize>(s:&str)->Result<[u8;N]>{need(s.len()==N*2&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)),"canonical hex")?;let mut out=[0u8;N];for(i,b)in out.iter_mut().enumerate(){*b=u8::from_str_radix(&s[2*i..2*i+2],16)?;}Ok(out)}
fn hex(b:&[u8])->String{b.iter().map(|x|format!("{x:02x}")).collect()}
fn head(l:&Ledger)->Result<Value>{let h=l.head()?;let c=l.cache_usage()?;let a=l.verification_attempts();Ok(json!({"height":h.height,"block_id":hex(&h.id),"leaf_count":h.leaf_count,"root_le":hex(&h.root.iter().flat_map(|x|x.to_le_bytes()).collect::<Vec<_>>()),"fee_escrow":h.fees,"unconsumed_liabilities":h.liabilities,"cached_bytes":c.cached_bytes,"unexported_bytes":c.unexported_bytes,"archive_committed_bytes":c.archive_committed_bytes,"proof_attempts":a.proofs,"source_signature_attempts":a.source_signatures,"block_version":l.block_version(),"retention":format!("{:?}",c.policy.retention())}))}
fn run()->Result<()>{
    let args=std::env::args().collect::<Vec<_>>();need(args.len()==4,"validator DB CHAIN ARCHIVE_ADDRESS")?;
    let db=PathBuf::from(&args[1]);let chain=unhex::<32>(&args[2])?;let address=&args[3];let mut ledger:Option<Ledger>=None;
    println!("{}",json!({"ready":true,"pid":std::process::id(),"role":"validator","direct_fixture_paths":false}));std::io::stdout().flush()?;
    let mut input=std::io::BufReader::new(std::io::stdin());let mut line=Vec::new();
    loop{
        line.clear();let n=input.by_ref().take(4097).read_until(b'\n',&mut line)?;if n==0{break}need(n<=4096&&line.last()==Some(&b'\n'),"command cap")?;
        let c:Value=serde_json::from_slice(&line)?;let op=c["op"].as_str().ok_or("command op")?;let mut rows=Vec::new();
        let inclusive=metrics::Span::start()?;
        let result:Result<Value>=(||{
            match op{
                "init"|"apply"=>{
                    need(c.as_object().ok_or("command object")?.len()==4&&c["tag"].as_str().is_some_and(|t|t.len()<=32),"command fields")?;
                    let id=unhex::<32>(c["sha256"].as_str().ok_or("object digest")?)?;
                    let size=usize::try_from(c["bytes"].as_u64().ok_or("object bytes")?)?;
                    let kind=if op=="init"{1}else{2};if kind==1{need(size<=339320,"genesis cap")?;need(ledger.is_none(),"already initialized")?;}
                    let (frame,net)=metrics::measure(&mut rows,"receive-identity",||wire::get(address,id,size,kind))??;
                    if op=="init"{
                        ledger=Some(metrics::measure(&mut rows,"trusted-init-durable",||Ledger::create_with_archive_policy(&db,chain,&frame,CachePolicy::retaining(512*1024*1024)?))??);
                        Ok(json!({"accepted":true,"transport":net,"state":head(ledger.as_ref().unwrap())?}))
                    }else{
                        let (header,bodies)=metrics::measure(&mut rows,"bounded-frame-parse-copy",||wire::decode(&frame))??;drop(frame);
                        let l=ledger.as_mut().ok_or("not initialized")?;let h=cp03_history::history::parse_header(&header)?;let current=l.head()?;
                        if h.height()==current.height&&h.block_id()==current.id{
                            let same=metrics::measure(&mut rows,"current-canonical-retry-read",||l.scan_frame(current.height))??;
                            need(cp03_history::history::parse_scan_block(&same[4..])?.header().raw()==header,"exact canonical retry")?;
                            Ok(json!({"accepted":true,"retry_current_canonical":true,"transport":net,"state":head(l)?}))
                        }else{
                            let r=metrics::measure(&mut rows,"genuine-admit-atomic-durable-retain",||l.apply_expected_block(&header,&bodies))?;
                            match r{Ok(_)=>Ok(json!({"accepted":true,"retry_current_canonical":false,"transport":net,"state":head(l)?})),Err(e)=>Ok(json!({"accepted":false,"ledger_error":format!("{e:?}"),"transport":net,"state":head(l)?}))}
                        }
                    }
                },
                "open"=>{need(c.as_object().ok_or("command object")?.len()==1&&ledger.is_none(),"open state")?;ledger=Some(metrics::measure(&mut rows,"trusted-reopen",||Ledger::open(&db,chain))??);Ok(head(ledger.as_ref().unwrap())?)},
                "head"=>{need(c.as_object().ok_or("command object")?.len()==1,"head fields")?;head(ledger.as_ref().ok_or("not initialized")?)},
                "stop"=>{need(c.as_object().ok_or("command object")?.len()==1,"stop fields")?;Ok(json!({"stopped":true}))},
                _=>Err("unknown command".into())
            }
        })();
        inclusive.finish(&mut rows,"inclusive-command-receive-parse-verify-commit-head",&result)?;
        println!("{}",json!({"op":op,"result":result.as_ref().ok(),"error":result.as_ref().err().map(|e|e.to_string()),"stages":rows}));std::io::stdout().flush()?;
        if op=="stop"{break}
    }Ok(())
}

fn main()->Result<()>{
    let start=std::time::Instant::now();
    let result=run(); // All run-local Ledger/provider values are dropped first.
    let terminal=metrics::lifetime(start)?;
    println!("{}",json!({"native_terminal":true,"completed":result.is_ok(),"error":result.as_ref().err().map(|e|e.to_string()),"native_lifetime":terminal}));
    std::io::stdout().flush()?;
    result
}
