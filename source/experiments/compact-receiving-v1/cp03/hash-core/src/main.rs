//! Fixed private-stdin hash adapter. No proof, source authorization or funding verdict.
use compact_arity_v3::{hash, permutation::P, statement::{Statement, MAX}};
use std::io::{Read, Write};
mod tree;
const BATCH: usize = 256;
const LIMIT: usize = 41 + 2 + BATCH * (2 + 528);
#[derive(Clone, Copy)]
enum Failure { Input, Io }
fn words(b: &[u8], n: usize) -> Result<Vec<u64>, Failure> {
    if b.len() != n * 8 { return Err(Failure::Input); }
    let v: Vec<u64> = b.chunks_exact(8).map(|w| u64::from_le_bytes(w.try_into().unwrap())).collect();
    if v.iter().any(|x| *x >= P) { return Err(Failure::Input); }
    Ok(v)
}
fn encode(v: impl IntoIterator<Item=u64>) -> Vec<u8> {
    v.into_iter().flat_map(u64::to_le_bytes).collect()
}
fn statement(chain: &[u8;32], b: &[u8]) -> Result<Vec<u8>, Failure> {
    let s = Statement::parse(b).map_err(|_| Failure::Input)?;
    if &s.chain != chain { return Err(Failure::Input); }
    let mut out = s.core().map_err(|_| Failure::Input)?.to_vec();
    out.extend(s.output_origins().map_err(|_| Failure::Input)?.into_iter().flatten());
    out.extend(s.commitments.into_iter().flatten());
    Ok(encode(out))
}
fn framed_statement<'a>(payload: &'a [u8], at: &mut usize) -> Result<&'a [u8], Failure> {
    let len_end = at.checked_add(2).ok_or(Failure::Input)?;
    let len = payload.get(*at..len_end).ok_or(Failure::Input)?;
    let n = u16::from_le_bytes(len.try_into().unwrap()) as usize;
    if ![448,464,528].contains(&n) { return Err(Failure::Input); }
    let end = len_end.checked_add(n).ok_or(Failure::Input)?;
    let b = payload.get(len_end..end).ok_or(Failure::Input)?;
    *at = end;
    Ok(b)
}
fn evaluate(b: &[u8]) -> Result<Vec<u8>, Failure> {
    if b.len() < 41 || &b[..8] != b"CPCH0301" { return Err(Failure::Input); }
    let chain: [u8;32] = b[9..41].try_into().unwrap();
    if b[8]!=6&&b.len()>LIMIT { return Err(Failure::Input); }
    let payload = &b[41..];
    match b[8] {
        1 => Ok(encode(hash::hash(&chain, hash::AUTH, &words(payload,5)?))),
        2 => {
            let note=words(payload,20)?;
            if note[0]!=0 || note[1]>MAX { return Err(Failure::Input); }
            Ok(encode(hash::hash(&chain,hash::NOTE,&note)))
        }
        3 => Ok(encode(hash::hash(&chain,hash::NF,&words(payload,21)?))),
        4 => {
            let mut at=0;
            let s=framed_statement(payload,&mut at)?;
            if at!=payload.len() { return Err(Failure::Input); }
            statement(&chain,s)
        }
        5 => {
            let count=u16::from_le_bytes(payload.get(..2).ok_or(Failure::Input)?.try_into().unwrap()) as usize;
            if !(1..=BATCH).contains(&count) { return Err(Failure::Input); }
            let capacity=count.checked_mul(322).and_then(|v|v.checked_add(2)).ok_or(Failure::Input)?;
            let mut out=Vec::with_capacity(capacity);
            out.extend((count as u16).to_le_bytes());
            let mut at=2;
            for i in 0..count {
                let s=framed_statement(payload,&mut at)?;
                let result=statement(&chain,s)?;
                out.extend((i as u16).to_le_bytes());
                out.extend(result);
            }
            if at!=payload.len() { return Err(Failure::Input); }
            // Nothing is emitted until the entire batch has passed, including EOF.
            Ok(out)
        }
        6 => tree::advance(&chain,payload),
        _ => Err(Failure::Input),
    }
}
fn run() -> Result<(),Failure> {
    let mut b=Vec::new();
    let mut input=std::io::stdin().lock();
    let prefix=input.by_ref().take(9).read_to_end(&mut b);
    let limit=if b.len()==9 && &b[..8]==b"CPCH0301" && b[8]==6 {tree::REQUEST_MAX}else{LIMIT};
    let read=prefix.and_then(|_|input.take((limit+1-b.len())as u64).read_to_end(&mut b));
    let result=match read {
        Err(_)=>Err(Failure::Io),
        Ok(_)=>if b.len()<=limit { evaluate(&b) } else { Err(Failure::Input) },
    };
    // Best-effort clearing, not a guaranteed allocator/compiler erasure boundary.
    b.fill(0);
    let mut out=result?;
    let written=std::io::stdout().write_all(&out);
    out.fill(0);
    written.map_err(|_|Failure::Io)
}
fn main() {
    if let Err(error)=run() {
        let (message,code)=match error {
            Failure::Input=>("CP03_HASH_INPUT_REJECTED",1),
            Failure::Io=>("CP03_HASH_IO_FAILURE",2),
        };
        eprintln!("{message}");
        std::process::exit(code);
    }
}
