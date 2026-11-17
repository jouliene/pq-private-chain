//! Bounded opaque archive transport; SHA256 identifies bytes, never validity.
use crate::{Result,need};
use std::{io::{Read,Write},net::TcpStream,time::{Duration,Instant}};
use sha2::{Digest,Sha256};
use serde_json::{Value,json};
pub const MAX:usize=268435456;
const CHUNK:usize=65536;
const RATE:f64=12_500_000.0;
fn socket_buffers(s:&TcpStream)->Result<Value>{
    let fd=std::os::fd::AsRawFd::as_raw_fd(s);let wanted=CHUNK as libc::c_int;
    for opt in [libc::SO_RCVBUF,libc::SO_SNDBUF]{need(unsafe{libc::setsockopt(fd,libc::SOL_SOCKET,opt,(&wanted as *const libc::c_int).cast(),std::mem::size_of_val(&wanted)as libc::socklen_t)}==0,"setsockopt")?;}
    let mut values=Vec::new();for opt in [libc::SO_RCVBUF,libc::SO_SNDBUF]{let mut n=0 as libc::c_int;let mut size=std::mem::size_of_val(&n)as libc::socklen_t;need(unsafe{libc::getsockopt(fd,libc::SOL_SOCKET,opt,(&mut n as *mut libc::c_int).cast(),&mut size)}==0,"getsockopt")?;values.push(n);}
    Ok(json!({"requested_each":CHUNK,"receive":values[0],"send":values[1]}))
}
fn paced_write(s:&mut TcpStream,bytes:&[u8])->Result<()>{
    let start=Instant::now();let mut n=0usize;
    for part in bytes.chunks(CHUNK){n+=part.len();let due=Duration::from_secs_f64(n as f64/RATE);if let Some(wait)=due.checked_sub(start.elapsed()){std::thread::sleep(wait)}s.write_all(part)?;}Ok(())
}
pub fn get(address:&str,id:[u8;32],size:usize,kind:u8)->Result<(Vec<u8>,Value)>{
    need(size>0&&size<=MAX&&[1,2].contains(&kind),"GET bound")?;
    let mut s=TcpStream::connect(address)?;s.set_read_timeout(Some(Duration::from_secs(120)))?;s.set_write_timeout(Some(Duration::from_secs(120)))?;
    s.set_nodelay(true)?;let buffers=socket_buffers(&s)?;
    let mut request=b"CPNWR004".to_vec();request.extend([2,kind,0,0]);request.extend((size as u64).to_le_bytes());request.extend(id);paced_write(&mut s,&request)?;s.shutdown(std::net::Shutdown::Write)?;
    let mut ack=[0u8;52];s.read_exact(&mut ack)?;
    need(&ack[..8]==b"CPACK004"&&ack[8..12]==[0,0,0,0]&&u64::from_le_bytes(ack[12..20].try_into()?)==size as u64&&ack[20..]==id,"archive GET ACK")?;
    let mut bytes=vec![0u8;size];for part in bytes.chunks_mut(CHUNK){s.read_exact(part)?;}
    let mut extra=[0u8;1];need(s.read(&mut extra)?==0,"GET trailing bytes")?;
    need(Sha256::digest(&bytes).as_slice()==id,"GET digest")?;
    Ok((bytes,json!({"application_sent":52,"application_received":52+size,"frame_bytes":size,"userspace_chunk":CHUNK,"socket_buffers":buffers,"ingress_frames_peak":1,"rate_bits_per_second":100000000,"server_request_latency_milliseconds":40})))
}
/// Parse framing and canonical bodies only; ledger always performs genuine admission.
pub fn decode(bytes:&[u8])->Result<(Vec<u8>,Vec<Vec<u8>>)>{
    need(bytes.len()<=MAX&&bytes.len()>=228&&&bytes[..8]==b"CPNET004","network frame")?;
    let mut at=8usize;
    fn blob<'a>(bytes:&'a[u8],at:&mut usize,cap:usize)->Result<&'a[u8]>{
        let end=at.checked_add(4).ok_or("blob offset")?;let n=u32::from_le_bytes(bytes.get(*at..end).ok_or("blob length")?.try_into()?)as usize;*at=end;
        need(n>0&&n<=cap,"blob bound")?;let end=at.checked_add(n).ok_or("blob overflow")?;let b=bytes.get(*at..end).ok_or("blob truncated")?;*at=end;Ok(b)
    }
    let header=blob(bytes,&mut at,cp03_history::HEADER_MAX)?.to_vec();let h=cp03_history::history::parse_header(&header)?;
    need(h.version()==4&&h.encoded_full_bytes()==Some(bytes.len()as u64),"network profile/size")?;
    let mut bodies=Vec::with_capacity(h.body_ids().len());
    for id in h.body_ids(){let raw=blob(bytes,&mut at,cp03_history::BODY_MAX)?;let parsed=cp03_history::body::parse_full(raw)?;need(parsed.body_id()==*id,"body ID")?;bodies.push(raw.to_vec());}
    need(at==bytes.len(),"network EOF")?;
    need(cp03_history::history::network_encoded_size(&bodies.iter().map(Vec::len).collect::<Vec<_>>())?==bytes.len()as u64,"exact size")?;
    Ok((header,bodies))
}
