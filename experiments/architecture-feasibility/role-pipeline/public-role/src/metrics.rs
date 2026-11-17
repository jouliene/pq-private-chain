//! Adapted from executed archive-controls metrics; Linux I/O is self-only.
use crate::fixture::{Result,need};
use serde_json::{Value,json};
use std::{collections::BTreeMap,fs,time::Instant};
struct Usage { user:f64, system:f64, peak:i64, input:i64, output:i64 }
fn usage(who:i32)->Result<Usage>{
    let mut u:libc::rusage=unsafe{std::mem::zeroed()};
    need(unsafe{libc::getrusage(who,&mut u)}==0,"getrusage")?;
    let sec=|t:libc::timeval|->Result<f64>{need(t.tv_sec>=0 && (0..1_000_000).contains(&t.tv_usec),"usage time")?;Ok(t.tv_sec as f64+t.tv_usec as f64/1e6)};
    Ok(Usage{user:sec(u.ru_utime)?,system:sec(u.ru_stime)?,peak:u.ru_maxrss,input:u.ru_inblock,output:u.ru_oublock})
}
fn io()->Result<BTreeMap<String,u64>>{
    let raw=fs::read_to_string("/proc/self/io").map_err(|_|"Linux proc io")?;
    let mut out=BTreeMap::new();
    for line in raw.lines(){let (name,n)=line.split_once(':').ok_or("io field")?;
        out.insert(name.to_string(),n.trim().parse().map_err(|_|"io number")?);}
    need(["rchar","wchar","syscr","syscw","read_bytes","write_bytes","cancelled_write_bytes"].iter().all(|k|out.contains_key(*k)),"io fields")?;Ok(out)
}
pub struct Span { own:Usage, child:Usage, io:BTreeMap<String,u64>, start:Instant }
impl Span {
    pub fn start()->Result<Self>{Ok(Self{own:usage(libc::RUSAGE_SELF)?,child:usage(libc::RUSAGE_CHILDREN)?,io:io()?,start:Instant::now()})}
    pub fn finish<T,E:std::fmt::Debug>(self,rows:&mut Vec<Value>,name:&str,result:&std::result::Result<T,E>)->Result<()> {
        let wall=self.start.elapsed().as_secs_f64();let b=usage(libc::RUSAGE_SELF)?;let d=usage(libc::RUSAGE_CHILDREN)?;let io=io()?;
        let mut delta=BTreeMap::new();for(k,v)in io {delta.insert(k.clone(),v.checked_sub(*self.io.get(&k).ok_or("io key drift")?).ok_or("io counter regressed")?);}
        let cpu=[b.user-self.own.user,b.system-self.own.system,d.user-self.child.user,d.system-self.child.system];
        need(cpu.iter().all(|v|v.is_finite() && *v>=0.0) && wall.is_finite(),"clock deltas")?;
        rows.push(json!({"name":name,"error":result.as_ref().err().map(|e|format!("{e:?}")),"wall_seconds":wall,
            "self_user_seconds":cpu[0],"self_system_seconds":cpu[1],"waited_child_user_seconds":cpu[2],"waited_child_system_seconds":cpu[3],
            "self_peak_rss_kib_cumulative":b.peak,"waited_child_peak_rss_kib_cumulative":d.peak,
            "self_inblock_delta":b.input-self.own.input,"self_oublock_delta":b.output-self.own.output,
            "waited_child_inblock_delta":d.input-self.child.input,"waited_child_oublock_delta":d.output-self.child.output,
            "linux_self_io_delta":delta,"scope":"complete synchronous call; self IO includes sampling overhead, excludes helper IO; waited children separate; cumulative peaks not summed; cold page cache uncontrolled"}));Ok(())
    }
}
pub fn measure<T,E:std::fmt::Debug>(rows:&mut Vec<Value>,name:&str,f:impl FnOnce()->std::result::Result<T,E>)->Result<std::result::Result<T,E>>{
    let s=Span::start()?;let r=f();s.finish(rows,name,&r)?;Ok(r)
}
