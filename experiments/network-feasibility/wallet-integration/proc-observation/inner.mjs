// Harmless public fork/held-FD-exec discriminator. No cryptography or private input.
import * as fs from 'node:fs';
import {spawnSync} from 'node:child_process';
const namespaces=Object.fromEntries(['pid','mnt','net'].map(n=>[n,fs.readlinkSync('/proc/self/ns/'+n)]));
console.log(JSON.stringify({kind:'ready',pid:process.pid,namespaces}));
process.stdin.once('data',()=>{
 let completed=0;
 for(let i=0;i<96;i++){
  const python=i>=32,exe=python?'/usr/bin/python3.12':'/usr/bin/true';let fd;
  try{
   fd=fs.openSync(exe,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
   const args=python?['-I','-B','-c',i>=64?'import os,time;time.sleep(.006);os.execv("/usr/bin/python3.12",["python3.12","-I","-B","-c","import time;time.sleep(.006)"])':'import time;time.sleep(.006)']:[];
   const r=spawnSync('/proc/self/fd/3',args,{stdio:['ignore','ignore','ignore',fd],env:{PATH:'/usr/bin:/bin',LANG:'C'},timeout:1000,killSignal:'SIGKILL'});
   if(r.error||r.signal||r.status!==0)throw new Error('PUBLIC_CHILD_FAILED');completed++;
  }finally{if(fd!==undefined)fs.closeSync(fd);}
 }
 console.log(JSON.stringify({kind:'done',completed,child_launches:96}));
});
