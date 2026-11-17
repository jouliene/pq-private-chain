// Fixed trusted Rust program. Expected digest is operator configuration, never receipt input.
import * as fs from 'node:fs';
import * as c from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {LocalReceiptMiss,HashCoreFailure} from './errors.mjs';
const EXECUTABLE=fileURLToPath(new URL('./hash-core/target/release/cp03-hash-core',import.meta.url));
export const BATCH_LIMIT=256,REQUEST_MAX=135723,RESPONSE_MAX=82434;
const P=18446744069414584321n;
function fail(){throw new HashCoreFailure();}
function input(ok){if(!ok)throw new LocalReceiptMiss();}
function executableBytes(fd){
  const st=fs.fstatSync(fd);if(!st.isFile()||st.size<=0||st.size>32*1024*1024)fail();
  const b=Buffer.alloc(st.size+1);let at=0;
  while(at<b.length){const n=fs.readSync(fd,b,at,b.length-at,at);if(!n)break;at+=n;}
  if(at!==st.size||fs.fstatSync(fd).size!==st.size)fail();return b.subarray(0,at);
}
export function decodeFieldResponse(response,words){
  // This is the production success boundary for every AUTH/NOTE/NF/statement response.
  if(![8,40].includes(words)||!Buffer.isBuffer(response)||response.length!==8*words)fail();
  for(let j=0;j<words;j++)if(response.readBigUInt64LE(j*8)>=P)fail();
  return Buffer.from(response);
}
export function decodeBatchResponse(response,count){
  // Exposed for public parser controls, not a source of branded receipt contexts.
  if(!Number.isInteger(count)||count<1||count>BATCH_LIMIT||!Buffer.isBuffer(response)||response.length!==2+322*count||response.readUInt16LE(0)!==count)fail();
  const result=[];
  for(let i=0;i<count;i++){
    const at=2+322*i;if(response.readUInt16LE(at)!==i)fail();
    const record=response.subarray(at+2,at+322);
    result.push(decodeFieldResponse(record,40));
  }
  return result;
}
export function fixedHashCore(expectedSha256){
  if(typeof expectedSha256!=='string'||!(/^[a-f0-9]{64}$/).test(expectedSha256))fail();
  function call(op,chain,payload,expected){
    input(Buffer.isBuffer(chain)&&chain.length===32&&Buffer.isBuffer(payload)&&payload.length<=REQUEST_MAX-41);
    let fd,request,result;
    try {
      fd=fs.openSync(EXECUTABLE,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
      if(c.createHash('sha256').update(executableBytes(fd)).digest('hex')!==expectedSha256)fail();
      request=Buffer.concat([Buffer.from('CPCH0301'),Buffer.from([op]),chain,payload]);
      result=spawnSync('/proc/self/fd/3',[],{input:request,env:{LANG:'C',RUST_BACKTRACE:'0'},stdio:['pipe','pipe','pipe',fd],timeout:5000,maxBuffer:Math.max(expected+1,64),killSignal:'SIGKILL'});
      if(c.createHash('sha256').update(executableBytes(fd)).digest('hex')!==expectedSha256)fail();
      if(result.error||result.signal)fail();
      if(result.status===1&&result.stdout.length===0&&result.stderr.equals(Buffer.from('CP03_HASH_INPUT_REJECTED\n'))){if(op===4||op===5)throw new LocalReceiptMiss();fail();}
      if(result.status!==0||result.stderr.length||result.stdout.length!==expected)fail();
      return op===5?Buffer.from(result.stdout):decodeFieldResponse(result.stdout,op===4?40:8);
    }catch(error){if(error instanceof LocalReceiptMiss||error instanceof HashCoreFailure)throw error;fail();}
    finally{request?.fill(0);if(fd!==undefined){try{fs.closeSync(fd);}catch{fail();}}}
  }
  function frame(statement){input(Buffer.isBuffer(statement)&&[448,464,528].includes(statement.length));const n=Buffer.alloc(2);n.writeUInt16LE(statement.length);return Buffer.concat([n,statement]);}
  return Object.freeze({
    auth:(chain,key)=>call(1,chain,key,64),
    note:(chain,note)=>call(2,chain,note,64),
    nf:(chain,key,origin,cm)=>{const p=Buffer.concat([key,origin,cm]);try{return call(3,chain,p,64);}finally{p.fill(0);}},
    statement:(chain,statement)=>call(4,chain,frame(statement),320),
    statements:(chain,statements)=>{
      input(Array.isArray(statements)&&statements.length>=1&&statements.length<=BATCH_LIMIT);
      const count=Buffer.alloc(2);count.writeUInt16LE(statements.length);
      const response=call(5,chain,Buffer.concat([count,...Array.from(statements,frame)]),2+322*statements.length);
      return decodeBatchResponse(response,statements.length);
    },
    // Fixed batch opcode only, used to test Rust's grammar instead of only JS prechecks.
    rejectedBatchWireForControl:(chain,payload)=>call(5,chain,payload,RESPONSE_MAX),
  });
}
