// Fixed trusted Rust program. Expected digest is operator configuration, never receipt input.
import * as fs from 'node:fs';
import * as c from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {LocalReceiptMiss,HashCoreFailure} from './errors.mjs';
const EXECUTABLE=fileURLToPath(new URL('./hash-core/target/release/cp03-hash-core',import.meta.url));
export const BATCH_LIMIT=256,REQUEST_MAX=135723,RESPONSE_MAX=82434;
export const TREE_STATE_MAX=173248,TREE_REQUEST_MAX=213249,TREE_RESPONSE_MAX=338716;
const TREE_DEPTH=40,TREE_CAPACITY=1n<<40n;
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
  function call(op,chain,payload,expected,decode=null){
    input(Buffer.isBuffer(chain)&&chain.length===32&&Buffer.isBuffer(payload)&&payload.length<=(op===6?TREE_REQUEST_MAX:REQUEST_MAX)-41);
    let fd,request,result;
    try {
      fd=fs.openSync(EXECUTABLE,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
      if(c.createHash('sha256').update(executableBytes(fd)).digest('hex')!==expectedSha256)fail();
      request=Buffer.concat([Buffer.from('CPCH0301'),Buffer.from([op]),chain,payload]);
      result=spawnSync('/proc/self/fd/3',[],{input:request,env:{LANG:'C',RUST_BACKTRACE:'0'},stdio:['pipe','pipe','pipe',fd],timeout:5000,maxBuffer:Math.max(expected+1,64),killSignal:'SIGKILL'});
      if(c.createHash('sha256').update(executableBytes(fd)).digest('hex')!==expectedSha256)fail();
      if(result.error||result.signal)fail();
      if(result.status===1&&result.stdout.length===0&&result.stderr.equals(Buffer.from('CP03_HASH_INPUT_REJECTED\n'))){if(op===4||op===5)throw new LocalReceiptMiss();fail();}
      if(result.status!==0||result.stderr.length||(op===6?result.stdout.length>expected:result.stdout.length!==expected))fail();
      if(op===6){if(typeof decode!=='function')fail();return decode(result.stdout);}
      return op===5?Buffer.from(result.stdout):decodeFieldResponse(result.stdout,op===4?40:8);
    }catch(error){if(error instanceof LocalReceiptMiss||error instanceof HashCoreFailure)throw error;fail();}
    finally{request?.fill(0);if(Buffer.isBuffer(result?.stdout))result.stdout.fill(0);if(Buffer.isBuffer(result?.stderr))result.stderr.fill(0);if(fd!==undefined){try{fs.closeSync(fd);}catch{fail();}}}
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
    treeAdvance:(chain,options)=>advanceTree(call,chain,options),
    // Fixed batch opcode only, used to test Rust's grammar instead of only JS prechecks.
    rejectedBatchWireForControl:(chain,payload)=>call(5,chain,payload,RESPONSE_MAX),
  });
}

// Tree messages are private local data. Canonical parsing does not authenticate
// a checkpoint or authorize arbitrary state import into a wallet capability.
function treeInput(ok){if(!ok)fail();}
function treeDigest(b){treeInput(Buffer.isBuffer(b)&&b.length===64);for(let i=0;i<8;i++)treeInput(b.readBigUInt64LE(i*8)<P);return b;}
function treeMask(index,count){let out=0n;for(let d=0n;d<40n;d++){const start=((index>>d)^1n)<<d;if(start+(1n<<d)<=count)out|=1n<<d;}return out;}
function treeState(bytes,chain,k){
  treeInput(Buffer.isBuffer(bytes)&&bytes.length>=64&&bytes.length<=TREE_STATE_MAX);
  let at=0;const take=n=>{treeInput(Number.isSafeInteger(n)&&n>=0&&at+n<=bytes.length);const b=bytes.subarray(at,at+n);at+=n;return b;};
  const u16=()=>take(2).readUInt16LE(),u64=()=>take(8).readBigUInt64LE();
  treeInput(take(8).equals(Buffer.from('CPTRST06'))&&u16()===1&&u16()===TREE_DEPTH&&take(32).equals(chain)&&u16()===k);
  const live=u16(),branches=take(1)[0];treeInput(take(7).every(x=>x===0));const count=u64();treeInput(live<=k&&branches<=40&&count<=TREE_CAPACITY);
  let position=0n,seen=0;
  for(let d=40;d>=0;d--)if(count&(1n<<BigInt(d))){const start=u64(),level=take(1)[0];treeInput(take(7).every(x=>x===0));treeDigest(take(64));treeInput(start===position&&level===d);position+=1n<<BigInt(d);seen++;}
  treeInput(seen===branches&&position===count);const targets=[];
  for(let i=0;i<live;i++){
    const token=take(16),index=u64();treeDigest(take(64));const mask=u64();
    treeInput(index<count&&(i===0||targets[i-1].index<index)&&!targets.some(x=>x.token.equals(token))&&mask===treeMask(index,count));
    for(let d=0;d<40;d++)if(mask&(1n<<BigInt(d)))treeDigest(take(64));targets.push({token,index});
  }
  treeInput(at===bytes.length);return {count,targets};
}
// Production parser boundary, also available to public parser controls. This
// returns no branded wallet authority and performs no independent chain proof.
export function decodeTreeResponse(response,chain,k,expectedCount,expectedTargets=null){
  const owned=[];const own=b=>{const copy=Buffer.from(b);owned.push(copy);return copy;};
  try{
    treeInput(Buffer.isBuffer(chain)&&chain.length===32&&Number.isInteger(k)&&k>=1&&k<=64&&typeof expectedCount==='bigint'&&expectedCount>=0n&&expectedCount<=TREE_CAPACITY);
    treeInput(Buffer.isBuffer(response)&&response.length>=92&&response.length<=TREE_RESPONSE_MAX&&response.subarray(0,8).equals(Buffer.from('CPTRP006'))&&response.readUInt16LE(8)===1&&response.readUInt16LE(10)===k);
    const count=response.readBigUInt64LE(12),root=treeDigest(response.subarray(20,84)),stateLength=response.readUInt32LE(84),n=response.readUInt16LE(88);
    treeInput(count===expectedCount&&n<=k&&response.readUInt16LE(90)===0&&stateLength>=64&&stateLength<=TREE_STATE_MAX&&response.length===92+stateLength+2584*n);
    const state=response.subarray(92,92+stateLength),parsed=treeState(state,chain,k);treeInput(parsed.count===count&&parsed.targets.length===n);
    if(expectedTargets!==null)treeInput(Array.isArray(expectedTargets)&&expectedTargets.length===n&&expectedTargets.every((x,i)=>x.index===parsed.targets[i].index&&x.token.equals(parsed.targets[i].token)));
    const witnesses=[];let at=92+stateLength;
    for(let i=0;i<n;i++){
      const token=response.subarray(at,at+16),index=response.readBigUInt64LE(at+16);treeInput(token.equals(parsed.targets[i].token)&&index===parsed.targets[i].index);at+=24;const siblings=[];
      for(let d=0;d<40;d++){siblings.push(treeDigest(response.subarray(at,at+64)));at+=64;}witnesses.push({token,index,siblings});
    }
    treeInput(at===response.length);
    const result=Object.freeze({state:own(state),count,root:own(root),witnesses:Object.freeze(witnesses.map(w=>Object.freeze({token:own(w.token),index:w.index,siblings:Object.freeze(w.siblings.map(own))})))});
    owned.length=0;return result;
  }catch{for(const b of owned)b.fill(0);fail();}
}
function advanceTree(call,chain,options){
  let state,payload;const forget=[],leaves=[];
  try{
    treeInput(Buffer.isBuffer(chain)&&chain.length===32&&options!==null&&typeof options==='object'&&!Array.isArray(options));
    const keys=Object.keys(options);treeInput(keys.length===4&&['state','maxOwned','forget','leaves'].every(x=>keys.includes(x)));
    const k=options.maxOwned;treeInput(Number.isInteger(k)&&k>=1&&k<=64&&(options.state===null||(Buffer.isBuffer(options.state)&&options.state.length>=64&&options.state.length<=TREE_STATE_MAX))&&Array.isArray(options.forget)&&options.forget.length<=64&&Array.isArray(options.leaves)&&options.leaves.length<=256);
    state=options.state===null?Buffer.alloc(0):Buffer.from(options.state);const prior=state.length?treeState(state,chain,k):{count:0n,targets:[]};treeInput(options.state===null||state.length>0);
    for(const token of options.forget){treeInput(Buffer.isBuffer(token)&&token.length===16);forget.push(Buffer.from(token));}
    forget.sort(Buffer.compare);for(let i=0;i<forget.length;i++)treeInput((i===0||!forget[i-1].equals(forget[i]))&&prior.targets.some(x=>x.token.equals(forget[i])));
    for(const input of options.leaves){
      treeInput(input!==null&&typeof input==='object'&&!Array.isArray(input)&&Object.keys(input).length===3&&['origin','cm','token'].every(x=>Object.hasOwn(input,x)));
      treeDigest(input.origin);treeDigest(input.cm);treeInput(input.token===null||(Buffer.isBuffer(input.token)&&input.token.length===16));
      if(input.token!==null)treeInput(!prior.targets.some(x=>x.token.equals(input.token))&&!leaves.some(x=>x.token?.equals(input.token)));
      const token=input.token===null?null:Buffer.from(input.token);
      leaves.push({origin:Buffer.from(input.origin),cm:Buffer.from(input.cm),token});
    }
    const count=prior.count+BigInt(leaves.length);treeInput(count<=TREE_CAPACITY);const expected=prior.targets.filter(x=>!forget.some(t=>t.equals(x.token))).map(x=>({token:x.token,index:x.index}));
    for(let i=0;i<leaves.length;i++)if(leaves[i].token!==null)expected.push({token:leaves[i].token,index:prior.count+BigInt(i)});treeInput(expected.length<=k);
    payload=Buffer.alloc(24+state.length+forget.length*16+leaves.length*152);treeInput(payload.length+41<=TREE_REQUEST_MAX);payload.write('CPTRQ006',0,'ascii');payload.writeUInt16LE(1,8);payload.writeUInt16LE(k,10);payload.writeUInt32LE(state.length,12);payload.writeUInt16LE(forget.length,16);payload.writeUInt16LE(leaves.length,18);let at=24;state.copy(payload,at);at+=state.length;
    for(const token of forget){token.copy(payload,at);at+=16;}
    for(const leaf of leaves){leaf.origin.copy(payload,at);leaf.cm.copy(payload,at+64);if(leaf.token!==null){payload[at+128]=1;leaf.token.copy(payload,at+136);}at+=152;}
    treeInput(at===payload.length);return call(6,chain,payload,TREE_RESPONSE_MAX,response=>decodeTreeResponse(response,chain,k,count,expected));
  }catch{fail();}
  finally{state?.fill(0);payload?.fill(0);for(const token of forget)token.fill(0);for(const leaf of leaves){leaf.origin.fill(0);leaf.cm.fill(0);leaf.token?.fill(0);}}
}
