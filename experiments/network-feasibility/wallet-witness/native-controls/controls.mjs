// PUBLIC synthetic helper controls. Never print private wire/state/token/path data.
import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
const source=process.argv[2],expected=process.argv[3];
let active='startup',checks=0;const held=[],replies=[];
function need(ok){if(!ok)throw new Error('PUBLIC_TREE_CONTROL_REJECTED');}
function keep(x){if(Buffer.isBuffer(x))held.push(x);return x;}
function dispose(result){result.state.fill(0);result.root.fill(0);for(const w of result.witnesses){w.token.fill(0);for(const s of w.siblings)s.fill(0);}}
function funded(n,token=null){const origin=Buffer.alloc(64),cm=Buffer.alloc(64);for(let i=0;i<8;i++){origin.writeBigUInt64LE(BigInt(n),i*8);cm.writeBigUInt64LE(BigInt(n+100),i*8);}return {origin:keep(origin),cm:keep(cm),token};}
function tok(n){return keep(Buffer.alloc(16,n));}
try{
 need(typeof source==='string'&&typeof expected==='string'&&/^[a-f0-9]{64}$/.test(expected));
 const module=await import(pathToFileURL(path.join(source,'experiments/compact-receiving-v1/cp03/hash-core.mjs')).href);
 const {fixedHashCore,decodeTreeResponse,TREE_STATE_MAX,TREE_REQUEST_MAX,TREE_RESPONSE_MAX,REQUEST_MAX,RESPONSE_MAX}=module;
 const {HashCoreFailure}=await import(pathToFileURL(path.join(source,'experiments/compact-receiving-v1/cp03/errors.mjs')).href);
 const core=fixedHashCore(expected),chain=keep(Buffer.alloc(32,7)),A=tok(2),B=tok(1),C=tok(3);
 function run(name,fn){active=name;fn();checks++;}
 function rejected(fn){let failed=false,value;try{value=fn();}catch(error){failed=error instanceof HashCoreFailure;}if(value?.state&&value?.witnesses)dispose(value);need(failed);}
 function advance(state,leaves=[],forget=[],k=2){const r=core.treeAdvance(chain,{state,maxOwned:k,forget,leaves});replies.push(r);return r;}
 const binary=path.join(source,'experiments/compact-receiving-v1/cp03/hash-core/target/release/cp03-hash-core');
 function pin(fd){const st=fs.fstatSync(fd);need(st.isFile()&&st.size>0&&st.size<=32*1024*1024);const h=crypto.createHash('sha256'),b=Buffer.alloc(65536);let at=0;while(at<st.size){const n=fs.readSync(fd,b,0,Math.min(b.length,st.size-at),at);need(n>0);h.update(b.subarray(0,n));at+=n;}b.fill(0);need(h.digest('hex')===expected);}
 function wire(state,k,forget,leaves){
  const b=Buffer.alloc(41+24+state.length+16*forget.length+152*leaves.length);b.write('CPCH0301',0,'ascii');b[8]=6;chain.copy(b,9);b.write('CPTRQ006',41,'ascii');b.writeUInt16LE(1,49);b.writeUInt16LE(k,51);b.writeUInt32LE(state.length,53);b.writeUInt16LE(forget.length,57);b.writeUInt16LE(leaves.length,59);let at=65;state.copy(b,at);at+=state.length;for(const t of forget){t.copy(b,at);at+=16;}for(const l of leaves){l.origin.copy(b,at);l.cm.copy(b,at+64);if(l.token!==null){b[at+128]=1;l.token.copy(b,at+136);}at+=152;}return keep(b);
 }
 function raw(request,valid){let fd,result;try{fd=fs.openSync(binary,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);pin(fd);result=spawnSync('/proc/self/fd/3',[],{input:request,env:{LANG:'C',RUST_BACKTRACE:'0'},stdio:['pipe','pipe','pipe',fd],timeout:5000,maxBuffer:TREE_RESPONSE_MAX+1,killSignal:'SIGKILL'});pin(fd);need(!result.error&&!result.signal);if(valid){need(result.status===0&&result.stderr.length===0);return keep(Buffer.from(result.stdout));}need(result.status===1&&result.stdout.length===0&&result.stderr.equals(Buffer.from('CP03_HASH_INPUT_REJECTED\n')));return null;}finally{request.fill(0);result?.stdout?.fill(0);result?.stderr?.fill(0);if(fd!==undefined)fs.closeSync(fd);}}
 let genesis,first,unchanged,second,forgotten;
 run('fixed-caps-and-genesis',()=>{need(TREE_STATE_MAX===173248&&TREE_REQUEST_MAX===213249&&TREE_RESPONSE_MAX===338716&&REQUEST_MAX===135723&&RESPONSE_MAX===82434);genesis=advance(null);need(genesis.count===0n&&genesis.witnesses.length===0&&genesis.state.length===64);});
 run('first-owned-leaf',()=>{first=advance(genesis.state,[funded(1,A)]);need(first.count===1n&&first.witnesses.length===1&&first.witnesses[0].index===0n&&first.witnesses[0].token.equals(A)&&first.witnesses[0].siblings.length===40);});
 run('padding-is-not-state',()=>{unchanged=advance(first.state);need(unchanged.state.equals(first.state)&&unchanged.root.equals(first.root));const maskAt=64+80+88;need(first.state.readBigUInt64LE(maskAt)===0n);});
 run('new-real-right-sibling',()=>{second=advance(first.state,[funded(2,B)]);need(second.count===2n&&second.witnesses.length===2&&second.witnesses[0].index===0n&&second.witnesses[1].index===1n&&second.witnesses[0].token.equals(A)&&second.witnesses[1].token.equals(B));need(!second.witnesses[0].siblings[0].equals(first.witnesses[0].siblings[0])&&second.state.readBigUInt64LE(64+80+88)===1n);});
 run('forget-preserves-root-and-count',()=>{forgotten=advance(second.state,[],[A]);need(forgotten.count===2n&&forgotten.root.equals(second.root)&&forgotten.witnesses.length===1&&forgotten.witnesses[0].index===1n&&forgotten.witnesses[0].token.equals(B));});
 run('forget-new-discovery',()=>{const r=advance(forgotten.state,[funded(3,C)],[B]);need(r.count===3n&&r.witnesses.length===1&&r.witnesses[0].index===2n&&r.witnesses[0].token.equals(C));});
 run('unknown-and-duplicate-forget',()=>{rejected(()=>advance(first.state,[],[B]));rejected(()=>advance(first.state,[],[A,A]));});
 run('same-call-alias-and-cap',()=>{rejected(()=>advance(first.state,[funded(2,A)],[A]));rejected(()=>advance(second.state,[funded(3,C)],[],2));});
 run('state-chain-K-field-geometry',()=>{for(const offset of[0,8,10,12,44,48,49,56,64,72,73,160,168,232]){const bad=keep(Buffer.from(first.state));bad[offset]^=1;rejected(()=>advance(bad));bad.fill(0);}const noncanonical=keep(Buffer.from(first.state));noncanonical.writeBigUInt64LE(18446744069414584321n,80);rejected(()=>advance(noncanonical));noncanonical.fill(0);});
 run('native-full-input-rejection',()=>{const valid=wire(Buffer.alloc(0),2,[],[funded(1,A)]);const trailing=keep(Buffer.concat([valid,Buffer.from([0])]));raw(trailing,false);valid.fill(0);const flag=wire(Buffer.alloc(0),2,[],[funded(1,null)]);flag[65+128]=2;raw(flag,false);const field=wire(Buffer.alloc(0),2,[],[funded(1,null)]);field.writeBigUInt64LE(18446744069414584321n,65);raw(field,false);const alias=wire(first.state,2,[A],[funded(2,A)]);raw(alias,false);});
 run('production-response-parser',()=>{const response=raw(wire(Buffer.alloc(0),2,[],[funded(1,A)]),true);const parsed=decodeTreeResponse(response,chain,2,1n);need(parsed.state.equals(first.state)&&parsed.root.equals(first.root));dispose(parsed);for(const offset of[0,8,10,12,84,88,90,92+12,response.length-8]){const bad=keep(Buffer.from(response));bad[offset]^=1;if(offset===response.length-8)bad.writeBigUInt64LE(18446744069414584321n,offset);rejected(()=>decodeTreeResponse(bad,chain,2,1n));bad.fill(0);}const extra=keep(Buffer.concat([response,Buffer.from([0])]));rejected(()=>decodeTreeResponse(extra,chain,2,1n));extra.fill(0);const short=keep(Buffer.from(response.subarray(0,response.length-1)));rejected(()=>decodeTreeResponse(short,chain,2,1n));short.fill(0);response.fill(0);});
 run('max-block-and-owned-bound',()=>{const leaves=Array.from({length:256},(_,i)=>funded(i+10,i<64?tok(i):null));const r=advance(null,leaves,[],64);need(r.count===256n&&r.witnesses.length===64&&r.state.length<=TREE_STATE_MAX);rejected(()=>advance(null,leaves.concat([funded(999)]),[],64));});
 run('legacy-auth-note-nf',()=>{const key=keep(Buffer.alloc(40)),note=keep(Buffer.alloc(160)),origin=keep(Buffer.alloc(64)),cm=keep(Buffer.alloc(64));note.writeBigUInt64LE(1n,8);for(const b of[core.auth(chain,key),core.note(chain,note),core.nf(chain,key,origin,cm)]){need(b.length===64);for(let i=0;i<8;i++)need(b.readBigUInt64LE(i*8)<18446744069414584321n);b.fill(0);}});
 for(const reply of replies)dispose(reply);for(const b of held)b.fill(0);
 console.log(JSON.stringify({format:'CP03-NATIVE-TREE-PUBLIC-CONTROLS01',passed:true,checks,scope:'Fixed helper/public structural controls only; not private-wallet integration or PQ assurance'}));
}catch{
 for(const reply of replies)dispose(reply);for(const b of held)b.fill(0);console.error('CP03_NATIVE_TREE_PUBLIC_CONTROLS_FAILED '+active);process.exitCode=1;
}
