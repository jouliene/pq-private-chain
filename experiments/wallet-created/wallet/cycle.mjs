// Synthetic two-note endowment. Only the wallet holds opening data. Public replay receives genesis and complete packets.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';

const [configPath, mode, approvedGenesis] = process.argv.slice(2);
const cfg=JSON.parse(fs.readFileSync(configPath));
const out=cfg.output;
const moduleAt=rel=>import(pathToFileURL(path.join(cfg.source_root,rel)));
const [keys,pay,codec,receiving,hash]=await Promise.all([
  'wallet/cp03/keys.mjs','wallet/cp03/payments.mjs','wallet/cp03/codec.mjs',
  'experiments/compact-receiving-v1/cp03/receipt.mjs','experiments/compact-receiving-v1/cp03/hash-core.mjs'].map(moduleAt));
const core=hash.fixedHashCore(cfg.helper_sha256);
const magic=Buffer.from(cfg.backend==='reference'?'RFPAY001':'WHPAY001');
const genesisFile=path.join(out,'genesis.bin');
function need(x) {if (!x) throw Error('wallet cycle invariant');}
function save(name,buf){fs.writeFileSync(path.join(out,name),buf,{flag:'wx',mode:0o600});}
const digest=raw=>crypto.createHash('sha256').update(raw).digest('hex');
const produced=[], admissions=[];
let stage='initialization';
function bridge(op,statement,proof,packet) {
  stage=op;
  const res=spawnSync(cfg.python,['-I','-B',cfg.bridge,configPath,op,statement,proof],{
    input:packet||Buffer.alloc(0),timeout:920000,killSignal:'SIGKILL',maxBuffer:131072,env:{PATH:'/usr/bin:/bin',LANG:'C'}});
  if(res.error || res.signal) throw Error('backend lifecycle');
  if(res.status===1 && res.stdout.length===0 && res.stderr.toString()==='payment backend rejected\n') return null;
  need(res.status===0 && res.stderr.length===0 && res.stdout.length<=65536);
  const summary=JSON.parse(res.stdout);
  need(summary.accepted===true && summary.mode===op && Number.isSafeInteger(summary.proof_bytes));
  return summary;
}
function tree(chain,leaves,select=new Set()) {
  const input=leaves.map((leaf,i)=>({...leaf,token:select.has(i)?Buffer.alloc(16,i+1):null}));
  return core.treeAdvance(chain,{state:null,maxOwned:2,forget:[],leaves:input});
}
function makeLedger(bytes) {
  need(bytes.length===8+32+4*64 && bytes.subarray(0,8).equals(Buffer.from('WGEN0001')));
  const chain=bytes.subarray(8,40);
  const leaves=[0,1].map(i=>({origin:bytes.subarray(40+128*i,104+128*i),cm:bytes.subarray(104+128*i,168+128*i)}));
  const initial=tree(chain,leaves);
  return {chain,adapter:receiving.createReceiptAdapter(chain,cfg.helper_sha256), leaves,
    spent:new Set(), fees:0n, root:initial.root, treeState:initial.state};
}
function fields(ledger,body) {
  need(body.length>=4877 && body.length<=4876+2097152 && body.subarray(0,8).equals(magic)
    && body.readUInt16LE(8)===1 && body.readUInt16LE(10)===528 && body.readUInt32LE(12)===body.length-4876
    && body.readUInt32LE(16)===0);
  const statement=body.subarray(20,548), p=codec.parseStatement(statement);
  need(p.arity===2 && p.chain.equals(ledger.chain) && p.credit===0n && p.debit===0n &&
    p.fee===codec.FEES[2] && p.count===BigInt(ledger.leaves.length) && p.root.equals(ledger.root));
  need(!p.nullifiers.some(n=>ledger.spent.has(n.toString('hex'))));
  const contexts=ledger.adapter.contextsBatch([statement])[0];
  const envelopes=[body.subarray(548,2712),body.subarray(2712,4876)];
  const additions=contexts.map((c,i)=>{
    const info=ledger.adapter.contextInfo(c);
    need(info.cm.equals(p.commitments[i]) && ledger.adapter.digest(c,envelopes[i]).equals(p.receipts[i]));
    return {origin:info.origin,cm:info.cm};
  });
  return {statement,p,contexts,envelopes,additions,proof:body.subarray(4876)};
}
function checkpoint(l){return JSON.stringify([l.root.toString('hex'),l.leaves.length,[...l.spent].sort(),String(l.fees)]);}
function admit(l,body) {
  const before=performance.now();
  const x=fields(l,body);
  // These two detached public inputs are the entire per-call namespace of the verifier.
  const d=fs.mkdtempSync(path.join(out,'.verify-'));
  let m;
  try {
    const s=path.join(d,'statement'),p=path.join(d,'proof');
    fs.writeFileSync(s,x.statement);fs.writeFileSync(p,x.proof);
    m=bridge('verify',s,p);
  } finally {fs.rmSync(d,{recursive:true,force:true});}
  need(m!==null);
  const leaves=l.leaves.concat(x.additions), spent=new Set(l.spent);
  const next=core.treeAdvance(l.chain,{state:l.treeState,maxOwned:2,forget:[],
    leaves:x.additions.map(leaf=>({...leaf,token:null}))});
  for(const n of x.p.nullifiers) spent.add(n.toString('hex'));
  const fees=l.fees+x.p.fee;
  need(fees<=codec.MAX && next.count===BigInt(leaves.length));
  Object.assign(l,{leaves,root:next.root,treeState:next.state,spent,fees});
  return {...m,admission_elapsed_s:(performance.now()-before)/1000,body_bytes:body.length};
}
function issue(chain,wallet) {
  return keys.withWallet(wallet,v=>[0,1].map(i=> {
    const note=receiving.makeNote(50000000n,v.adapter.auth(v.spending));
    const origin=Buffer.alloc(64);origin.writeBigUInt64LE(BigInt(i+1));
    return {note,origin,cm:v.adapter.commitment(note)};
  }));
}
function spendInputs(ledger,owned) {
  const indices=owned.map(n=>ledger.leaves.findIndex(v=>v.origin.equals(n.origin)&&v.cm.equals(n.cm)));
  need(indices.length===2 && indices[0]>=0 && indices[1]>=0 && indices[0]!==indices[1]);
  const w=tree(ledger.chain,ledger.leaves,new Set(indices));
  need(w.root.equals(ledger.root));
  return owned.map((n,i)=>({note:n.note,origin:n.origin,index:BigInt(indices[i]),siblings:w.witnesses.find(x=>x.index===BigInt(indices[i])).siblings}));
}
function scan(wallet,ledger,body) {
  return keys.withWallet(wallet,v=>{
    const statement=body.subarray(20,548);
    const cs=v.adapter.contextsBatch([statement])[0],found=[];
    for(let i=0;i<2;i++){
      const info=v.adapter.contextInfo(cs[i]);
      const envelope=body.subarray(548+2164*i,548+2164*(i+1));
      for(const key of v.keys) {
        const opened=v.adapter.tryOpen(envelope,key.descriptor,key.key,v.spending,cs[i]);
        if(opened) {
          need(ledger.leaves.some(leaf=>leaf.origin.equals(info.origin)&&leaf.cm.equals(info.cm)));
          found.push({origin:info.origin,cm:info.cm,note:Buffer.from(opened.note)});receiving.wipeOpening(opened);
        }
      }
    }
    return found;
  });
}
function parsePacketForControls(raw,field,change) {const b=Buffer.from(raw);b[field]^=change;return b;}
function publicReplay(genesis) {
  need(digest(genesis)===approvedGenesis);
  const ledger=makeLedger(genesis), controls=[];
  for(let i=0;i<3;i++) {
    const b=fs.readFileSync(path.join(out,'payment'+(i+1)+'.body'));
    for(const [name,other] of [['wrong-statement',parsePacketForControls(b,20+48,1)],
      ['receipt',parsePacketForControls(b,548+2000,1)],['changed-proof',parsePacketForControls(b,4876+Math.floor((b.length-4876)/2),1)]]) {
      const before=checkpoint(ledger);let rejected=false;
      try{admit(ledger,other);}catch{rejected=true;}
      need(rejected && checkpoint(ledger)===before);controls.push(name);
    }
    admissions.push(admit(ledger,b));
    const before=checkpoint(ledger);let rejected=false;
    try{admit(ledger,b);}catch{rejected=true;}
    need(rejected && checkpoint(ledger)===before);controls.push('replay');
  }
  return {backend:cfg.backend, genesis_sha256:digest(genesis),admissions,controls,spent:ledger.spent.size,fees:String(ledger.fees),leaves:ledger.leaves.length};
}
async function generate(){
  const chain=crypto.randomBytes(32), wallets=[0,1,2].map(()=>keys.createWallet(chain,cfg.helper_sha256));
  let owned=issue(chain,wallets[0]);
  const genesis=Buffer.concat([Buffer.from('WGEN0001'),chain,...owned.flatMap(n=>[n.origin,n.cm])]);
  save('genesis.bin',genesis);
  const l=makeLedger(genesis);
  try {
    for(let i=0;i<3;i++){
      const sender=wallets[i],receiver=wallets[(i+1)%3],dest=keys.descriptor(receiver,0);
      const available=owned.reduce((a,n)=>a+n.note.readBigUInt64LE(8),0n)-codec.FEES[2];
      const a=BigInt(crypto.randomInt(1000000,10000000));
      const draft=pay.preparePayment(sender,cfg.helper_sha256,{anchor:{root:l.root,count:BigInt(l.leaves.length)},
        inputs:spendInputs(l,owned),outputs:[{descriptor:dest,amount:a},{descriptor:dest,amount:available-a}]});
      const stem='payment'+(i+1),s=path.join(out,stem+'.statement'),f=path.join(out,stem+'.proof');
      const pub=pay.publicPayment(draft);save(stem+'.statement',pub.statement);
      try {
        const proc=await pay.consumePrivatePacket(draft,privatePacket=>bridge('prove',s,f,privatePacket));
        need(proc!==null);
        const b=pay.completeBody(draft,Buffer.alloc(0),fs.readFileSync(f));
        magic.copy(b);b.writeUInt16LE(1,8);
        const result=admit(l,b);admissions.push(result); save(stem+'.body',b);
        for(const n of owned)n.note.fill(0);
        stage='receive';
        owned=scan(receiver,l,b);
        need(owned.length===2 && owned.reduce((a,n)=>a+n.note.readBigUInt64LE(8),0n)===available);
        const outsider=wallets[(i+2)%3];need(scan(outsider,l,b).length===0);
        produced.push({...proc,body_bytes:b.length,receipts_opened:owned.length,unrelated_receipts:0});
      }finally{pay.disposePayment(draft);}
    }
    return {backend:cfg.backend,genesis_sha256:digest(genesis),produced,admissions,spent:l.spent.size,fees:String(l.fees),leaves:l.leaves.length};
  }finally{for(const n of owned)n.note.fill(0);for(const w of wallets)keys.disposeWallet(w);}
}
try {
  const result=mode==='generate'?await generate():publicReplay(fs.readFileSync(genesisFile));
  console.log(JSON.stringify(result));
} catch {
  console.error('wallet cycle failed at '+stage);process.exitCode=1;
}
