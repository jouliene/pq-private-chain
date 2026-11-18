// Public finite fixture. Verification is one process per three bodies, with one installed matrix preparation.
import {DatabaseSync} from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';

function cpu() {
  // Linux clock ticks are obtained centrally with sysconf in the driver.
  const words=fs.readFileSync('/proc/self/stat','utf8').split(') ').at(-1).split(' ');
  const own=process.cpuUsage();
  return {self_us:own.user+own.system,child_ticks:Number(words[13])+Number(words[14])};
}
const difference=(a,b,tick)=>(b.self_us-a.self_us)/1e6+(b.child_ticks-a.child_ticks)/tick;
function ensure(ok){if(!ok)throw Error('atomic public admission');}
const meta=raw=>Buffer.from(raw);

export function durable({cfg,configPath,dir,genesis,makeLedger,fields,core,magic,expectedGenesis,sha}) {
  ensure(sha(genesis)===expectedGenesis);
  const ledger=makeLedger(genesis);
  const bodies=[1,2,3].map(i=>fs.readFileSync(path.join(cfg.output,'payment'+i+'.body')));
  const inputs=fs.mkdtempSync(path.join(dir,'inputs-'));
  const tick=cfg.clk_tck;
  const start=performance.now();
  for(let i=0;i<3;i++){
    const b=bodies[i];
    ensure(b.length>4876&&b.length<=4876+2097152&&b.subarray(0,8).equals(magic)&&b.readUInt32LE(12)===b.length-4876);
    fs.writeFileSync(path.join(inputs,i+'.statement'),b.subarray(20,548));
    fs.writeFileSync(path.join(inputs,i+'.proof'),b.subarray(4876));
  }
  const child=spawnSync(cfg.python,['-I','-B',cfg.batch,configPath,inputs],{
    input:Buffer.alloc(0),encoding:'utf8',timeout:65000,maxBuffer:65536, env:{PATH:'/usr/bin:/bin',LANG:'C'}});
  ensure(!child.error&&child.status===0&&child.stderr==='');
  const proofRun=JSON.parse(child.stdout);
  ensure(proofRun.backend.accepted===true && proofRun.backend.records.length===3);
  const dbPath=path.join(dir,'node.sqlite');
  const db=new DatabaseSync(dbPath);
  db.exec('PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; CREATE TABLE head (id INTEGER PRIMARY KEY, root BLOB, n INTEGER, fees INTEGER, frontier BLOB); CREATE TABLE spent (nf BLOB PRIMARY KEY) WITHOUT ROWID; CREATE TABLE funded (pos INTEGER PRIMARY KEY, origin BLOB, cm BLOB); CREATE TABLE bodies (height INTEGER PRIMARY KEY, body BLOB NOT NULL)');
  db.exec('BEGIN IMMEDIATE');
  db.prepare('INSERT INTO head VALUES (0,?,?,0,?)').run(ledger.root,2,ledger.treeState);
  const putLeaf=db.prepare('INSERT INTO funded VALUES (?,?,?)');
  for(const [i,v] of ledger.leaves.entries())putLeaf.run(i,v.origin,v.cm);
  db.exec('COMMIT');
  const pre=cpu(),ledgerStart=performance.now();
  try {
    // All three immutable submitted pairs have verified. Every dependent state transition is checked in order.
    for (const [i,b] of bodies.entries()) {
      ensure(proofRun.backend.records[i].proof_bytes===b.length-4876);
      db.exec('BEGIN IMMEDIATE');
      try {
        const head=db.prepare('SELECT root,n,fees,frontier FROM head WHERE id=0').get();
        const x=fields({chain:ledger.chain,adapter:ledger.adapter,root:meta(head.root),
            leaves:{length:head.n},spent:{has:k=>!!db.prepare('SELECT 1 FROM spent WHERE nf=?').get(Buffer.from(k,'hex'))}},b);
        const next=core.treeAdvance(ledger.chain,{state:meta(head.frontier),maxOwned:2,forget:[],
          leaves:x.additions.map(v=>({...v,token:null}))});
        ensure(next.count===BigInt(head.n)+2n && BigInt(head.fees)+x.p.fee<=1840960000000000n);
        const addNF=db.prepare('INSERT INTO spent VALUES (?)');
        for(const nf of x.p.nullifiers)addNF.run(nf);
        x.additions.forEach((v,j)=>putLeaf.run(head.n+j,v.origin,v.cm));
        db.prepare('INSERT INTO bodies VALUES (?,?)').run(i+1,b);
        db.prepare('UPDATE head SET root=?,n=?,fees=?,frontier=? WHERE id=0').run(next.root,next.count,BigInt(head.fees)+x.p.fee,next.state);
        db.exec('COMMIT');
      }catch(e){db.exec('ROLLBACK');throw e;}
    }
    const post=cpu(),ledgerElapsed=(performance.now()-ledgerStart)/1000;
    const final=db.prepare('SELECT n,fees FROM head WHERE id=0').get();
    ensure(final.n===8 && final.fees===6336744 && db.prepare('SELECT count(*) AS n FROM spent').get().n===6);
    const finalBytes=db.prepare('SELECT sum(length(body)) AS b FROM bodies').get().b;
    ensure(finalBytes===bodies.reduce((n,b)=>n+b.length,0));
    const elapsed=(performance.now()-start)/1000;
    const ledgerCpu=difference(pre,post,tick);
    const cryptoCpu=proofRun.backend.records.reduce((s,r)=>s+r.post_preparation_thread_cpu_s,0);
    return {backend:proofRun, cpu_tick_hz:tick,ledger_cpu_s:ledgerCpu,
      ledger_elapsed_s:ledgerElapsed,crypto_process_cpu_s:proofRun.user_s+proofRun.system_s,
      post_preparation_proof_plus_ledger_group_cpu_s:cryptoCpu+ledgerCpu,
      whole_path_elapsed_s:elapsed,records:3,fees:final.fees,funded_count:final.n,
      sqlite_bytes:fs.statSync(dbPath).size,retained_body_bytes:finalBytes,
      ledger_waited_ticks:{before:pre.child_ticks,after:post.child_ticks},
      ledger_self_cpu_us:post.self_us-pre.self_us, genesis_sha256:expectedGenesis};
  }finally{db.close();}
}
