"""Fresh public CLI verification/state regression; no wallet secrets or verdict cache."""
from pathlib import Path
import argparse,json,re,sqlite3,struct,time
import importlib.util,sys
_common_path=Path(__file__).resolve().parent/"common.py"
_spec=importlib.util.spec_from_file_location("common",_common_path)
_common=importlib.util.module_from_spec(_spec);sys.modules["common"]=_common;_spec.loader.exec_module(_common)
from common import ROOT,need,sha,save,run,controlled_env,package_sources,installation,hashes,read_json
TABLES={'meta':'singleton','sources':'id','nullifiers':'id','cores':'id','leaves':'idx','nodes':'level,idx','anchors':'height','blocks':'height','bodies':'height,ordinal','node_undo':'height,level,idx','body_cache':'singleton','archive_segments':'segment','archive_objects':'id','archive_pending':'height,ordinal'}

def snapshot(db):
 with sqlite3.connect(Path(db).as_uri()+'?mode=ro',uri=True,timeout=0)as c:
  c.execute('PRAGMA query_only=ON');c.execute('BEGIN')
  names={r[0]for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")};need(names==set(TABLES),'all14 tables exact')
  need(c.execute('PRAGMA integrity_check').fetchall()==[('ok',)]and c.execute('PRAGMA foreign_key_check').fetchall()==[],'SQLite invariants')
  out={'schema':c.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetchall(),'version':c.execute('PRAGMA user_version').fetchone()}
  for name,order in TABLES.items():out[name]=c.execute('SELECT * FROM '+name+' ORDER BY '+order).fetchall()
  return out

def offsets(raw,n):
 need(raw[:8]==b'CPBODY03'and raw[20:28]==b'CP-P2-03','body grammar')
 version,size,prooflen,auth,reserved=struct.unpack_from('<HHIHH',raw,8);need(version==3 and size==[448,464,528][n]and auth==(4627 if n==0 else 0)and reserved==0,'body shape')
 proof=20+size+4328+auth;need(proof+prooflen==len(raw)and raw[proof:proof+10]==b'CPFRI003\x03\0','proof grammar');need(struct.unpack_from('<I',raw,proof+206)[0]==10,'degree bits')
 return {'proof':proof,'auth':20+size+4328,'envelope':20+size,'fee':20+208+64*n,'credit':20+288+64*n,'debit':20+296+64*n}

def attempt_label(value):
 if re.fullmatch(r'[a-z][a-z0-9_-]{0,47}',value)is None:raise argparse.ArgumentTypeError('lowercase bounded attempt label')
 return value

def genesis_accounting(raw):
 need(raw[:12]==b'CPGEN003\x03\0\0\0'and len(raw)>=376,'genesis header')
 declared_g=struct.unpack_from('<Q',raw,44)[0];source_count=struct.unpack_from('<H',raw,52)[0]
 need(source_count==1 and len(raw)==376+2648*source_count,'fixed one-source genuine fixture')
 registered_credit=struct.unpack_from('<Q',raw,424)[0]
 need(declared_g==registered_credit and registered_credit>0,'declared source liability sum')
 return declared_g,source_count,registered_credit

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--label',type=attempt_label,default='replay');label=parser.parse_args().label
 package_sources();installed=installation();build=read_json(ROOT/'build-result.json');need(build['format']=='CP03-AUDIT-BUILD01'and build['actual_exit']==0,'actual build required');need(build['installation_sha256']==sha(ROOT/'installation.json'),'build installation identity')
 binary=ROOT/build['binary'];need(binary==ROOT/'target/release/ledger-cp03'and sha(binary)==build['binary_sha256'],'new ELF');work=ROOT/(label+'-work');log=ROOT/'results'/label;result_path=ROOT/(label+'-result.json');failure_path=ROOT/(label+'-failure.json');need(not any(x.exists()for x in (work,log,result_path,failure_path)),'immutable replay attempt');work.mkdir();log.mkdir();cfg=read_json(ROOT/'public/expected.json');public=ROOT/'public';chain=cfg['chain'];blocks=[(public/x['header'],public/x['body'])for x in cfg['blocks']];genesis=public/cfg['genesis'];declared_g,source_count,registered_credit=genesis_accounting(genesis.read_bytes());checks=[];calls=[];stage='start';started=time.monotonic()
 def budget(cap):
  remaining=600-(time.monotonic()-started);need(remaining>=1,'whole public replay budget');return min(cap,int(remaining))
 def command(args,error=None):
  need(sha(binary)==build['binary_sha256'],'ELF changed');hashes(installed['runtime'])
  r,o,e=run([str(binary),*map(str,args)],cwd=ROOT,seconds=budget(120),record=log/f'{len(calls):03d}');calls.append(r)
  if error is not None:need(r['process_exit']==1 and o==b''and e==('CP03_LEDGER_ERROR '+error+'\n').encode(),'exact rejection '+error);return None
  need(r['process_exit']==0 and not e,'genuine CLI success');v=json.loads(o);need(isinstance(v,dict),'public CLI object');return v
 def init(name,count=0):
  db=work/(name+'.db');initial=command(['init',db,chain,genesis]);need(initial['height']=='0'and initial['leaf_count']=='0'and initial['fee_escrow']=='0'and initial['unconsumed_liabilities']==str(declared_g),'initial source liability G')
  for header,body in blocks[:count]:command(['replay',db,chain,header,body])
  return db
 def reject(db,bodies,error):
  before=snapshot(db);command(['admit',db,chain,*bodies],error);need(snapshot(db)==before,'all14 unchanged after '+error)
 def put(name,raw):
  p=work/(name+'.body');p.write_bytes(raw);return p
 def mutate(raw,i):
  b=bytearray(raw);b[i]^=1;return bytes(b)
 def word(raw,i,v):
  b=bytearray(raw);struct.pack_into('<Q',b,i,v);return bytes(b)
 try:
  stage='native-worker-controls';worker=ROOT/'source/runtime/cp03/provider/embedded/source-signature.mjs';need(sha(worker)=='560d795353d3a6282da3c71b0af3baf5df75ffb702e7c3793a3c944c7565de2f','worker source');script=worker.read_text()+'\nrunPublicWorker();\n';a=(public/'a.request').read_bytes();b=(public/'b.request').read_bytes();need(len(a)==len(b)==7541 and a[:8]==b[:8]==b'CPAUTH03','public requests')
  for name,data,code,out in [('valid-a',a,0,b'CPAUTH03 VALID\n'),('valid-b',b,0,b'CPAUTH03 VALID\n'),('invalid-signature',mutate(a,len(a)-1),1,b'CPAUTH03 INVALID\n'),('wrong-key',a[:8]+b[8:2600]+a[2600:],1,b'CPAUTH03 INVALID\n')]:
   r,o,e=run([installed['node'],'--disable-sigusr1','--input-type=module','--eval',script],cwd=ROOT,data=data,seconds=budget(15),record=log/('native-'+name));need(r['process_exit']==code and o==out and not e,'native '+name)
  checks.append('fresh-native-valid-invalid-wrong-key')
  stage='four-block-replay';db=init('canonical');prefix3=None
  raw=[body.read_bytes()for _,body in blocks];shapes=[offsets(v,n)for v,n in zip(raw,[0,2,1,1])];fees=[struct.unpack_from('<Q',v,o['fee'])[0]for v,o in zip(raw,shapes)];credit=struct.unpack_from('<Q',raw[0],shapes[0]['credit'])[0]
  need(credit==registered_credit and all(struct.unpack_from('<Q',v,o['credit'])[0]==0 for v,o in zip(raw[1:],shapes[1:])),'exact genuine source claim and ordinary zero credits');source_liabilities=declared_g-credit
  for index,(header,body)in enumerate(blocks):
   got=command(['replay',db,chain,header,body]);need(got['height']==str(index+1)and got['leaf_count']==str(2*(index+1))and got['fee_escrow']==str(sum(fees[:index+1]))and got['unconsumed_liabilities']==str(source_liabilities),'actual accounting')
   if index==2:prefix3=snapshot(db)
  endpoint=cfg['endpoint'];need(got['block_id']==endpoint['blockId']and got['genesis_id']==endpoint['genesisId']and got['height']==endpoint['height']and got['chain']==endpoint['chain'],'independent retained endpoint');final=snapshot(db);checks.append('genuine-credit-three-ordinary-accounting-endpoint')
  stage='scan-rollback';scan=work/'history.scan';command(['scan',db,chain,scan]);checked=work/'checked.scan';command(['check-scan',chain,genesis,scan,endpoint['height'],endpoint['blockId'],checked]);need(scan.read_bytes()==checked.read_bytes(),'complete checked scan')
  wrong=work/'wrong.scan';command(['check-scan',chain,genesis,scan,endpoint['height'],'00'*64,wrong],'Codec');need(not wrong.exists(),'no partial published scan')
  command(['rollback',db,chain,endpoint['blockId']]);need(snapshot(db)==prefix3,'same-target rollback all14');command(['replay',db,chain,*blocks[3]]);need(snapshot(db)==final,'same-target reinclusion all14');reject(db,[blocks[3][1]],'Replay');checks.append('scan-endpoint-rollback-reinclusion-core-replay')
  for kind,index,alternate,error in [('source',0,public/cfg['source_alternate'],'Source'),('nf',1,public/cfg['nf_alternate'],'Replay')]:
   stage=kind+'-genuine-conflict';first=init(kind+'-first',index);other=init(kind+'-alt',index);command(['admit',first,chain,blocks[index][1]]);command(['admit',other,chain,alternate]);one,two=snapshot(first),snapshot(other);need(one['cores']!=two['cores'],'distinct genuine CORE');need(one['sources']==two['sources']if kind=='source'else one['nullifiers']==two['nullifiers'],'actual conflicting identity');reject(first,[alternate],error);late=init(kind+'-late',index);reject(late,[blocks[index][1],alternate],error);checks.append(kind+'-solo-current-late-conflict')
  # No diagnostic verdict shortcut: CLI invokes current real verifier/source provider.
  cases=[('opaque-proof',mutate(raw[1],shapes[1]['proof']+210),'Proof',1,blocks[1][1]),('source-signature',mutate(raw[0],shapes[0]['auth']),'Source',0,blocks[0][1]),('receipt',mutate(raw[1],shapes[1]['envelope']+2163),'Receipt',1,blocks[1][1]),('fee',word(raw[1],shapes[1]['fee'],0),'Fee',1,blocks[1][1]),('debit',word(raw[1],shapes[1]['debit'],1),'Codec',1,blocks[1][1])]
  for name,data,error,count,positive in cases:
   stage=name;bad=put(name,data);test=init(name,count);reject(test,[bad],error);command(['admit',test,chain,positive]);checks.append(name+'-all14-and-genuine-followup')
  stage='wrong-registered-key';g=bytearray(genesis.read_bytes());g[432:3024]=b[8:2600];gp=work/'wrong-key.genesis';gp.write_bytes(g);test=work/'wrong-key.db';command(['init',test,chain,gp]);reject(test,[blocks[0][1]],'Source');checks.append('wrong-registered-key-original-proof')
  stage='late-invalid';alt=(public/cfg['nf_alternate']).read_bytes();ao=offsets(alt,2);bad=put('late-fee',word(alt,ao['fee'],0));late=init('late-invalid',1);reject(late,[blocks[1][1],bad],'Fee');command(['admit',late,chain,blocks[1][1]]);checks.append('late-valid-plus-invalid-all14')
  package_sources();hashes(installed['runtime']);need(sha(binary)==build['binary_sha256'],'ELF final');stage='complete'
  result={'format':'CP03-AUDIT-REPLAY01','process_exit':0,'label':label,'checks':checks,'actual_cli_calls':len(calls),'endpoint':endpoint,'fee_sum':sum(fees),'credit':credit,'declared_g':declared_g,'source_count':source_count,'unconsumed_source_liabilities':source_liabilities,'implied_private_supply':declared_g-source_liabilities-sum(fees),'supply_scope':'Public accounting identity only; not reconstruction of private witnesses' ,'binary_sha256':build['binary_sha256'],'installation_sha256':sha(ROOT/'installation.json'),'private_inputs':False,'new_proofs_created':False,'final_private_recovery_reproduced':False,'whole_protocol_security_or_resource_pass':False,'opaque_proof_scope':'same canonical frame/statement with one opaque-root byte; exact Ledger Proof rejection, not direct inner Crypto error instrumentation'}
  save(result_path,result);print(json.dumps(result,sort_keys=True))
 except BaseException as exc:
  save(failure_path,{'label':label,'format':'CP03-AUDIT-REPLAY-FAILURE01','stage':stage,'exception_type':type(exc).__name__,'completed_checks':checks,'actual_cli_calls':len(calls)});raise
if __name__=='__main__':main()
