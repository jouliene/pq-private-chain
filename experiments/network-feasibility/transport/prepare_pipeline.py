"""Fixed Gate2 public framing/oracles before the offered epoch; no private input."""
import json,struct,shutil
from pathlib import Path
from prepare import need,sha,h64,read_entry,MAX
from oracle import disk

def prepare(manifest,approved,directory,source_root):
 manifest=Path(manifest).resolve(strict=True);need(sha(manifest)==approved,'explicit pipeline workload approval');w=json.loads(manifest.read_text())
 need(set(w)=={'format','block_version','ordinary_count','batch_size','ordinary_batch_count','chain','genesis','blocks','endpoint'},'pipeline schema')
 n=w['batch_size'];batches=w['ordinary_batch_count'];need(w['format']=='CP04-NETWORK-PIPELINE-WORKLOAD01'and w['block_version']==4 and(n,batches)in[(96,8),(2,3)]and w['ordinary_count']==n*batches and len(w['blocks'])==1+batches,'fixed pipeline shape')
 base=manifest.parent;directory=Path(directory);directory.mkdir();public={str(manifest):approved};objects={};bodyids=set();previous=None
 genesis=read_entry(base,w['genesis'],339320);public[str(genesis)]=w['genesis']['sha256'];shutil.copyfile(genesis,directory/'genesis.bin')
 g=genesis.read_bytes();need(g[:12]==b'CPGEN004\x04\0\0\0'and g[12:44].hex()==w['chain'],'genesis profile/chain');previous=h64(b'GENESIS',g)
 objects['genesis']={'path':str(directory/'genesis.bin'),'sha256':sha(directory/'genesis.bin'),'bytes':len(g),'kind':1}
 for batch,row in enumerate(w['blocks']):
  need(set(row)=={'header','bodies'}and len(row['bodies'])==n,'pipeline block count')
  hp=read_entry(base,row['header'],8408);header=hp.read_bytes();public[str(hp)]=row['header']['sha256']
  need(header[:12]==b'CPBLOCK4\x04\0\0\0'and len(header)==216+64*n and header[12:44].hex()==w['chain']and header[44:108]==previous and int.from_bytes(header[108:116],'little')==batch+1 and int.from_bytes(header[116:118],'little')==n,'ordered pipeline header')
  bodies=[read_entry(base,entry,2106575)for entry in row['bodies']]
  for p,entry in zip(bodies,row['bodies']):public[str(p)]=entry['sha256']
  full=228+68*n+sum(p.stat().st_size for p in bodies);need(full<=MAX and int.from_bytes(header[208:216],'little')==full,'pipeline full size')
  for j,p in enumerate(bodies):
   raw=p.read_bytes();off=20+int.from_bytes(raw[10:12],'little')+4328+int.from_bytes(raw[16:18],'little');need(raw[:10]==b'CPBODY03\x03\0'and raw[30]==(0 if batch==0 else 2)and len(raw)-off==int.from_bytes(raw[12:16],'little'),'pipeline body shape')
   ident=h64(b'BODY',raw[:off],h64(b'PROOF',raw[off:]));need(ident==header[216+64*j:216+64*(j+1)]and ident not in bodyids,'distinct canonical pipeline body');bodyids.add(ident)
  name='funding'if batch==0 else'ordinary'+str(batch);out=directory/(name+'.frame')
  with out.open('xb')as f:
   f.write(b'CPNET004'+struct.pack('<I',len(header))+header)
   for p in bodies:
    f.write(struct.pack('<I',p.stat().st_size))
    with p.open('rb')as source:shutil.copyfileobj(source,f,65536)
  need(out.stat().st_size==full,'actual pipeline encoded size');previous=h64(b'BLOCK',header)
  objects[name]={'path':str(out),'sha256':sha(out),'bytes':full,'kind':2,'height':batch+1,'block_id':previous.hex()}
 endpoint=w['endpoint'];need(set(endpoint)=={'height','block_id','leaf_count','root_le','fee_escrow','unconsumed_liabilities'},'exact six-field pipeline endpoint')
 expected={'height':str(batches+1),'block_id':previous.hex(),'leaf_count':str(int.from_bytes(header[120:128],'little')),'root_le':header[128:192].hex(),'fee_escrow':str(int.from_bytes(header[192:200],'little')),'unconsumed_liabilities':str(int.from_bytes(header[200:208],'little'))};need(endpoint==expected,'final header/endpoint equality')
 costs_path=base/'proof-costs.json';need(costs_path.is_file()and costs_path.stat().st_size<=8*1024**2,'public proof costs');public[str(costs_path)]=sha(costs_path);costs=json.loads(costs_path.read_text());need(costs['format']=='CP04-PRODUCER-PROOF-COSTS02'and len(costs['rows'])==n*(batches+1),'every proof cost row')
 proof_public=Path(source_root)/'experiments/compact-all-payments-v3/public';evidence=Path(source_root)/'experiments/compact-all-payments-v3/evidence';parents=[];known=[];labels=set();evidence_files=[];external_stats={}
 for cost in costs['rows']:
  rel=Path(cost['parent_receipt']);need(not rel.is_absolute()and '..'not in rel.parts,'public parent receipt path');receipt=Path(source_root)/rel
  need(receipt.parent==evidence and receipt.resolve(strict=True)==receipt and receipt.is_file()and not receipt.is_symlink()and len(cost['parent_receipt_sha256'])==64,'public parent receipt pin');label=receipt.stem;need(label not in labels,'unique proof labels');labels.add(label);d=proof_public/label
  need(d.is_dir()and not d.is_symlink()and sorted(p.name for p in d.iterdir())==['manifest.json','proof.bin','statement.bin'],'exact public proof copies')
  parents.append(d);known.append(d/'proof.bin')
  claim=evidence/(label+'.claim');need(claim.is_file()and not claim.is_symlink(),'parent claim exists');evidence_files.extend([receipt,claim])
  for p in list(d.iterdir())+[receipt,claim]:
   need(p.is_file()and not p.is_symlink(),'public/provenance file kind');st=p.stat();external_stats[str(p)]={'size':st.st_size,'blocks':st.st_blocks,'mtime_ns':st.st_mtime_ns,'inode':st.st_ino}
 external_source=disk(base);parent_copies={'logical_bytes':0,'allocated_bytes':0,'files':0}
 for d in parents:
  for k,v in disk(d).items():parent_copies[k]+=v
 provenance={'logical_bytes':sum(p.stat().st_size for p in evidence_files),'allocated_bytes':sum(p.stat().st_blocks*512 for p in evidence_files),'files':len(evidence_files)}
 need(base.name.endswith('.public'),'producer public directory');supervisor=base.parent/base.name.removesuffix('.public');need(supervisor.is_dir(),'producer supervisor receipts');supervisor_disk=disk(supervisor)
 for p in list(supervisor.rglob('*'))+list(base.rglob('*')):
  if p.is_file():need(not p.is_symlink(),'supervisor file kind');st=p.stat();external_stats[str(p)]={'size':st.st_size,'blocks':st.st_blocks,'mtime_ns':st.st_mtime_ns,'inode':st.st_ino}
 # Required body/manifest identities were checked once above; duplicate Parent
 # copies/provenance are stat-only experimental disk, not verifier authority.
 return {'format':'CP04-PIPELINE-PREPARED01','objects':objects,'chain':w['chain'],'endpoint':w['endpoint'],'batch_size':n,'ordinary_batch_count':batches,'ordinary_count':n*batches,'source_pins':public,'source_producer_public_disk':external_source,'parent_public_copies_disk':parent_copies,'parent_evidence_provenance_disk':provenance,'producer_supervisor_disk':supervisor_disk,'stat_only_external_files':external_stats,'charged_external_producer_disk':{k:external_source[k]+parent_copies[k]+provenance[k]+supervisor_disk[k]for k in external_source},'proof_public_root':str(proof_public),'known_actual_new_proof':str(known[0]),'scope':'public launcher construction and immutable-copy accounting before offer clock; not acceptance'}
