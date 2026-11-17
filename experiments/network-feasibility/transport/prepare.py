"""Launcher-side public byte oracle and framing. Not part of role timings."""
import hashlib,json,shutil,struct
from pathlib import Path
MAX=268435456

def need(ok,s):
 if not ok:raise ValueError(s)
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb')as f:
  for b in iter(lambda:f.read(65536),b''):h.update(b)
 return h.hexdigest()
def h64(label,raw,suffix=b''):
 tag=b'PQPC/CP3/'+label
 return hashlib.sha3_512(struct.pack('<H',len(tag))+tag+struct.pack('<I',len(raw))+raw+suffix).digest()
def read_entry(base,row,cap):
 need(set(row)=={'path','sha256'},'entry schema');p=Path(row['path'])
 need(not p.is_absolute()and '..'not in p.parts,'entry relative path');p=base/p
 need(p.resolve(strict=True)==p and not p.is_symlink()and p.is_file()and p.stat().st_size<=cap,'entry kind/bound')
 need(sha(p)==row['sha256'],'public bytes identity');return p

def prepare(manifest,approved,directory):
 manifest=Path(manifest).resolve(strict=True);need(sha(manifest)==approved,'explicit workload approval');w=json.loads(manifest.read_text())
 need(set(w)=={'format','block_version','ordinary_count','chain','genesis','blocks','endpoint'},'workload schema')
 need(w['format']=='CP04-NETWORK-BLOCK-WORKLOAD01'and w['block_version']==4 and w['ordinary_count']in(2,96)and len(w['blocks'])==2,'workload shape')
 n=w['ordinary_count'];base=manifest.parent;directory=Path(directory);directory.mkdir()
 genesis=read_entry(base,w['genesis'],339320);shutil.copyfile(genesis,directory/'genesis.bin')
 objects={'genesis':{'path':str(directory/'genesis.bin'),'sha256':sha(directory/'genesis.bin'),'bytes':genesis.stat().st_size,'kind':1}}
 public={str(manifest):approved,str(genesis):w['genesis']['sha256']};ordinaryids=[]
 for i,row in enumerate(w['blocks']):
  need(set(row)=={'header','bodies'}and len(row['bodies'])==n,'block schema')
  hp=read_entry(base,row['header'],8408);header=hp.read_bytes();public[str(hp)]=row['header']['sha256']
  need(header[:12]==b'CPBLOCK4\x04\0\0\0'and len(header)==216+64*n and int.from_bytes(header[116:118],'little')==n,'header shape')
  bodies=[read_entry(base,b,2106575)for b in row['bodies']]
  for p,b in zip(bodies,row['bodies']):public[str(p)]=b['sha256']
  need(len({sha(p)for p in bodies})==n,'distinct full bodies')
  full=228+68*n+sum(p.stat().st_size for p in bodies)
  need(full<=MAX and int.from_bytes(header[208:216],'little')==full,'full encoded bound')
  for j,p in enumerate(bodies):
   b=p.read_bytes();stmt=int.from_bytes(b[10:12],'little');auth=int.from_bytes(b[16:18],'little');offset=20+stmt+4328+auth
   need(b[:10]==b'CPBODY03\x03\0'and b[30]==(0 if i==0 else 2),'body arity')
   need(len(b)-offset==int.from_bytes(b[12:16],'little'),'proof length')
   bodyid=h64(b'BODY',b[:offset],h64(b'PROOF',b[offset:]))
   need(bodyid==header[216+64*j:216+64*(j+1)],'canonical body hash correspondence')
   if i==1:ordinaryids.append(bodyid)
  def frame(name,h,last=None):
   out=directory/(name+'.frame')
   with out.open('xb')as f:
    f.write(b'CPNET004'+struct.pack('<I',len(h))+h)
    for j,p in enumerate(bodies):
     if last is not None and j==n-1:f.write(struct.pack('<I',len(last)));f.write(last)
     else:
      f.write(struct.pack('<I',p.stat().st_size))
      with p.open('rb')as b:shutil.copyfileobj(b,f,65536)
   need(out.stat().st_size==full,'actual frame size')
   objects[name]={'path':str(out),'sha256':sha(out),'bytes':full,'kind':2}
  frame('funding'if i==0 else'ordinary',header)
  if i==1:
   bad=bytearray(bodies[-1].read_bytes());off=20+int.from_bytes(bad[10:12],'little')+4328+int.from_bytes(bad[16:18],'little')
   need(bad[off:off+8]==b'CPFRI003','proof envelope offset')
   bad[off+206+4]^=1 # Opaque first trace commitment digest; no parser/statement/fee mutation.
   invalid=bytearray(header);invalid[216+64*(n-1):216+64*n]=h64(b'BODY',bad[:off],h64(b'PROOF',bad[off:]))
   frame('invalid_last',bytes(invalid),bytes(bad))
 need(len(set(ordinaryids))==n,'distinct ordinary public IDs')
 need(all(sha(p)==h for p,h in public.items()),'source oracle postcheck')
 return {'format':'CP04-TRANSPORT-PREPARED01','objects':objects,'chain':w['chain'],'endpoint':w['endpoint'],'ordinary_count':n,'source_pins':public,'scope':'launcher-side construction/oracle outside measured roles; no cryptographic acceptance'}
