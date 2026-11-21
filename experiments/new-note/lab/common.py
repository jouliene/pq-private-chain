"""N7P1 research codec, public arithmetic API and opaque receipt roles."""
from hashlib import sha3_384, shake_256
from pathlib import Path
import json
import os
import struct
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
P = 2**64-2**32+1
DEPTH = 40
MAX_COUNT = 1 << DEPTH
CT = 1744
SIG = 17088
MAX_PACKET = 272*1024  # isolated cap on each complete physical frame, including its signature
ZERO = bytes(32)
SUITE = b'N7P1'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(label, *args):
    return sha3_384(label.encode('ascii')+b'\0'+b''.join(args)).digest()


def data(path):
    return json.loads(Path(path).read_bytes())


def store(path, value):
    Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')


def words(raw):
    need(len(raw)==56,'digest width')
    v=list(struct.unpack('<7Q',raw))
    need(all(x<P for x in v),'noncanonical digest')
    return v


def pack(v):
    need(len(v)==7 and all(type(x) is int and 0<=x<P for x in v),'digest words')
    return struct.pack('<7Q',*v)


def u32s(raw):
    return list(struct.unpack('<'+'I'*(len(raw)//4),raw))


def scalars(label, net, seed):
    # Uniform 63-bit words. The 384-bit backup bounds total spend-secret entropy.
    r=shake_256(label+b'\0'+net+seed).digest(56)
    return [x & (2**63-1) for (x,) in struct.iter_unpack('<Q',r)]


def funding_policy(nonce,grants):
    payload=b''.join(pack(g['owner'])+struct.pack('<8IQQ',*g['asset'],g['native'],g['token']) for g in grants)
    return digest('N7G1/network',nonce,struct.pack('<Q',len(grants)),payload)


def genesis_id(genesis):
    return digest('N7G1/genesis',json.dumps(genesis,sort_keys=True,separators=(',',':')).encode())


def credit_salt(net,index):
    return scalars(b'N7G1/public-credit-salt',net,struct.pack('<Q',index))


class Arithmetic:
    def __init__(self):
        self.proc=subprocess.Popen(['/circuit','eval-stream'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    def __enter__(self):
        return self
    def __exit__(self,*_):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)
        self.proc.stdout.close()
    def call(self,op,**kw):
        self.proc.stdin.write((json.dumps(dict(op=op,**kw))+'\n').encode())
        self.proc.stdin.flush()
        reply=self.proc.stdout.readline(4096)
        need(reply,'arithmetic worker failed')
        out=json.loads(reply)
        pack(out)
        return out


def crypto(op, raw):
    return subprocess.run(['/node',str(HERE/'crypto.mjs'),op],input=raw,stdout=subprocess.PIPE,check=True).stdout


def note_bytes(n):
    return (pack(n['owner'])+struct.pack('<8I',*n['asset'])+pack(n['salt'])+
            struct.pack('<QQ',n['native'],n['token']))


def decode_note(b):
    need(len(b)==160,'note plaintext width')
    return dict(owner=words(b[:56]),asset=u32s(b[56:88]),salt=words(b[88:144]),
                native=int.from_bytes(b[144:152],'little'),token=int.from_bytes(b[152:],'little'))


def private_note(owner,asset,n,t):
    return dict(owner=owner,asset=u32s(asset if t else ZERO),native=n,token=t,
                salt=scalars(b'N7P1/salt',b'',os.urandom(48)))


def context_header(net,kind,root,count,fee,nfs,cms,cts,expiry=0,payer=0,terms=b'',auth=b''):
    need(kind in (0,1,2) and len(net)==48 and len(nfs)==len(cms)==len(cts)==2 and all(len(c)==CT for c in cts),'header shape')
    need(2<=count<=MAX_COUNT and fee==(3 if kind==0 or kind==payer+1 else 0),'fee or count')
    ext=b''
    if kind:
        need(0<expiry<2**32 and payer in (0,1) and len(terms)==48 and len(auth)==32,'authorization header')
        ext=struct.pack('<IB',expiry,payer)+terms+auth
    return (SUITE+bytes([kind])+net+pack(root)+struct.pack('<QQ',count,fee)+b''.join(map(pack,nfs+cms))+
            b''.join(cts)+ext)


def parse(raw,genesis=None):
    need(3841<len(raw)<=MAX_PACKET and raw[:4]==SUITE,'new profile or packet size')
    k=raw[4]; need(k<=2,'kind')
    count,fee=struct.unpack_from('<QQ',raw,109)
    nfs=[words(raw[i:i+56]) for i in (125,181)]
    cms=[words(raw[i:i+56]) for i in (237,293)]
    cts=[raw[349:349+CT],raw[349+CT:349+2*CT]]
    end=349+2*CT
    expiry=payer=0
    terms=auth=b''
    if k:
        expiry,payer=struct.unpack_from('<IB',raw,end)
        terms,auth=raw[end+5:end+53],raw[end+53:end+85]
    head=context_header(raw[5:53],k,words(raw[53:109]),count,fee,nfs,cms,cts,expiry,payer,terms,auth)
    need(raw.startswith(head) and len(raw)>=len(head)+4,'canonical packet header')
    n,=struct.unpack_from('<I',raw,len(head))
    need(n>0 and len(raw)==len(head)+4+n,'proof length')
    s=dict(root=words(raw[53:109]),count=count,fee=fee,context=u32s(digest('N7P1/proof-context',genesis,head)) if genesis is not None else None,nullifiers=nfs,outputs=cms)
    return dict(header=head,statement=s,proof=raw[len(head)+4:],net=raw[5:53],kind=k,cts=cts,
                terms=terms,auth=auth,expiry=expiry,payer=payer)


def role(mode,statement,proof=b'',witness=None):
    with tempfile.TemporaryDirectory() as folder:
        d=Path(folder); store(d/'statement',statement)
        if mode=='verify': (d/'proof').write_bytes(proof)
        args=['/usr/bin/time','-o',str(d/'resources'),'-f','%e %U %S %M','/circuit',mode,str(d/'statement'),str(d/'proof')]
        start=time.perf_counter()
        result=subprocess.run(args,input=json.dumps(witness).encode() if witness is not None else b'',stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        need(result.returncode==0,mode+' rejected')
        wall,user,system,rss=(d/'resources').read_text().split()
        metric=dict(wall_s=time.perf_counter()-start,user_s=float(user),system_s=float(system),max_rss_KiB=int(rss))
        native=json.loads(result.stdout)
        for key in ('preparation_ms','operation_ms','degree_bits','gates_before_blinding','proof_bytes','expanded_proof_bytes'):
            metric[key]=native[key]
        return ((d/'proof').read_bytes() if mode=='prove' else None),metric


def split_bundle(raw,genesis=None):
    need(raw[:4]==b'N7S1' and len(raw)<=2*MAX_PACKET+12,'swap bundle')
    frames=[]; pos=4
    for side in (1,2):
        need(pos+4<=len(raw),'missing side')
        n,=struct.unpack_from('<I',raw,pos); pos+=4
        need(SIG<n<=MAX_PACKET and pos+n<=len(raw),'signed leg bound')
        core,sig=raw[pos:pos+n-SIG],raw[pos+n-SIG:pos+n];pos+=n
        leg=parse(core,genesis);need(leg['kind']==side,'swap order')
        frames.append((core,leg,sig))
    need(pos==len(raw),'trailing bundle bytes')
    return frames


def swap_digest(a,b):
    return digest('N7S1/joint-approval',digest('N7S1/leg',a),digest('N7S1/leg',b))
