"""Public TKN1 test chain. One authorized fixed issuance, one native-fee sink, no subsequent mint."""
import hashlib
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2]/"experiments/advancing-payments"))
from wire import CT, Role, ZERO, digest, need, pieces, sha, u32, u64

VK = "f4b865c6c2aaa9afdd6a7a7ecb94fe9b76ffdc75d25d5a570cf595d315576c2b"
BITS = 22
WINDOW = 8
NETWORK = hashlib.sha256(b"TKN1/network/v1\0"+bytes.fromhex(VK)+bytes([BITS,WINDOW])).digest()
ALLOC = ((100,70),(100,50),(100,70),(100,50))
GEN = b"TKN1GEN1"
BLOCK = b"TKN1BLK1"
PREFIX = 8+32+132+4
MAX_PACKET = 256*1024

def context(i):
    return hashlib.sha256(b"TKN1/endowment\0"+NETWORK+u32(i)).digest()

def header(parent,height,state,body,root):
    return parent+u32(height)+state+body+root

def work(raw):
    seed = hashlib.sha256(b"TKN1/template\0"+raw[:-8]).digest()
    return hashlib.sha256(b"TKN1/work\0"+seed+raw[-8:]).digest()

def mine(template):
    prefix = b"TKN1/work\0"+hashlib.sha256(b"TKN1/template\0"+template).digest()
    target = (1 << (256-BITS)).to_bytes(32,"big")
    for n in range(2**64):
        nonce=u64(n)
        if hashlib.sha256(prefix+nonce).digest()<target:
            return template+nonce
    raise ValueError("nonce exhausted")

def unpack(raw):
    need(PREFIX+8<len(raw)<=PREFIX+MAX_PACKET+8 and raw[:40]==BLOCK+NETWORK,"block frame")
    n,=struct.unpack_from("<I",raw,PREFIX-4)
    need(0<n<=MAX_PACKET and len(raw)==PREFIX+n+8,"packet framing")
    return raw[40:172],raw[PREFIX:-8]

class Ledger:
    def __init__(self, hashes, verifier, genesis, approved):
        need(sha(genesis)==approved and genesis[:40]==GEN+NETWORK and len(genesis)==40+112*len(ALLOC),
             "authorized genesis")
        self.hashes,self.verifier=hashes,verifier
        self.genesis=genesis
        self.endowments=genesis[40:]
        self.cms=[]
        self.nfs=[]
        self.rows=[]
        self.fees=0
        for i,(row,values) in enumerate(zip(pieces(self.endowments,112),ALLOC)):
            need(row[:32]==context(i) and struct.unpack("<QQ",row[64:80])==values,"genesis allocation")
            cm=hashes.call(b"C"+row[:80])
            need(cm==row[80:] and cm!=ZERO and cm not in self.cms,"endowment CM")
            self.cms.append(cm)
        self.head=header(ZERO,0,digest(b"TKN1/state0",NETWORK,genesis),digest(b"TKN1/body0",genesis),
                         hashes.call(b"R"+b"".join(self.cms)))
        self.anchors=[hashes.call(b"H"+self.head)]
        self.work_parent=hashlib.sha256(b"TKN1/genesis-work-parent\0"+genesis).digest()
        self.logs=[]

    def transition(self,packet):
        effects=self.verifier.call(packet)
        need(len(effects)==3757 and effects[:1]==b"1","native verifier rejected")
        e=effects[1:]
        height=int.from_bytes(e[32:36],"little")
        new_height=len(self.anchors)
        need(0<=height<new_height and new_height-height<=WINDOW and self.anchors[height]==e[:32],"eligible branch")
        nfs=pieces(e[36:100],32)
        cms=pieces(e[100:164],32)
        fee,=struct.unpack("<Q",e[164:172])
        need(fee==3 and len(set(nfs))==2 and not set(nfs).intersection(self.nfs),"spentness and fee")
        need(len(set(cms))==2 and ZERO not in cms and not set(cms).intersection(self.cms),"fresh outputs")
        root=self.hashes.call(b"R"+b"".join(self.cms+cms))
        state=digest(b"TKN1/state",NETWORK,self.work_parent,self.head[36:68],u64(self.fees+fee),e[:172])
        h=header(self.anchors[-1],new_height,state,digest(b"TKN1/body",NETWORK,packet),root)
        rows=[cm+ct for cm,ct in zip(cms,pieces(e[172:],CT))]
        return h,nfs,cms,rows,fee

    def accept(self,raw):
        h,packet=unpack(raw)
        need(int.from_bytes(work(raw),"big")<(1<<(256-BITS)),"PoW")
        computed,nfs,cms,rows,fee=self.transition(packet)
        need(h==computed,"header/effects mismatch")
        anchor=self.hashes.call(b"H"+h)
        need(len(anchor)==32,"anchor")
        self.head=h
        self.work_parent=work(raw)
        self.anchors.append(anchor)
        self.cms.extend(cms)
        self.nfs.extend(nfs)
        self.rows.extend(rows)
        self.fees+=fee
        self.logs.append(dict(height=len(self.logs)+1,block_bytes=len(raw),packet_bytes=len(packet),
                              proof_bytes=len(packet)-9-2*CT,receipts_bytes=2*CT,nonce=int.from_bytes(raw[-8:],"little"),
                              work_hash=work(raw).hex(),anchor=anchor.hex(),funded_root=h[-32:].hex(),
                              cumulative_fee_sink_native=self.fees,tx_sha256=sha(packet)))
    def produce(self,packet):
        h,*_=self.transition(packet)
        raw=mine(BLOCK+NETWORK+h+u32(len(packet))+packet)
        self.accept(raw)
        return raw
