"""Decode MSP1 envelopes, check real public proofs and independently verify issuer signatures."""
from dataclasses import dataclass
from pathlib import Path
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0,str(ROOT/'experiments/user-assets/review'))
import public_replay as ast1

ZERO, MAX, BURN = bytes(32), (1<<62)-1, 1<<62


def label(domain, payload):
    digest = bytearray(ast1.sha(domain+payload))
    for i in (7,15,23,31):
        digest[i] &= 127
    return bytes(digest)


def auth(network, op, issuer, sequence, prior, inner):
    return ast1.sha(b'MNG1/supply-auth/v1\0'+network+bytes([op])+issuer+ast1.U64.pack(sequence)+prior+ast1.sha(inner))


@dataclass(frozen=True)
class Event:
    txid: bytes
    op: int
    issuer: bytes
    sequence: int
    prior: bytes
    born: int
    anchor: bytes
    nullifiers: tuple
    commitments: tuple
    fee: int
    asset: bytes
    delta: int
    receipts: bytes
    legacy: bool = False

    def transition(self):
        body=b''.join((*self.nullifiers,*self.commitments,ast1.U64.pack(self.fee),self.asset,ast1.U64.pack(self.delta)))
        return body if self.legacy else body+self.txid


class Reader:
    def __init__(self,role,roots,network,node,legacy=None):
        self.role,self.roots,self.network,self.node = role,roots,network,node
        self.legacy = legacy
        self.events = {}
        self.sigs = []
        self.cases = []
        self.counts = {'proof':0,'legacy_proof':0,'signature':0}

    def packet(self, raw):
        if raw.startswith(b'AST1'):
            assert self.legacy is not None
            x=self.legacy.packet(raw)
            self.counts['legacy_proof']+=1
            e=Event(x.txid,int(bool(x.cap)),b'',0,ZERO,x.born,x.anchor,x.nullifiers,x.commitments,x.fee,x.issue,x.cap,x.receipts,True)
            assert self.events.setdefault(e.txid,e)==e
            return e
        assert len(raw) <= 262144 and raw[:5] == b'MSP1\x01'
        op = raw[5]
        assert op in range(5)
        signed = op in (2,3)
        if signed:
            pk,seq,prev = raw[6:38],ast1.U64.unpack_from(raw,38)[0],raw[46:78]
            signature = raw[78:17166]
            inner = raw[17166:]
            assert len(signature)==17088 and seq<1<<63
            message = auth(self.network,op,pk,seq,prev,inner)
            assert self.role.call(b'V'+pk+message+signature)==b'1'
            self.sigs.append(pk+message+signature)
            self.counts['signature'] += 1
            if not any(kind==op for kind,_,_ in self.cases):
                self.cases.append((op,raw,(pk,seq,prev,signature,inner)))
        else:
            pk,seq,prev,inner = b'',0,ZERO,raw[6:]
        assert inner[:5]==b'MNG1\x01'
        size = ast1.U32.unpack_from(inner,5)[0]
        end = 9+size
        assert size>256 and len(inner)==end+3584
        length,*words=struct.unpack_from('<32Q',inner,end-256)
        assert length==31 and all(v<ast1.P for v in words)
        pi,ct=inner[end-248:end],inner[end:]
        assert ast1.reference(self.roots,['--ciphertext-digests'],ct)==[pi[176:208].hex()]
        assert words[4] < 1<<32 and words[21]==3
        assert self.role.call(inner)==b'1'+pi[:36]+pi[40:176]+ct+pi[208:]
        self.counts['proof']+=1
        e=Event(ast1.sha(raw),op,pk,seq,prev,words[4],pi[:32],(pi[40:72],pi[72:104]),(pi[104:136],pi[136:168]),
                words[21], pi[208:240], words[30],ct)
        assert len(set(e.nullifiers))==len(set(e.commitments))==2 and ZERO not in e.commitments
        magnitude=e.delta&MAX
        assert e.delta<1<<63 and bool(e.delta&BURN)==(op==4)
        assert (op==0)==(magnitude==0)==(e.asset==ZERO)
        if op:
            assert all(x<128 for x in e.asset[7::8])
        if op==1:
            assert e.asset==label(b'AST1/issue-id/v1\0',self.network+e.nullifiers[0])
        if op==2:
            assert e.asset==label(b'MNG1/managed-id/v1\0',self.network+pk+e.nullifiers[0])
        assert self.events.setdefault(e.txid,e)==e
        return e

    def verify_sigs(self):
        assert len(self.cases) == 2 and len(self.sigs)>=2
        tests = []
        for op,raw,(pk,seq,prev,sig,inner) in self.cases:
            def opposite(b):
                return bytes([b[0]^1])+b[1:]
            end=9+ast1.U32.unpack_from(inner,5)[0]
            issue=auth(self.network,op,pk,seq,prev,inner)
            for tag,offset in [('proof',9),('first_output',end-248+104),('second_output',end-248+136),
                               ('asset',end-40),('quantity',end-8),('first_receipt',end+100),('second_receipt',end+1892)]:
                changed=bytearray(inner)
                changed[offset]^=1
                tests.append((op,tag,pk+auth(self.network,op,pk,seq,prev,changed)+sig))
            for tag,msg in [('network',auth(opposite(self.network),op,pk,seq,prev,inner)),
                            ('opcode',auth(self.network,5-op,pk,seq,prev,inner)),
                            ('authority',auth(self.network,op,opposite(pk),seq,prev,inner)),
                            ('predecessor',auth(self.network,op,pk,seq,opposite(prev),inner)),
                            ('sequence',auth(self.network,op,pk,seq^1,prev,inner))]:
                tests.append((op,tag,pk+msg+sig))
            tests.append((op,'signature',pk+issue+opposite(sig)))
        blob=b''.join(self.sigs+[case for _,_,case in tests])
        results=subprocess.check_output([self.node,HERE/'verify_slh.mjs'],input=blob,timeout=60)
        assert results==b'1'*len(self.sigs)+b'0'*len(tests)
        return dict(valid_public_signatures=len(self.sigs),mutated_binding_rejections=[(op,tag) for op,tag,_ in tests],
                    independent_provider='Node 24.22.1 / OpenSSL 3.5.9, SLH-DSA-SHAKE-128f, empty context')
