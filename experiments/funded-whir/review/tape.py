"""Read the public funded CFW tape, verify every salted opening, and check the terminal masked RS identity."""
from hashlib import sha3_512,sha256,shake_256
import argparse
import json
from pathlib import Path
import struct

P=2**64-2**32+1
ZERO=(0,)*5
ONE=(1,0,0,0,0)
DOMAIN=b'PQPC/FUNDED-WHIR-01/EF5/K19/M18/guard4-all/radix16/N19-17-16-17/Q53-38-30-31'
PINS={b'FWT1\x01':(31,'a1cfa119fe582ecd935734ac51db5d1e6c91af9e0019af737d79791dd688cb9c'),
      b'FWL1\x01':(34,'2bc9e336428462084efd673d31da240992e25a289e7fa6ab88237f2d568f6f3e')}


def H(label,*parts):
    digest=sha3_512(b'PQPC/CFW-01'+struct.pack('<I',len(label))+label)
    for part in parts:
        digest.update(struct.pack('<Q',len(part)));digest.update(part)
    return digest.digest()


def words(buf):
    out=[w for (w,) in struct.iter_unpack('<Q',buf)]
    assert all(v<P for v in out)
    return out


def extensions(data):
    assert len(data)%40==0
    ws=words(data)
    return [tuple(ws[i:i+5]) for i in range(0,len(ws),5)]


def plus(a,b):
    return tuple((x+y)%P for x,y in zip(a,b,strict=True))


def mul(a,b):
    c=[0]*9
    for i,x in enumerate(a):
        for j,y in enumerate(b):
            c[i+j]+=x*y
    for i in range(8,4,-1):
        c[i-5]+=3*c[i]
    return tuple(x%P for x in c[:5])


def evaluate(poly,point):
    result=ZERO
    for c in reversed(poly):
        result=plus(mul(result,point),c)
    return result


class Tape:
    def __init__(self,state,data):
        self.state,self.data,self.index=state,data,0

    def take(self,n):
        assert 0<=n<=len(self.data)-self.index
        data=self.data[self.index:self.index+n];self.index+=n
        return data

    def message(self,name,n):
        data=self.take(n)
        self.state=H(b'message',name.encode(),self.state,data)
        return data

    def fields(self,name,k):
        return extensions(self.message(name,40*k))

    def draw(self,name):
        self.state=H(b'verifier-coin-packet',name.encode(),self.state)
        return shake_256(self.state)

    def point(self,name,exclude=()):
        # Rejection sampling per limb; an all-zero/one vector is excluded only for the final outer point.
        gen=self.draw(name);raw=gen.digest(256);pos=0
        while True:
            limbs=[]
            while len(limbs)<5:
                if pos+8>len(raw):
                    raw=gen.digest(len(raw)*2)
                val=int.from_bytes(raw[pos:pos+8],'little');pos+=8
                if val<P:
                    limbs.append(val)
            if tuple(limbs) not in exclude:
                return tuple(limbs)

    def positions(self,name,q,n):
        buf=self.draw(name).digest(8*q)
        return [v&(n-1) for (v,) in struct.iter_unpack('<Q',buf)]

    def opening(self,tree,root,n,width,indices):
        leaves={};values={}
        for index in sorted(set(indices)):
            raw=self.take(width*40);values[index]=extensions(raw)
            leaves[index]=H(b'rs-leaf',bytes([tree]),struct.pack('<I',index),self.take(64),raw)
        frontier=0
        for depth in range(n.bit_length()-1):
            absent=[i^1 for i in sorted(leaves) if i^1 not in leaves]
            for i in absent:
                leaves[i]=self.take(64)
            frontier+=len(absent)
            leaves={i//2:H(b'rs-parent',bytes([tree,depth]),leaves[i],leaves[i+1]) for i in leaves if i%2==0}
        assert leaves=={0:root}
        return values,dict(tree=tree,draws=len(indices),unique=len(values),sibling_hashes=frontier,
                           query_positions_SHA256=sha256(b''.join(struct.pack('<I',i) for i in indices)).hexdigest())


def read(packet):
    tag=packet[:5]
    count,pin=PINS[tag]
    n,=struct.unpack_from('<I',packet,5);a=9+8*count
    assert n<=245952 and len(packet)==a+n+3584
    encoded=packet[9:a];public=words(encoded)
    assert public[5:9]!=public[9:13] and public[13:17]!=public[17:21] and public[4]<2**32
    assert (public[21]==3 and not any(public[26:])) if count==31 else (public[21] in (0,3) and all(x<2**32 for x in public[26:]))
    program=H(b'registered-funded-matrix',tag,pin.encode())
    t=Tape(H(b'registered-statement',DOMAIN,program,encoded),packet[a:a+n])
    root=[t.message('rs-root-0',64)]
    target,=t.fields('outer-mask-cube-sum',1)
    t.draw('four-base-guards')
    assert len(words(t.message('guard-replies',32)))==4
    t.draw('outer-zerocheck')
    for j in range(19):
        coeff=t.fields(f'outer-polynomial-{j}',6)
        assert target==plus(coeff[0],evaluate(coeff,ONE))
        point=t.point(f'outer-point-{j}',(ZERO,ONE) if j==18 else ())
        target=evaluate(coeff,point)
    t.fields('outer-masked-terminals',3);t.draw('outer-batch')
    openings=[]
    for i,(q,domain) in enumerate(zip((53,38,30),(2**19,2**17,2**16),strict=True)):
        label=f'stage-{i}'
        t.fields(label+'-mask-sum',1);t.draw(label+'-mask-mix')
        for j in range(4):
            coeff=t.fields(label+f'-polynomial-{j}',3)
            if j:
                assert target==plus(coeff[0],evaluate(coeff,ONE))
            target=evaluate(coeff,t.point(label+f'-point-{j}'))
        root.append(t.message(f'rs-root-{i+1}',64));t.draw(label+'-ood-vector')
        t.fields(label+'-ood-answer',1)
        indices=t.positions(label+'-queries-and-batch',q,domain)
        _,m=t.opening(i,root[i],domain,16,indices);openings.append(m)
    root.append(t.message('rs-root-4',64));t.fields('base-mask-target',1)
    delta=t.point('base-challenge');combined=t.fields('base-blinded-codeword',133)
    domain=2**17;omega=0xabd0a6e8aa3d8a0e
    assert pow(omega,domain//2,P)==P-1
    indices=t.positions('base-sample',31,domain)
    left,l=t.opening(3,root[3],domain,1,indices);right,r=t.opening(4,root[4],domain,1,indices)
    openings.extend((l,r))
    for idx in set(indices):
        z=pow(omega,idx,P)
        x=tuple(sum(c[i]*pow(z,j,P) for j,c in enumerate(combined))%P for i in range(5))
        assert x==plus(right[idx][0],mul(delta,left[idx][0]))
    assert t.index==len(t.data)
    return dict(suite=tag[:4].decode(),public_words=count,public_vector_sha256=sha256(encoded).hexdigest(),
                ordered_receipts_sha256=sha256(packet[-3584:]).hexdigest(),packet_sha256=sha256(packet).hexdigest(),
                packet_B=len(packet),proof_B=n,height=public[4],fee=public[21],root_count=len(root),
                outer_sumchecks=19,inner_adjacent_sumchecks=9,terminal_coefficients=133,
                same_positions_terminal_checks=len(indices),authenticated_tree_openings=openings)


if __name__=='__main__':
    if not __debug__:raise SystemExit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('packet',type=Path,nargs='+')
    print(json.dumps([read(path.read_bytes()) for path in p.parse_args().packet],sort_keys=True,indent=2))
