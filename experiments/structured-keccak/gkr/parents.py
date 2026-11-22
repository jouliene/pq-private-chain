"""Verifier-owned FS01 path-segment row wiring for the two-parent and batch gates."""
import numpy as np
from runtime import U, mul, xor
from rounds import N, RoundBatch, forward, run_rounds
from selection import run_selection

DEPTH = 40


def parse(data):
    if data[:4]!=b"SGP1" or len(data)<6:
        raise ValueError("invalid SGP1 header")
    paths = int.from_bytes(data[4:6],"little")
    if not paths or len(data)!=6+66*paths:
        raise ValueError("invalid SGP1 size")
    result = []
    for i in range(paths):
        off = 6+i*66
        level,depth = data[off:off+2]
        if not depth or level+depth>DEPTH:
            raise ValueError("invalid level schedule")
        result.append((level,depth,data[off+2:off+66]))
    return result


def binary(raw):
    return np.unpackbits(np.frombuffer(raw,np.uint8),bitorder="little")


class PathLayout:
    def __init__(self,data,k,private=None,*,detached=False):
        self.spec = parse(data)
        p = sum(d for _,d,_ in self.spec)
        if k<1 or 24%k:
            raise ValueError("invalid flattening factor")
        expected_len = sum(64+65*d for _,d,_ in self.spec)
        if private is not None and len(private)!=expected_len+(64 if detached else 0):
            raise ValueError("invalid secret size")
        if detached and (private is None or self.spec[0][1]<2):
            raise ValueError("detached fixture needs two levels")
        self.nbits = len(self.spec)*512+p*(513+N*(k+1))
        self.bits = np.zeros(self.nbits,np.uint8) if private is not None else None
        self.states = np.empty((p,25,N),np.uint8) if private is not None else None
        self.boundaries = np.empty((p,k+1,N),np.int64)
        self.children,self.siblings,self.directions,self.left = [],[],[],[]
        self.headers,self.order,self.roots = [],[],[]
        cursor = off = j = 0
        def alloc(n):
            nonlocal cursor
            ids = np.arange(cursor,cursor+n)
            cursor += n
            return ids
        for chain,(start,depth,root) in enumerate(self.spec):
            child = alloc(512)
            if private is not None:
                self.bits[child] = binary(private[off:off+64])
                off += 64
            for step in range(depth):
                level = start+step
                sib,di,bound = alloc(512),alloc(1)[0],alloc((k+1)*N).reshape(k+1,N)
                self.boundaries[j] = bound
                left,right = bound[0,24:536],bound[0,536:1048]
                self.children.append(child)
                self.siblings.append(sib)
                self.directions.append(di)
                self.left.append(left)
                self.order.append((left,right,child,sib))
                fixed = np.r_[0:24,1048:N]
                fixed_values = binary(bytes([0xf1,7,level])+bytes(128)+bytes([0x1f,0,0,0,0x80])+bytes(64))
                self.headers.append((bound[0,fixed],fixed_values[fixed]))
                if private is not None:
                    direction = private[off+64]
                    if direction not in (0,1):
                        raise ValueError("invalid direction")
                    self.bits[sib] = binary(private[off:off+64])
                    self.bits[di] = direction
                    off += 65
                    selected = binary(private[-64:]) if detached and chain==0 and step==1 else self.bits[child]
                    a,b = (self.bits[sib],selected) if direction else (selected,self.bits[sib])
                    fixed_values[24:536],fixed_values[536:1048] = a,b
                    self.states[j] = forward(fixed_values)
                    self.bits[bound] = self.states[j,::24//k]
                child = bound[-1,:512]
                j += 1
            self.roots.append((child,binary(root)))
        self.batch = RoundBatch(self.boundaries,self.states)
        linkell = 5+(p-1).bit_length()
        self.ntrace = self.batch.mask_count+3*linkell+3+self.batch.depth+2

    def constraints(self,ctx):
        run_rounds(self.batch,ctx)
        run_selection(self.children,self.siblings,self.directions,self.left,ctx)
        fixed = self.headers+self.roots
        count = sum(len(ids) for ids,_ in fixed) + 512*len(self.order)
        gamma = ctx.tr.challenge(b"FS01 header capacity root and complementary child",count)
        target = 0
        off = 0
        for ids,values in fixed:
            target ^= xor(gamma[off:off+len(ids)][values.astype(bool)])
            off += len(ids)
        def apply(out,scale):
            off = 0
            for ids,_ in fixed:
                np.bitwise_xor.at(out,ids,mul(gamma[off:off+len(ids)],scale))
                off += len(ids)
            for terms in self.order:
                v = mul(gamma[off:off+512],scale)
                for ids in terms:
                    np.bitwise_xor.at(out,ids,v)
                off += 512
        ctx.bind(apply,ctx.form(target))
