"""Compile privately owned FS01 notes and paths into shared Keccak and bit constraints."""
from pathlib import Path
import sys

import numpy as np

GKR = Path(__file__).resolve().parents[1] / "gkr"
sys.path.insert(0, str(GKR))
from rounds import RoundBatch, forward

I = np.int32
B = np.uint8


def public_bits(data):
    return np.unpackbits(np.frombuffer(data, B), bitorder="little").astype(I)


class Wiring:
    """A bit ID names exactly one coordinate in the committed binary assignment."""
    def __init__(self, flatten, private):
        self.flatten = flatten
        self.private = private
        self.width = 2
        self.values = bytearray((0, 1))
        self.linear = []
        self.products = []
        self.bounds = []
        self.states = []
        self.selectors = []
        # The constants are themselves committed and pinned by two public equations.
        self.pin(np.array([0, 1], I), np.array([0, 1], B))

    def allocate(self, width, values=None):
        if self.private:
            values = np.asarray(values, B).reshape(width)
            self.values.extend(values.tobytes())
        start = self.width
        self.width += width
        return np.arange(start, start+width, dtype=I)

    def secret(self, nbytes, data):
        if self.private and len(data) != nbytes:
            raise ValueError("unexpected private input length")
        return self.allocate(8*nbytes, public_bits(data) if self.private else None)

    def read(self, ids):
        return np.frombuffer(self.values, B)[ids]

    def pin(self, ids, public):
        self.linear.append(((np.asarray(ids, I),), np.asarray(public, B)))

    def xor(self, *inputs):
        arrays = tuple(np.asarray(x, I) for x in inputs)
        v = None
        if self.private:
            v = np.bitwise_xor.reduce([self.read(x) for x in arrays],axis=0)
        result = self.allocate(len(arrays[0]),v)
        self.linear.append(((*arrays,result), np.zeros(len(result),B)))
        return result

    def product(self,x,y):
        a,b = np.atleast_1d(x).astype(I),np.atleast_1d(y).astype(I)
        v = self.read(a) & self.read(b) if self.private else None
        z = self.allocate(len(a),v)
        self.products.append((a,b,z))
        return z

    def permutation(self, input_ids):
        state = forward(self.read(input_ids)) if self.private else None
        step = 24//self.flatten
        witness_ids = [input_ids]
        for round_id in range(step,25,step):
            witness_ids.append(self.allocate(1600,state[round_id] if self.private else None))
        self.bounds.append(witness_ids)
        if self.private:
            self.states.append(state)
        return witness_ids[-1]

    def shake(self, tag, *payload):
        raw = np.concatenate((public_bits(bytes((0xf1,tag))), *payload))
        pad = bytearray(136-len(raw)//8%136)
        pad[0] = 0x1f
        pad[-1] |= 0x80
        raw = np.concatenate((raw,public_bits(pad)))
        prior = None
        for chunk in raw.reshape(-1,1088):
            if prior is None:
                state_in = np.concatenate((chunk,np.zeros(512,I)))
            else:
                state_in = np.concatenate((self.xor(chunk,prior[:1088]),prior[1088:]))
            prior = self.permutation(state_in)
        return prior[:512]

    def order(self, child, sibling, direction):
        d = int(direction)
        left_v = None
        if self.private:
            left_v = self.read(sibling if self.values[d] else child)
        left = self.allocate(512,left_v)
        self.selectors.append((child,sibling,d,left))
        return left,self.xor(child,sibling,left)

    def below_count(self, index, count):
        if count == 1<<40:
            return
        less = np.array([0],I)
        for i in range(40):
            x = index[i:i+1]
            one = np.array([1],I)
            if (count>>i)&1:
                less = self.xor(one,self.product(x,self.xor(less,one)))
            else:
                less = self.product(self.xor(x,one),less)
        self.pin(less,[1])

    def distinct(self,x,y):
        same = np.array([1],I)
        for v in self.xor(x,y):
            same = self.product(same,self.xor([v],[1]))
        self.pin(same,[0])

    def batch(self):
        return RoundBatch(np.asarray(self.bounds,I), np.asarray(self.states,B) if self.private else None)


def build(chain, root, count, nfs, flatten, openings=None):
    if (len(chain)!=64 or len(root)!=64 or not 2<=count<=1<<40 or
        len(nfs)!=2 or any(len(v)!=64 for v in nfs) or nfs[0]==nfs[1] or
        flatten<=0 or 24%flatten):
        raise ValueError("invalid funded public statement")
    w = Wiring(flatten,openings is not None)
    indices = []
    for j in range(2):
        record = openings[j] if openings is not None else {}
        def private(name, n):
            return w.secret(n,bytes.fromhex(record[name]) if w.private else None)
        ask,occ = private("ask",64),private("occ",64)
        native,asset,qty,salt = (private(name,n) for name,n in
                                 (("native",8),("asset",64),("qty",8),("salt",64)))
        owner = w.shake(3,ask)
        cm = w.shake(4,public_bits(chain),owner,native,asset,qty,salt)
        leaf = w.shake(5,occ,cm)
        nf = w.shake(8,ask,occ)
        w.pin(nf,public_bits(nfs[j]))
        idx = w.secret(5,int(record["index"]).to_bytes(5,"little") if w.private else None)
        indices.append(idx)
        w.below_count(idx,count)
        for level in range(40):
            sibling = w.secret(64,bytes.fromhex(record["path"][level]) if w.private else None)
            left,right = w.order(leaf,sibling,idx[level])
            leaf = w.shake(7,public_bits(bytes([level])),left,right)
        w.pin(leaf,public_bits(root))
    w.distinct(*indices)
    if len(w.bounds)!=92 or len(w.selectors)!=80:
        raise ValueError("unregistered funding geometry")
    return w
