"""SmallWood-LCS and degree-enforcing polynomial commitment, Figs. 4 and 8."""
from dataclasses import dataclass
from functools import cached_property
import os

import numpy as np

from field import U, basis, evaluate, inv, mul, random_fields, xor, evaluate_many, encode, WIDE
from transcript import hash_bytes


@dataclass(frozen=True)
class Profile:
    pack: int = 32
    opens: int = 16
    leaves: int = 256
    decs_rows: int = 16
    salt_bytes: int = 16
    hash_bytes: int = 32

    @cached_property
    def points(self):
        return tuple(range(self.pack+self.opens))

    @cached_property
    def qpoints(self):
        return tuple(range(2*self.pack+self.opens))

    @cached_property
    def omega(self):
        return tuple(range(self.pack))

    def evaluation(self, index):
        return len(self.qpoints)+index




def derive_leaf(i, raw, salt, hlen):
    return hash_bytes(b"DECS leaf", i.to_bytes(4, "little"), raw, salt).digest(hlen)


def node(left, right):
    return hash_bytes(b"DECS node",left,right).digest(len(left))


def merkle(leaves):
    layers = [leaves]
    while len(layers[-1]) > 1:
        l = layers[-1]
        layers.append([node(a,b) for a,b in zip(l[::2],l[1::2])])
    return layers


def dot_rows(data, scales):
    return xor(mul(data, scales[:,None]),axis=0)


def powers(n, x):
    out = np.ones(n, U)
    for i in range(1,n):
        out[i] = mul(out[i-1], x)
    return out


class Commitment:
    def __init__(self, profile, tr, length, witness=None):
        p = self.p = profile
        self.n = n = (length+p.pack-1)//p.pack
        d = len(p.points)
        if tr.producing:
            # Polynomial samples at 0..d-1, P|Omega = witness rows.
            table = random_fields((n, d))
            table[:,:p.pack] = np.pad(witness, (0,n*p.pack-length)).reshape(n,p.pack)
            # Sample uniformly in the kernel of sum_{x in Omega} M(x).
            coeff = random_fields((len(p.qpoints),))
            functional = xor(np.array([powers(len(coeff),x) for x in p.omega]), axis=0)
            pivot = np.flatnonzero(functional)[0]
            coeff[pivot] ^= mul(xor(mul(coeff,functional)), inv(functional[pivot]))
            # Remark 7: M=Mlo+X^(dQ-dP)*Mhi, with both pieces degree <=dP.
            # Randomize their overlapping coefficients while preserving M.
            low = coeff[:d].copy()
            high = coeff[p.pack:].copy()
            overlap = random_fields((d-p.pack,))
            low[p.pack:] = overlap
            high[:len(overlap)] ^= overlap
            blocks = [low,high]
            masks = np.array([[xor(mul(chunk,powers(len(chunk),x))) for x in p.points]
                              for chunk in blocks], U)
            self.samples = np.vstack((table,masks,random_fields((p.decs_rows,d))))
            self.salts = [os.urandom(p.salt_bytes) for _ in range(p.leaves)]
            self.columns = evaluate_many(self.samples,p.points,[p.evaluation(i) for i in range(p.leaves)])
            self.tree = merkle([derive_leaf(i,encode(col),s,p.hash_bytes) for i,(col,s)
                                in enumerate(zip(self.columns,self.salts))])
        self.root = tr.message(b"DECS root",p.hash_bytes,self.tree[-1][0] if tr.producing else None)
        self.gamma = tr.challenge(b"degree matrix",p.decs_rows*(n+2)).reshape(p.decs_rows,n+2)
        if tr.producing:
            self.rsamples = np.array([r ^ dot_rows(self.samples[:n+2],row)
                                      for r,row in zip(self.samples[n+2:],self.gamma)])
            rhash = hash_bytes(b"R canonical",encode(self.rsamples)).digest(p.hash_bytes)
        self.rhash = tr.message(b"degree digest",p.hash_bytes,rhash if tr.producing else None)

    def open(self, tr, coef, target, *, diagnostic_invalid_prover=False):
        p,n = self.p,self.n
        d = len(p.points)
        weights = np.pad(coef,(0,n*p.pack-len(coef))).reshape(n,p.pack)
        def qvalue(x, col):
            return (xor(mul(evaluate(weights,p.omega,x),col[:n])) ^ col[n]
                    ^ mul(powers(p.pack+1,x)[-1],col[n+1]))
        if tr.producing:
            q = [qvalue(x,evaluate(self.samples,p.points,x)) for x in p.qpoints]
        q = tr.fields(b"LCS Q",len(p.qpoints),q if tr.producing else None)
        if xor(q[:p.pack]) != target and not (tr.producing and diagnostic_invalid_prover):
            raise ValueError("linear constraints rejected")
        indices = []
        while len(indices) < p.opens:
            # N is a power of two dividing 65536.
            for sample in tr.challenge(b"opening indices",p.opens):
                idx = int(sample) % p.leaves
                if idx not in indices:
                    indices.append(idx)
                    if len(indices) == p.opens:
                        break
        indices.sort()
        r_open = []
        for i in indices:
            col = tr.fields(b"open column",n+2+p.decs_rows,self.columns[i] if tr.producing else None)
            salt = tr.message(b"leaf salt",p.salt_bytes,self.salts[i] if tr.producing else None)
            h = derive_leaf(i,encode(col),salt,p.hash_bytes)
            idx = i
            for j in range(p.leaves.bit_length()-1):
                sibling = tr.message(b"Merkle sibling",p.hash_bytes,self.tree[j][idx^1] if tr.producing else None)
                h = node(sibling,h) if idx&1 else node(h,sibling)
                idx >>= 1
            if h != self.root:
                raise ValueError("DECS Merkle path rejected")
            x = p.evaluation(i)
            if evaluate(q,p.qpoints,x) != qvalue(x,col):
                raise ValueError("LCS polynomial rejected")
            r_open.append(col[n+2:] ^ xor(mul(self.gamma,col[:n+2]),axis=1))
        extra = [j for j in range(p.leaves) if j not in indices][:d-p.opens]
        for idx in extra:
            sample = evaluate(self.rsamples,p.points,p.evaluation(idx)) if tr.producing else None
            r_open.append(tr.fields(b"R completion",p.decs_rows,sample))
        domain = tuple(p.evaluation(j) for j in indices+extra)
        recovered = np.array([evaluate(np.array(r_open).T,domain,x) for x in p.points]).T
        if hash_bytes(b"R canonical",encode(recovered)).digest(p.hash_bytes) != self.rhash:
            raise ValueError("DECS polynomial rejected")
