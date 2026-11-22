"""Explicit GF(2^16) embedding in GF(2^256) and inverse extension-basis coordinates."""
from functools import lru_cache
import os

import numpy as np
from sw_wide import mul as kmul
from field import EXP, LOG

F = np.dtype("<u2")
ALPHA = 0x3002abcf2bc4795d59f58d944fcb6e1c7f47feefc2ba73a348aac61ea068d7a5


def power(x,n):
    y = 1
    while n:
        if n & 1:
            y = kmul(y,x)
        x = kmul(x,x)
        n >>= 1
    return y


if power(ALPHA,16) ^ power(ALPHA,12) ^ power(ALPHA,3) ^ ALPHA ^ 1:
    raise RuntimeError("subfield generator does not satisfy the base modulus")

EMBED = [0]
for i in range(16):
    a = power(ALPHA,i)
    EMBED.extend([v ^ a for v in EMBED])
EMBED = np.array(EMBED,dtype=object)
BETA = [1<<j for j in range(16)]


def inverse_basis():
    pivots = {}
    for j,b in enumerate(BETA):
        for i in range(16):
            v,k = kmul(b,EMBED[1<<i]),1<<(16*j+i)
            while v:
                p = v.bit_length()-1
                if p not in pivots:
                    pivots[p] = (v,k)
                    break
                a,c = pivots[p]
                v,k = v^a,k^c
    if len(pivots) != 256:
        raise RuntimeError("singular extension basis")
    def solve(v):
        k = 0
        while v:
            a,c = pivots[v.bit_length()-1]
            v,k = v^a,k^c
        return k
    return [[solve(b << (8*j)) for b in range(256)] for j in range(32)]


DECOMPOSE = inverse_basis()


def split(x):
    v = 0
    for i,b in enumerate(int(x).to_bytes(32,"little")):
        v ^= DECOMPOSE[i][b]
    return np.frombuffer(v.to_bytes(32,"little"),F)


def join(parts):
    v = 0
    for b,a in zip(BETA,parts,strict=True):
        v ^= kmul(b,EMBED[a])
    return v


def fmul(a,b):
    return np.where((a == 0) | (b == 0),0,EXP[LOG[a]+LOG[b]]).astype(F)


def finv(a):
    if np.any(a==0):
        raise ValueError("zero denominator")
    return EXP[65535-LOG[a]]


def fprod(a):
    return 0 if np.any(a==0) else EXP[int(np.sum(LOG[a]))%65535]


def frandom(shape):
    return np.frombuffer(os.urandom(2*int(np.prod(shape))),F).reshape(shape).copy()


def fencode(v):
    return np.asarray(v,F).tobytes()


def freduce(v,axis=None):
    return np.bitwise_xor.reduce(v,axis=axis,initial=0)


@lru_cache(maxsize=24)
def fweights(nodes):
    p = np.array(nodes,F)
    return np.array([finv(fprod(p[p!=x]^x)) for x in p],F)


def fbasis(nodes,x):
    delta = np.asarray(nodes,F)^x
    if not np.all(delta):
        return (delta==0).astype(F)
    return fmul(fmul(fweights(nodes),finv(delta)),fprod(delta))


def feval(data,nodes,x):
    return freduce(fmul(data,fbasis(nodes,x)),axis=-1)


def fpowers(n,x):
    if not x:
        a = np.zeros(n,F)
        a[0] = 1
        return a
    return EXP[(LOG[x]*np.arange(n,dtype=np.int64))%65535]
