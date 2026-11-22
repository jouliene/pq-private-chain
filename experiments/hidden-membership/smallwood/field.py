"""Vector arithmetic and interpolation over GF(2^16), modulo x^16+x^12+x^3+x+1."""
import os
from functools import lru_cache

import numpy as np

U = np.dtype("<u2")
EXP = np.empty(131070, dtype=U)
LOG = np.zeros(65536, dtype=np.int32)
value = 1
for i in range(65535):
    EXP[i] = value
    LOG[value] = i
    value = (value << 1) ^ (0x1100b if value >> 15 else 0)
if value != 1 or np.unique(EXP[:65535]).size != 65535:
    raise RuntimeError("invalid primitive element")
EXP[65535:] = EXP[:65535]


def mul(a, b):
    return np.where((a == 0) | (b == 0), 0, EXP[LOG[a] + LOG[b]]).astype(U)


def inv(a):
    if np.any(a == 0):
        raise ValueError("division by zero")
    return EXP[65535 - LOG[a]]


def xor(v, axis=None):
    return np.bitwise_xor.reduce(v, axis=axis, initial=0)


def random_fields(shape):
    return np.frombuffer(os.urandom(2 * int(np.prod(shape))), U).reshape(shape).copy()


@lru_cache(maxsize=8)
def weights(points):
    p = np.asarray(points, dtype=U)
    w = np.ones(len(p), dtype=U)
    for i, x in enumerate(p):
        w[i] = inv(product(p[p != x] ^ x))
    return w


def product(v):
    if np.any(v == 0):
        return 0
    return EXP[int(np.sum(LOG[v])) % 65535]


def basis(points, x):
    p = np.asarray(points, dtype=U)
    delta = p ^ x
    if not np.all(delta):
        return (delta == 0).astype(U)
    return mul(mul(weights(tuple(points)), inv(delta)), product(delta))


def evaluate(samples, points, x):
    b = basis(points, x)
    return xor(mul(b, samples), axis=-1)


def eq_table(point):
    t = np.ones(1, dtype=U)
    for r in reversed(point):
        t = np.stack((mul(t, r ^ 1), mul(t, r)), axis=1).ravel()
    return t


def fold(t, r):
    return t[::2] ^ mul(t[::2] ^ t[1::2], r)

# The calibration path keeps its compact uint16 arrays. A new verifier process fixes its profile.
FIELD = os.environ.get("SW_FIELD","gf16")
if FIELD not in ("gf16","gf256"):
    raise ValueError("unknown verifier field profile")
WIDE = FIELD == "gf256"
BYTES = 2


def encode(values):
    return np.asarray(values,dtype=U).tobytes()


def decode(data):
    return np.frombuffer(data,U)


if WIDE:
    from wide import U, BYTES, mul, inv, product, random_fields, encode, decode, interpolation_batch


def evaluate_many(samples, points, xs):
    if WIDE:
        return interpolation_batch(samples,np.array([basis(points,x) for x in xs],U))
    return [evaluate(samples,points,x) for x in xs]
