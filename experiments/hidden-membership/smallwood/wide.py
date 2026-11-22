"""Optional GF(2^256) representation for the same construction; native CLMUL for bulk work."""
import os

import numpy as np
import sw_wide

U = np.dtype(object)
BYTES = 32
_op = np.frompyfunc(sw_wide.mul,2,1)


def mul(a,b):
    return _op(a,b)


def encode(values):
    return b"".join(int(v).to_bytes(BYTES,"little") for v in np.asarray(values,dtype=U).flat)


def decode(raw):
    view = memoryview(raw)
    return np.array([int.from_bytes(view[i:i+BYTES],"little") for i in range(0,len(view),BYTES)],U)


def random_fields(shape):
    return decode(os.urandom(BYTES*int(np.prod(shape)))).reshape(shape)


def inv(a):
    def inverse(x):
        if x == 0:
            raise ValueError("division by zero")
        # Itoh–Tsujii via binary decomposition of 255. 254 squarings plus 14 multiplies.
        t, k = int(x), 1
        for _ in range(7):
            t2 = t
            for _ in range(k):
                t2 = sw_wide.mul(t2,t2)
            t = sw_wide.mul(t2,t)
            k *= 2
            t = sw_wide.mul(sw_wide.mul(t,t),int(x))
            k += 1
        return sw_wide.mul(t,t)
    if np.ndim(a) == 0:
        return inverse(a)
    flat = np.asarray(a,dtype=U).ravel()
    prefix = [1]
    for x in flat:
        prefix.append(sw_wide.mul(prefix[-1],int(x)))
    acc = inverse(prefix[-1])
    result = np.empty(len(flat),U)
    for i in reversed(range(len(flat))):
        result[i] = sw_wide.mul(acc,prefix[i])
        acc = sw_wide.mul(acc,int(flat[i]))
    return result.reshape(np.shape(a))


def product(v):
    r = 1
    for x in v:
        r = sw_wide.mul(r,int(x))
    return r


def interpolation_batch(samples, weights):
    raw = sw_wide.matrix_product(encode(samples),encode(weights),samples.shape[1])
    return decode(raw).reshape(len(weights),len(samples))
