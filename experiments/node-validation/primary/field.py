"""Research scalar arithmetic in the CP03 quintic power basis. No constant-time claim."""

from secrets import randbelow
from math import prod

P = 2**64 - 2**32 + 1


class K(tuple):
    def __new__(cls, limbs=0):
        if isinstance(limbs, int):
            limbs = (limbs, 0, 0, 0, 0)
        if len(limbs) != 5:
            raise ValueError("EF5 arity")
        return tuple.__new__(cls, (x % P for x in limbs))

    def __add__(self, other):
        return K([x + y for x, y in zip(self, K(other))])

    __radd__ = __add__

    def __neg__(self):
        return K([-x for x in self])

    def __sub__(self, other):
        return self + -K(other)

    def __rsub__(self, other):
        return K(other) + -self

    def __mul__(self, other):
        if isinstance(other, int):
            return K([other*x for x in self])
        result = [0] * 5
        for i, x in enumerate(self):
            for j, y in enumerate(other):
                n = i+j
                result[n % 5] += x*y*(3 if n >= 5 else 1)
        return K(result)

    __rmul__ = __mul__

    def __pow__(self, exponent):
        if exponent < 0:
            raise ValueError("negative exponent")
        result, power = K(1), self
        while exponent:
            if exponent & 1:
                result = result * power
            power = power * power
            exponent >>= 1
        return result

    def pack(self):
        return b''.join(x.to_bytes(8, "little") for x in self)

    @classmethod
    def unpack(cls, data):
        if len(data) != 40:
            raise ValueError("field length")
        limbs = [int.from_bytes(data[i:i+8], "little") for i in range(0, 40, 8)]
        if max(limbs) >= P:
            raise ValueError("noncanonical EF5")
        return cls(limbs)


def uniform():
    return K([randbelow(P) for _ in range(5)])


def dot(left, right):
    return sum((x*y for x, y in zip(left, right, strict=True)), K())


def poly(coefs, x):
    value = K()
    for c in reversed(coefs):
        value = value*x+c
    return value


def eqweight(point, bits):
    return prod((x*y+(1-x)*(1-y) for x, y in zip(point, bits, strict=True)), start=K(1))


def interpolate(values):
    """Newton forward interpolation at successive small base-field integers."""
    values, basis, out = list(values), [1], [K() for _ in values]
    for i in range(len(out)):
        for j, c in enumerate(basis):
            out[j] += values[0]*c
        values = [y-x for x, y in zip(values, values[1:])]
        inv = pow(i+1, -1, P)
        basis = [((basis[j-1] if j else 0) - i*(basis[j] if j<len(basis) else 0))*inv % P
                 for j in range(len(basis)+1)]
    return out
