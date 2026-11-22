"""Deterministic backend field checks and differential FS01/R1CS tests with ephemeral data."""
import secrets
import numpy as np
from field import WIDE, inv, mul
from relation import Circuit, bits, parent


def remainder(a,m):
    while a.bit_length() >= m.bit_length():
        a ^= m << (a.bit_length() - m.bit_length())
    return a


def reference_mul(x,y,m):
    ans = 0
    while y:
        if y & 1:
            ans ^= x
        x <<= 1
        y >>= 1
    return remainder(ans,m)


def check_field():
    n,m = (256,(1<<256)|0x425) if WIDE else (16,0x1100b)
    # Both extension degrees are powers of two; Rabin has only one prime divisor.
    x = 2
    for i in range(n):
        x = reference_mul(x,x,m)
        if i+1 == n//2:
            a,b = x^2,m
            while b:
                a,b=b,remainder(a,b)
            assert a == 1
    assert x == 2
    for i in range(n):
        x = (1<<i)|1
        y = (1<<(n-1-i))|1
        assert mul(x,y) == reference_mul(x,y,m)
        assert mul(x,inv(x)) == 1


def check_relation():
    for d0,d1 in [(0,0),(0,1),(1,0),(1,1)]:
        a,b,c,hole = (secrets.token_bytes(64) for _ in range(4))
        s = (a,b,c,d0,d1)
        first = parent(38,a,b,d0)
        good = Circuit(38,parent(39,first,c,d1),s)
        aa,bb,cc = (m.apply(good.w) for m in good.matrices)
        assert np.all(mul(aa,bb)==cc)
        bad = Circuit(38,parent(39,hole,c,d1),s,bits(hole))
        aa,bb,cc = (m.apply(bad.w) for m in bad.matrices)
        wrong = np.flatnonzero(mul(aa,bb)!=cc)
        # The first and second 24-round Keccak groups and final digest are genuine.
        # Only the second input selection equations disagree.
        boundary = 1538 + 1536 + 38400 + 512
        assert len(wrong)>0 and np.all((wrong>=boundary) & (wrong<boundary+1024))
        assert all(np.array_equal(x.index[:-512],y.index[:-512]) for x,y in zip(good.matrices,bad.matrices))
        # Public roots legitimately change the final 512 linear rows.


if __name__ == "__main__":
    check_field()
    check_relation()
    print("field arithmetic, irreducibility and all four linked orientations passed")
