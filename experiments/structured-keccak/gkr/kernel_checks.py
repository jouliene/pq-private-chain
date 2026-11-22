"""Structured transition and masking checks; these clear internal checks are separate from proof replay."""
import hashlib
import secrets
import numpy as np
from cbip import Context
from parents import PathLayout
from rounds import RC,forward,lanes,linear_map_weights,state_projection
from runtime import Transcript, U, eq_table, mul, random_fields, xor


def parent(level,cur,sib,d):
    children = sib+cur if d else cur+sib
    return hashlib.shake_256(bytes([241,7,level])+children).digest(64)


def fixture(start,depth):
    child = secrets.token_bytes(64)
    private = bytearray(child)
    for i in range(depth):
        sib,d = secrets.token_bytes(64),secrets.randbits(1)
        private.extend(sib+bytes([d]))
        child = parent(start+i,child,sib,d)
    return bytes([start,depth])+child,bytes(private)


def valid_constraints(layout,mutation=None):
    local = Transcript(b"clear kernel discriminator")
    masks = random_fields((layout.ntrace,))
    if mutation:
        mutation(layout)
    ctx = Context(local,layout.nbits,layout.ntrace,layout.bits,masks)
    layout.constraints(ctx)
    weights,trace_weights,rhs = ctx.finalize()
    return (xor(weights[layout.bits!=0]) ^ xor(mul(trace_weights,masks))) == rhs


def main():
    initial = np.unpackbits(np.frombuffer(secrets.token_bytes(200),np.uint8),bitorder="little")
    rx = random_fields((11,))
    for mapped,coeff in zip(lanes(initial),linear_map_weights(rx)):
        assert xor(eq_table(rx)[:1600][mapped!=0]) == xor(coeff[:1600][initial!=0])
    # Ragged Z-axis and two independent terminal roots. Each root is independently frozen.
    specs,ws = zip(fixture(0,2),fixture(39,1))
    st = b"SGP1\2\0"+b"".join(specs)
    w = b"".join(ws)
    for k in (1,3,8,24):
        lay = PathLayout(st,k,w)
        for idx,digest_bits in lay.roots:
            assert np.array_equal(lay.bits[idx],digest_bits)
        assert valid_constraints(lay)
    # Alter one hidden round output with fixed public pad and root, and then a committed
    # boundary, a private direction and a capacity bit in distinct assignments.
    def corrupt_round(l):
        l.states[0,11,720] ^= 1
    def corrupt_boundary(l):
        l.bits[l.boundaries[0,1,1599]] ^= 1
    def corrupt_direction(l):
        l.bits[l.directions[1]] ^= 1
    def corrupt_capacity(l):
        l.bits[l.boundaries[1,0,1301]] ^= 1
    for change in (corrupt_round,corrupt_boundary,corrupt_direction,corrupt_capacity):
        assert not valid_constraints(PathLayout(st,3,w),change)
    print("ragged batches at K=1,3,8,24; linear-map transposes; two public roots; four corruptions passed")


if __name__ == "__main__":
    main()
