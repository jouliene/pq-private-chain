"""Clear packed input wiring for FS01 parent Keccak-f[1600], with no proof-system dependency."""
import json
import secrets
import sys
from pathlib import Path


def gf16_mul(x,y):
    """Polynomial basis modulo X^16+X^12+X^3+X+1, as in the mixed profile."""
    z = 0
    while y:
        if y&1:
            z ^= x
        x <<= 1
        if x >> 16:
            x ^= 0x1100b
        y >>= 1
    return z


def words(data):
    if len(data) != 64:
        raise ValueError("expected 512-bit child")
    return [int.from_bytes(data[i:i+2],"little") for i in range(0,64,2)]


def packed_row(level,child,sibling,selector):
    if not 0 <= level < 40 or selector not in (0,1):
        raise ValueError("invalid parent level or selector")
    a,b = words(child),words(sibling)
    change = [gf16_mul(selector,u^v) for u,v in zip(a,b)]
    ordered = [u^d for u,d in zip(a,change)] + [v^d for v,d in zip(b,change)]
    row = [0x07f1,level^((ordered[0]&255)<<8)]
    row.extend((lo>>8)^((hi&255)<<8) for lo,hi in zip(ordered,ordered[1:]))
    row.extend([(ordered[-1]>>8)^0x1f00,0,0x8000])
    row.extend([0]*32)
    return row


ROT = (0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14)
MASK64 = (1<<64)-1


def rotate(x,n):
    return ((x<<n) | (x>>(64-n))) & MASK64


def digest_row(row):
    """Permute the explicitly supplied state. This path never re-pads the row."""
    if len(row) != 100:
        raise ValueError("wrong state shape")
    a = [sum(row[j+k]<<(16*k) for k in range(4)) for j in range(0,100,4)]
    lfsr = 1
    for _ in range(24):
        c = [a[x]^a[x+5]^a[x+10]^a[x+15]^a[x+20] for x in range(5)]
        b = [0]*25
        for y in range(5):
            for x in range(5):
                i = x+5*y
                v = a[i]^c[(x-1)%5]^rotate(c[(x+1)%5],1)
                b[y+5*((2*x+3*y)%5)] = rotate(v,ROT[i])
        a = [b[x+5*y]^((~b[(x+1)%5+5*y])&b[(x+2)%5+5*y])
             for y in range(5) for x in range(5)]
        for j in range(7):
            if lfsr&1:
                a[0] ^= 1<<((1<<j)-1)
            lfsr = ((lfsr<<1)&255)^(0x71 if lfsr&128 else 0)
    return b"".join(v.to_bytes(8,"little") for v in a[:8])


def reference_row(level,left,right):
    return bytes((0xf1,7,level))+left+right+bytes((0x1f,0,0,0,0x80))+bytes(64)


def serialized(row):
    return b"".join(v.to_bytes(2,"little") for v in row)


def exercise():
    sys.path.insert(0,str(Path(__file__).resolve().parents[3]/"fresh-spend"/"binding"))
    from relation import FundedTree, leaf, parent
    if [b for b in range(1<<16) if gf16_mul(b,b^1)==0] != [0,1]:
        raise AssertionError("boolean constraint failed")
    zero = bytes(64)
    for d in (0,1):
        for level in range(40):
            assert serialized(packed_row(level,zero,zero,d)) == reference_row(level,zero,zero)
        for slot in (0,1):
            for i in range(512):
                children = [zero,zero]
                children[slot] = (1<<i).to_bytes(64,"little")
                ordered = children[::-1] if d else children
                assert serialized(packed_row(21,*children,d)) == reference_row(21,*ordered)
    # Two distinct funded entries, both reaching the same independently computed sparse root.
    entries = [(secrets.token_bytes(64),secrets.token_bytes(64)) for _ in range(5)]
    tree = FundedTree(entries)
    for idx in secrets.SystemRandom().sample(range(len(entries)),2):
        cur = leaf(*entries[idx])
        for level,sibling in enumerate(tree.path(idx)):
            d = (idx>>level)&1
            ordered = (sibling,cur) if d else (cur,sibling)
            digest = digest_row(packed_row(level,cur,sibling,d))
            assert digest == parent(level,*ordered)
            cur = digest
        assert cur == tree.root
    # At every level cover both orientations, including the high index bits not set by 5 entries.
    for level in range(40):
        child,sib = secrets.token_bytes(64),secrets.token_bytes(64)
        for d in (0,1):
            assert digest_row(packed_row(level,child,sib,d)) == (
                parent(level,sib,child) if d else parent(level,child,sib))
    return {"boolean_values_checked":65536,"ordered_input_basis_checks":2048,
            "affine_offset_checks":80,"keccak_reference_checks":160,
            "depth40_paths_to_one_funded_root":2,"packed_products_per_parent":32,
            "packed_products_two_depth40_paths":2560,"additional_bitness_if_unavailable":80}


if __name__ == "__main__":
    print(json.dumps(exercise(),indent=2))
