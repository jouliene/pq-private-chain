"""Public verifier for the measured Merkle and masked degree-check component."""
import hashlib
import json
import struct
import sys
from pathlib import Path

P = 2**64 - 2**32 + 1
N, COEFS, OPEN, INPUTS, MASKS = 2**20, 126, 25, 711, 33


def words(buf):
    return [v for v, in struct.iter_unpack("<Q", buf)]


def verify(data):
    offset = 0

    def read(count):
        nonlocal offset
        end = offset + count
        if end > len(data):
            raise ValueError("truncated")
        result = data[offset:end]
        offset = end
        return result

    root = read(64)
    xi = read(8 * COEFS * MASKS)
    digest = lambda d: hashlib.sha3_512(d).digest()
    challenges = hashlib.shake_256(b"I" + root + digest(b"D" + xi)).digest(1024)
    opened = set()
    for value in words(challenges):
        opened.add(value % N)
        if len(opened) == OPEN:
            break
    if len(opened) != OPEN:
        raise ValueError("challenge exhausted")
    material = hashlib.shake_256(b"G" + root).digest((INPUTS * MASKS + 64) * 8)
    gamma = [x for x in words(material) if x < P][:INPUTS * MASKS]
    coeffs = words(xi)
    if len(gamma) != INPUTS * MASKS or max(coeffs) >= P:
        raise ValueError("invalid coefficient")
    generator = pow(7, (P - 1) // N, P)
    hashes = {}
    for i in sorted(opened):
        row = read(32 + 8 * (INPUTS + MASKS))
        shares = words(row[32:])
        if max(shares) >= P:
            raise ValueError("invalid share")
        hashes[N + i] = digest(b"L" + row)
        x = pow(generator, i // 128 + (N // 128) * (i % 128), P)
        point = [pow(x, j, P) for j in range(COEFS)]
        for m in range(MASKS):
            lhs = sum(a*b for a,b in zip(point, coeffs[m*COEFS:(m+1)*COEFS], strict=True))
            gr = gamma[m*INPUTS:(m+1)*INPUTS]
            rhs = shares[INPUTS+m] + sum(a*b for a,b in zip(shares[:INPUTS], gr, strict=True))
            if (lhs-rhs) % P:
                raise ValueError("masked degree opening mismatch")
    siblings = 0
    while 1 not in hashes:
        parents = {}
        for i in sorted(hashes):
            if i // 2 in parents:
                continue
            other = hashes.get(i ^ 1)
            if other is None:
                other = read(64)
                siblings += 1
            pair = other + hashes[i] if i % 2 else hashes[i] + other
            parents[i // 2] = digest(b"N" + pair)
        hashes = parents
    if hashes[1] != root or offset != len(data):
        raise ValueError("Merkle root mismatch or trailing data")
    return dict(root=root.hex(), leaves=N, leaf_words=INPUTS+MASKS, opened=OPEN,
                degree_checks=OPEN*MASKS, frontier_hashes=siblings,
                component_transcript_B=len(data))


if __name__ == "__main__":
    print(json.dumps(verify(Path(sys.argv[1]).read_bytes()), indent=2))
