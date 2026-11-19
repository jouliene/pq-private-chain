"""Reconstruct an AP branch from approved public genesis and complete ordered block bytes.

Use the registered verifier separately for proof acceptance. This independent parser
checks the authenticated effects, branch eligibility and upstream full-tree roots.
"""

import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import struct
import subprocess


P = 2**64 - 2**32 + 1
CT = 1792
U32 = struct.Struct("<I")
U64 = struct.Struct("<Q")
ZERO = bytes(32)


def counted_hash(domain, *parts):
    prefix = b"advancing-payments/1/" + domain + b"\x00"
    framed = b"".join(U64.pack(len(item)) + item for item in parts)
    for counter in range(2**32):
        result = hashlib.sha3_256(prefix + framed + U32.pack(counter)).digest()
        if all(v < P for v in struct.unpack("<4Q", result)):
            return result
    raise ValueError("hash counter exhausted")


def fields(raw, width):
    if len(raw) % width:
        raise ValueError("partial public word")
    return [raw[i:i+width] for i in range(0, len(raw), width)]


def proof_public(packet):
    if not packet:
        return []
    assert packet[:4] == b"APV2"
    k = packet[4]
    n, = U32.unpack(packet[5:9])
    assert 1 <= k <= 4 and n and len(packet) == 9+n+2*k*CT
    proof = packet[9:9+n]
    count = 26*k + 2*(k != 1)
    tail = proof[-8*(count+1):]
    actual, *words = struct.unpack(f"<{count+1}Q", tail)
    assert actual == count and all(w < P for w in words)
    if k != 1:
        assert words[:2] == [0x415056320001, k]
        words = words[2:]
    records = []
    for i in range(k):
        row = words[26*i:26*(i+1)]
        word = lambda j: struct.pack("<4Q", *row[j:j+4])
        records.append((word(0),row[4],(word(5),word(9)),(word(13),word(17)),row[21],word(22),
                        packet[9+n+2*CT*i:9+n+2*CT*(i+1)]))
    return records


def reference(exe, args, data):
    value = subprocess.check_output([str(exe), *args], input=data, timeout=60)
    return value.decode().splitlines()


def check(genesis, approved, profile, blocks, exe, database=None):
    assert hashlib.sha256(genesis).hexdigest() == approved and genesis[:8] == b"APGEN001"
    leaves = fields(genesis[12:], 32)
    assert len(leaves) == U32.unpack(genesis[8:12])[0] and leaves and len(set(leaves)) == len(leaves)
    assert all(leaf != ZERO and all(n < P for n in struct.unpack("<4Q",leaf)) for leaf in leaves)
    initial_count = len(leaves)
    genesis_root = bytes.fromhex(reference(exe,[str(initial_count)],b"".join(leaves))[0].split()[2])
    profile_id = bytes.fromhex(profile)
    assert len(profile_id) == 32
    prev_state = counted_hash(b"genesis-state",profile_id,genesis)
    headers = [ZERO+U32.pack(0)+prev_state+counted_hash(b"genesis-data",genesis)+genesis_root]
    headers.extend(block[8:140] for block in blocks)
    ids = [bytes.fromhex(line.split()[1]) for line in reference(exe,["--header-ids"],b"".join(headers))]
    assert len(ids) == len(headers)
    positions = [(cm,0) for cm in leaves]
    seen_cm = set(leaves)
    spent = {}
    history = []
    pairs = []
    expected_digests = []
    fees = 0
    widths = []
    ages = []
    counts = [initial_count]
    for h, body in enumerate(blocks,1):
        assert len(body) >= 152 and body[:8] == b"APBLOCK1"
        head = headers[h]
        assert head[:32] == ids[h-1] and U32.unpack(head[32:36])[0] == h
        nonce = body[140:148]
        raw = body[152:]
        assert len(raw) == U32.unpack(body[148:152])[0] and head[68:100] == counted_hash(b"block-data",nonce,raw)
        slots = proof_public(raw)
        widths.append(len(slots))
        transition = []
        for anchor, born, nfs, cms, fee, ct_digest, cts in slots:
            assert 1 <= h-born <= 8 and ids[born] == anchor and fee == 3
            ages.append(h-born)
            assert len(set(nfs)) == 2 and not any(nf in spent for nf in nfs)
            assert ZERO not in cms and len(set(cms)) == 2 and seen_cm.isdisjoint(cms)
            spent.update((nf,h) for nf in nfs)
            seen_cm.update(cms)
            positions.extend((cm,h) for cm in cms)
            leaves.extend(cms)
            fees += fee
            pairs.append(cts)
            expected_digests.append(ct_digest.hex())
            transition.extend((*nfs,*cms,U64.pack(fee)))
        prev_state = counted_hash(b"state",prev_state,U64.pack(len(leaves)),U64.pack(fees),b"".join(transition))
        assert prev_state == head[36:68]
        counts.append(len(leaves))
        history.append((h,ids[h],head,fees,len(leaves),body))
    roots = {}
    for row in reference(exe,[str(n) for n in sorted(set(counts))],b"".join(leaves)):
        n,depth,digest = row.split()
        roots[int(n)] = bytes.fromhex(digest)
    assert all(roots[n] == hdr[100:132] for n,hdr in zip(counts,headers,strict=True))
    if pairs:
        assert reference(exe,["--ciphertext-digests"],b"".join(pairs)) == expected_digests
    if database:
        db = sqlite3.connect(database.resolve().as_uri()+"?mode=ro",uri=True)
        try:
            assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
            assert db.execute("SELECT genesis,profile FROM config").fetchone() == (approved,profile_id)
            assert db.execute("SELECT pos,cm,h FROM outs ORDER BY pos").fetchall() == [
                (i,cm,h) for i,(cm,h) in enumerate(positions)]
            assert dict(db.execute("SELECT nf,h FROM spent")) == spent
            pruned, floor = db.execute("SELECT prune,floor FROM config").fetchone()
            assert 0 <= floor <= len(blocks) and floor >= len(blocks)-8
            chain = db.execute("SELECT h,id,header,fees,n,body,frontier FROM blocks ORDER BY h").fetchall()
            genesis_row = (0,ids[0],headers[0],0,initial_count,None)
            segment_roots = {}
            for saved,expected in zip(chain,[genesis_row,*history],strict=True):
                h, _, _, _, n, body = expected
                assert saved[:5] == expected[:5]
                if pruned and h < floor:
                    assert saved[5:] == (None,None)
                    continue
                assert saved[5] == body
                # Each base-four digit counts completed, adjacent perfect subtrees.
                # Compute each from its actual leaf segment with the upstream full tree.
                frontier = bytearray()
                size = 1
                while size <= n:
                    first = n - n % (4*size)
                    for j in range((n//size)%4):
                        start = first+j*size
                        if size == 1:
                            part = leaves[start]
                        else:
                            key = (start,size)
                            if key not in segment_roots:
                                line, = reference(exe,[str(size)],b"".join(leaves[start:start+size]))
                                segment_roots[key] = bytes.fromhex(line.split()[2])
                            part = segment_roots[key]
                        frontier.extend(part)
                    size *= 4
                assert bytes(frontier) == saved[6]
        finally:
            db.close()
    return {"blocks":len(blocks),"payments":sum(widths),"widths":widths,"anchor_ages":ages,
            "funded":len(leaves),"distinct_spent":len(spent),"fees":fees,
            "head_id":ids[-1].hex(),"head_sorted_funded_root":headers[-1][100:132].hex(),
            "distinct_full_tree_prefixes":len(roots),"receipt_digest_comparisons":len(expected_digests)}


if __name__ == "__main__":
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("reference",type=Path)
    ap.add_argument("genesis",type=Path)
    ap.add_argument("genesis_sha")
    ap.add_argument("profile_sha")
    ap.add_argument("blocks",type=Path,nargs="+")
    ap.add_argument("--database",type=Path)
    a=ap.parse_args()
    print(json.dumps(check(a.genesis.read_bytes(),a.genesis_sha,a.profile_sha,[p.read_bytes() for p in a.blocks],
                           a.reference.resolve(),a.database),indent=2))
