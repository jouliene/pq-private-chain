"""Verify both roots over all common-prefix blocks and the selected swap extension."""

import argparse
from hashlib import sha256
from pathlib import Path
import importlib.util
import json
import struct
import sys

EX = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(EX / "funded-whir/relation"))
import frontend


def local_function(path, name):
    spec = importlib.util.spec_from_file_location("reference_" + path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, name)


sponge = local_function(EX / "funded-whir/relation/controls.py", "sponge")
inner = local_function(EX / "packed-tcith/encoding/check.py", "inner")


def node_hasher(constants, version):
    p = frontend.P
    start, middle, diag, end = constants
    tag = int.from_bytes(b"PQ4N/v1", "little")
    zero = bytes(32)

    def external(a):
        chunks = []
        for i in range(0, 12, 4):
            quad = a[i:i+4]
            chunks.append([sum(quad) + x + 2 * quad[(j+1) % 4] for j, x in enumerate(quad)])
        sums = [sum(column) for column in zip(*chunks)]
        return [(v + sums[j]) % p for chunk in chunks for j,v in enumerate(chunk)]

    def dense(a, keys):
        for offset in range(0, len(keys), 12):
            a = external([pow((v+k) % p, 7, p) for v,k in zip(a,keys[offset:offset+12],strict=True)])
        return a

    def node(children):
        padded = sorted(children + [zero] * (4-len(children)))
        message = struct.unpack("<16Q", b"".join(padded))
        assert all(x < p for x in message)
        if version == 1:
            return struct.pack("<4Q", *sponge(constants,list(message)))
        s = [0] * 8 + [tag,0,0,0]
        for offset in (0,8):
            for j in range(8):
                s[j] += message[offset + j]
            s = dense(external(s), start)
            for c in middle:
                s[0] = pow((s[0]+c) % p,7,p)
                total = sum(s)
                s = [(total+t*x) % p for x,t in zip(s,diag,strict=True)]
            s = dense(s,end)
        return struct.pack("<4Q", *s[:4])

    return node


class AppendTree:
    """Incrementally rehash only the incomplete group at each level."""

    def __init__(self, node):
        self.rows = [[]]
        self.node = node

    def append(self, leaf):
        row = self.rows[0]
        pos = len(row)
        row.append(leaf)
        for level in range(20):
            slot = pos // 4
            group = row[4*slot:4*slot+4]
            parent = self.node(group)
            if level+1 == len(self.rows):
                self.rows.append([])
            row = self.rows[level+1]
            if slot == len(row):
                row.append(parent)
            else:
                row[slot] = parent
            if len(row) == 1:
                return parent
            pos = slot
        raise ValueError("note capacity exceeded")


def block_id(raw):
    return sha256(b"PQDEV1/work\0" + sha256(b"PQDEV1/template\0"+raw[:-8]).digest()+raw[-8:]).digest()


def check(constants, events):
    snap = json.loads((events / "SOURCE.json").read_bytes())
    net = bytes.fromhex(snap["network"])
    tip = bytes.fromhex(snap["common"]["tip"])
    chronological = []
    while tip != sha256(b"AST1/PoW/genesis/v1\0"+net).digest():
        block = (events / "blocks" / (tip.hex()+".bin")).read_bytes()
        assert block_id(block) == tip and int.from_bytes(tip,"big") < (1<<234)
        chronological.append(block)
        tip = block[41:73]
    chronological.reverse()
    extra = (events / "released-swap.block").read_bytes()
    assert extra[41:73] == block_id(chronological[-1]) and int.from_bytes(block_id(extra),"big") < (1<<234)
    chronological.append(extra)
    trees = [AppendTree(node_hasher(constants,version)) for version in (1,2)]
    result = []
    spent = set()
    for height,block in enumerate(chronological,1):
        assert block[:41] == b"ASTPOW01"+net+bytes([22]) and int.from_bytes(block[73:77],"little") == height
        off = 214
        leaves = []
        for _ in range(block[213]):
            n = int.from_bytes(block[off:off+4],"little")
            words,_ = inner(block[off+4:off+4+n])
            for j in (5,9):
                nf = struct.pack("<4Q", *words[j:j+4])
                assert nf not in spent
                spent.add(nf)
            leaves.extend(struct.pack("<4Q",*words[j:j+4]) for j in (13,17))
            off += n+4
        assert off == len(block)-8
        leaves.append(block[117:149])
        for leaf in leaves:
            roots = [tree.append(leaf) for tree in trees]
        assert roots[0] == block[181:213] and roots[0] != roots[1]
        result.append(dict(height=height, leaves=len(trees[0].rows[0]), spent=len(spent),
                           spent_set_sha256=sha256(b"".join(sorted(spent))).hexdigest(),
                           old_root=roots[0].hex(), new_root=roots[1].hex(), tip=block_id(block).hex()))
    assert result[-2]["leaves"] == snap["common"]["notes"]
    assert result[-2]["spent"] == snap["common"]["spent"]
    assert result[-2]["spent_set_sha256"] == snap["common"]["spent_set_sha256"]
    completed = json.loads((events / "COMPLETE.json").read_bytes())
    assert result[-1]["tip"] == completed["swap_mined_at"]
    assert bytes.fromhex(snap["common"]["header"])[-32:].hex() == result[-2]["old_root"]
    return dict(prefix_blocks=len(chronological)-1, original_root_matches_including_extension=len(chronological),
                common=result[-2], selected_swap=result[-1])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("constants",type=Path)
    parser.add_argument("events",type=Path)
    args = parser.parse_args()
    print(json.dumps(check(frontend.constants(args.constants),args.events),indent=2))
