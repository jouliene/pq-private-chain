"""Compile and price a proposed seven-capacity-word branch index. No funded proving."""
import argparse
import inspect
import io
import json
from pathlib import Path
import struct
import sys

EXPERIMENTS = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(EXPERIMENTS / "lattice-spend/pivot"))
import pivot
sys.path.insert(0, str(EXPERIMENTS / "funded-whir/relation"))
from controls import fixture, projection
sys.path.insert(0, str(EXPERIMENTS / "packed-tcith/model"))
import model
import search

f = pivot.f
e = pivot.e
PUBLIC = {k: n + 8 for k, n in f.PUBLIC.items()}
TAG = int.from_bytes(b"PQ4N/v2", "little")


def compress(level, children, zero, constant, add, permute):
    width = 4 if level == 1 else 7
    if len(children) != 4 or any(len(child) != width for child in children):
        raise ValueError("invalid parent dimensions")
    state = [zero]*12
    state[5], state[6] = constant(TAG), constant(level)
    data = [v for child in children for v in child]
    data += [zero]*(-len(data) % 5)
    for start in range(0, len(data), 5):
        state[:5] = [add(a,b) for a,b in zip(state[:5], data[start:start+5], strict=True)]
        state = permute(state)
    return state[:5] + permute(state)[:2]


class Wider(e.Compact):
    def path(self, cm, note, active):
        perms = self.permutations
        for level, use in enumerate(active, 1):
            w = len(cm)
            pos = note["positions"][level-1] if level <= len(note["positions"]) else 0
            sib = note["siblings"][level-1] if level <= len(note["siblings"]) else [[0]*w]*3
            if len(sib) != 3 or pos not in range(4):
                raise ValueError("invalid path")
            children = list(sib)
            children.insert(pos, [self.val(v) for v in cm])
            slots = [self.wires(a, w) for a in children]
            flags = [self.bit(self.wire(int(pos == j))) for j in range(4)]
            self.eq(f.total(flags), f.ONE)
            for flag, slot in zip(flags, slots):
                for x, y in zip(slot, cm, strict=True):
                    self.constrain(flag, f.sub(x,y), f.ZERO)
            def permute(state):
                self.permutations += 1
                return f.permute(self, state, self.parameters)
            root = compress(level, slots, f.ZERO, f.literal, lambda a,b:f.add((a,1),(b,1)), permute)
            old = cm + [f.ZERO]*(7-w)
            cm = [self.select(use, x, y) for x, y in zip(root, old, strict=True)]
        self.path_perms += self.permutations-perms
        return cm


class Scalar:
    """Evaluate the pinned permutation on plain limbs; no emitted wires."""
    def assign(self,a,b):
        return f.literal(a.get(0,0)*b.get(0,0) % f.P)
    def sbox(self,a):
        return f.literal(pow(a.get(0,0),7,f.P))


def example(params, suite):
    w = fixture(suite)
    projection(params, w, tree=True)
    children = w["inputs"][0]["siblings"][0][:]
    # The test fixture uses one common four-occurrence synthetic branch.
    # Recover its sorted first group from both cached paths plus two pads.
    first, second = w["inputs"]
    remaining = [v for v in second["siblings"][0] if any(v)]
    if len(remaining) != 1:
        raise ValueError("unexpected first-leaf fixture")
    children.insert(first["positions"][0],remaining[0])
    if sorted(children,key=lambda row:struct.pack("<4Q",*row)) != children:
        raise ValueError("incorrect ordered fixture")
    def numeric(s):
        return [v.get(0,0) for v in f.permute(Scalar(),list(map(f.literal,s)),params)]
    root = compress(1,children,0,int,lambda a,b:(a+b)%f.P,numeric)
    for level in range(2,21):
        row = sorted([root, *[[i+level]*7 for i in (1,2,3)]],
                     key=lambda v:struct.pack("<7Q",*v))
        pos = row.index(root)
        for note in w["inputs"]:
            note["positions"].append(pos)
            note["siblings"].append(row[:pos]+row[pos+1:])
        root = compress(level,row,0,int,lambda a,b:(a+b)%f.P,numeric)
    w["depth"] = 20
    w["public"] += root + [20]
    return w


def compile_wider(suite, params, w):
    source = inspect.getsource(f.compile_relation)
    for old,new in [
        ("zip(root, header[13:17])", "zip(root, pub[-8:-1], strict=True)"),
        ("c.eq(total(active), depth)", "c.eq(total(active), depth)\n    c.eq(depth, pub[-1])"),
    ]:
        assert source.count(old) == 1
        source = source.replace(old,new)
    namespace = dict(f.compile_relation.__globals__, Circuit=Wider, PUBLIC=PUBLIC)
    exec(compile(source, __file__, "exec"), namespace)
    out = io.BytesIO()
    c = namespace["compile_relation"](suite,params,w,out)
    raw = e.COMPACT + e.SHAPE.pack(PUBLIC[suite],len(c.z),c.rows) + out.getvalue()
    assert not c.failures and e.evaluate(raw,c.z,w["public"])
    for where in (-8,-1):
        changed = list(w["public"])
        changed[where] = (changed[where]+1)%f.P
        z = list(c.z)
        z[1+len(changed)+where] = changed[where]
        assert not e.evaluate(raw,z,changed)
    census = pivot.census(suite,c,raw)
    private = len(c.z) - PUBLIC[suite] - 1
    census["public_words"] = PUBLIC[suite]
    census["private_columns"] = census["packing_groups"][0] = private
    return census


def price(census):
    both = {suite:{"degree7":row} for suite,row in census.items()}
    groups = {(suite,"degree7"):row["packing_groups"] for suite,row in census.items()}
    cost = pivot.bound_function(model.cost, dict(GROUPS=groups,CENSUS=both))
    grid = pivot.bound_function(search.search, dict(GROUPS=groups,cost=cost))
    candidates = grid("SLG1","degree7",maxs=260,maxell=80)
    result = {}
    def point(height,s,ell):
        results = {}
        for suite in census:
            r = cost(suite,"degree7",height,s,ell)
            wrapper = (21060 if suite=="SLG1" else 3847) + 8*8
            results[suite] = dict(proof_bytes=r["proof_B"], fixed_bytes=wrapper,
                                  framed_bytes=wrapper+r["proof_B"], profile=r["profile"],
                                  leaf_field_bytes=r["work"]["leaf_share_payload_B"])
        results["signed_pair_bytes"] = 13 + 2*results["SLG1"]["framed_bytes"]
        return results
    result["old_geometry"] = point(18,117,32)
    selected = None
    for row in candidates:
        prof = row["profile"]
        h = prof["N"].bit_length()-1
        if row["proof_B"] + 21060 + 64 <= 262144 and selected is None:
            selected = h
        if h in (18,20) or h==selected:
            result[f"screen_height_{h}"] = point(h,prof["s"],prof["ell"])
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("poseidon_source", type=Path)
    args = p.parse_args()
    params = f.constants(args.poseidon_source)
    census = {suite:compile_wider(suite,params,example(params,suite)) for suite in PUBLIC}
    print(json.dumps(dict(census=census,pricing=price(census)),indent=2))
