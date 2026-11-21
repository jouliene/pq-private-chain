"""Independent branch replay plus complete synthetic funded-relation checks."""
import argparse
import copy
from hashlib import sha256
import json
from pathlib import Path
import secrets
import struct
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
import pivot as v
sys.path.insert(0,str(v.EX/"funded-whir/relation"))
from controls import fixture,projection,sponge
# Load predecessor capture parsers without colliding with this check.py.
import importlib.util
spec=importlib.util.spec_from_file_location("funded_public_check",v.EX/"packed-tcith/encoding/check.py")
pc=importlib.util.module_from_spec(spec)
spec.loader.exec_module(pc)

f=v.f


def encode(vals):
    return struct.pack("<4Q",*vals)


def decode(raw):
    return list(struct.unpack("<4Q",raw))


def h(params,tag,*parts):
    return sponge(params,[tag]+[x for part in parts for x in part])


def input_leaf(params,w,n):
    opened=h(params,f.OPEN,w["asset_id"] if n["token"] else [0]*4,[n["token"]],n["raw"])
    pk=h(params,f.PK,h(params,f.AK,n["ask"]),n["nk"])
    return encode(h(params,f.CM,h(params,f.NOTE,pk,n["rho"],opened),[n["value"]]))


def parent_old(params,children):
    return encode(sponge(params,list(struct.unpack("<16Q",b"".join(children)))))


def synthetic_paths(params,pair,parent,depth,branch=0):
    group=sorted([*pair,bytes(32),bytes(32)])
    current=list(pair)
    paths=[dict(siblings=[],positions=[]) for _ in pair]
    for level in range(depth):
        for i,node in enumerate(current):
            pos=group.index(node)
            paths[i]["siblings"].append([decode(x) for j,x in enumerate(group) if j!=pos])
            paths[i]["positions"].append(pos)
        root=parent(params,group)
        current=[root]*2
        group=sorted([root,*[encode([branch+11*level+j]*4) for j in (1,2,3)]])
    return root,paths


def branch_accept(public,branch_roots):
    return branch_roots.get(tuple(public[:5]))==encode(public[-4:])


def full(params,suite):
    receipts=bytes(x%251 for x in range(3584))
    w=fixture(suite)
    w["ct_digest"]=pc.receipt_digest(params,receipts)
    leaves=[input_leaf(params,w,n) for n in w["inputs"]]
    w["depth"]=20
    old,paths=synthetic_paths(params,leaves,parent_old,20)
    w["header"][13:17]=decode(old)
    for n,path in zip(w["inputs"],paths,strict=True):
        n.update(path)
    projection(params,w,tree=False)
    legacy=v.e.compile_program(suite,params,w,True)
    assert not legacy.failures
    original=w["public"][:]
    new,paths=synthetic_paths(params,leaves,v.parent,20)
    for n,path in zip(w["inputs"],paths,strict=True):
        n.update(path)
    w["public"].extend(decode(new))
    state={tuple(original[:5]):new}
    assert old!=new and branch_accept(w["public"],state)
    tests=[]
    for label,mutate in [
        ("root",lambda z:z["public"].__setitem__(-1,(z["public"][-1]+1)%f.P)),
        ("header",lambda z:z["header"].__setitem__(0,z["header"][0]+1)),
        ("sibling",lambda z:z["inputs"][0]["siblings"][19][0].__setitem__(0,0xFEED)),
        ("direction",lambda z:z["inputs"][0]["positions"].__setitem__(19,(z["inputs"][0]["positions"][19]+1)%4)),
        ("nullifier",lambda z:z["public"].__setitem__(5,(z["public"][5]+1)%f.P)),
        ("fee",lambda z:z.__setitem__("fee",4)),
        ("supply_or_authorizing_key",lambda z:z["public"].__setitem__(26,(z["public"][26]+1)%f.P)),
        ("native_conservation",lambda z:z["outputs"][0].__setitem__("value",z["outputs"][0]["value"]+1)),
        ("token_conservation",lambda z:z["outputs"][0].__setitem__("token",z["outputs"][0]["token"]+1)),
    ]:
        bad=copy.deepcopy(w)
        mutate(bad)
        tests.append((label,bad))
    roots={}
    for label,cls in (("r1cs",v.Quadratic),("degree7",v.Compact)):
        c,program=v.compile_full(suite,params,w,cls,True)
        assert not c.failures and v.e.evaluate(program,c.z,w["public"])
        packed=pc.packed.pack(program,c.z,117)
        assert pc.packed.verify(program,packed,w["public"],117)
        assert c.path_perms==80
        roots[label]=sha256(program).hexdigest()
    for label,bad in tests:
        c=v.compile_full(suite,params,bad)
        assert c.failures,label
    # Both branch roots can be internally well formed, even with the same
    # monetary witness. The node must obtain the chosen branch root itself.
    alt,other_paths=synthetic_paths(params,leaves,v.parent,20,branch=1)
    other=copy.deepcopy(w)
    other["public"][-4:]=decode(alt)
    for n,path in zip(other["inputs"],other_paths,strict=True):
        n.update(path)
    assert not v.compile_full(suite,params,other).failures
    assert not branch_accept(other["public"],state) and not branch_accept(w["public"],{})
    assert pc.receipt_digest(params,receipts[1792:]+receipts[:1792])!=w["public"][22:26]
    return dict(accepted_legacy_and_both_new_encodings=True,active_depth=20,
                emitted_programs=roots,original_effect_words_unchanged=len(original),
                public_words=len(w["public"]),independent_packed_verifier=True,
                rejected_mutations=[label for label,_ in tests],
                rejected_unselected_branch_with_valid_arithmetic=True,
                rejected_unknown_anchor=True,rejected_swapped_receipts=True)


def replay(params,events):
    src=json.loads((events/"SOURCE.json").read_text())
    common=src["common"]
    tip=bytes.fromhex(common["tip"])
    net=bytes.fromhex(src["network"])
    blocks=[]
    while tip!=sha256(b"AST1/PoW/genesis/v1\0"+net).digest():
        raw=(events/"blocks"/(tip.hex()+".bin")).read_bytes()
        work=sha256(b"PQDEV1/work\0"+sha256(b"PQDEV1/template\0"+raw[:-8]).digest()+raw[-8:]).digest()
        assert work==tip and int.from_bytes(work,"big")<2**234 and raw[:41]==b"ASTPOW01"+net+bytes([22])
        blocks.append(raw)
        tip=raw[41:73]
    leaves=[]
    rewards=[]
    roots=[]
    for height,block in enumerate(reversed(blocks),1):
        assert int.from_bytes(block[73:77],"little")==height
        off=214
        assert block[213]<=4
        for _ in range(block[213]):
            n=int.from_bytes(block[off:off+4],"little")
            public,cts=pc.inner(block[off+4:off+4+n])
            assert public[22:26]==pc.receipt_digest(params,cts)
            leaves.extend([encode(public[13:17]),encode(public[17:21])])
            off+=4+n
        assert off==len(block)-8 and int.from_bytes(block[109:117],"little")>=100
        rewards.append(len(leaves))
        leaves.append(block[117:149])
        assert pc.tree(params,leaves,0)[0]==block[181:213]
        roots.append(v.tree(params,leaves,0)[0])
    assert len(leaves)==common["notes"]
    checked=0
    for i in secrets.SystemRandom().sample(rewards,2):
        for cls,make,want in [(v.e.Compact,pc.tree,blocks[0][181:213]),
                              (v.Compact,v.tree,roots[-1]),(v.Quadratic,v.tree,roots[-1])]:
            root,neighbors,indices=make(params,leaves,i)
            assert root==want
            c=cls([],params,None)
            cm=c.wires(decode(leaves[i]),4)
            active=[c.bit(c.wire(int(j<len(indices)))) for j in range(20)]
            got=c.path(cm,dict(siblings=neighbors,positions=indices),active)
            c.equal4(got,c.wires(decode(want),4))
            assert not c.failures
            c.equal4(got,c.wires(decode(roots[-2]),4))
            assert c.failures
            checked+=1
    assert len(set(roots))==len(roots)
    return dict(common_tip=common["tip"],funded_blocks=len(blocks),funded_occurrences=len(leaves),
                new_root=roots[-1].hex(),legacy_root=blocks[0][181:213].hex(),
                independently_checked_positive_mined_occurrences=2,
                path_evaluations=checked,rejected_adjacent_branch_state_root=True,
                every_original_root_matches=True)


if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("constants",type=Path)
    ap.add_argument("events",type=Path)
    a=ap.parse_args()
    params=f.constants(a.constants)
    out={s:full(params,s) for s in v.PUBLIC}
    out["archived_branch"]=replay(params,a.events)
    print(json.dumps(out,indent=2))
