"""Compare both frozen programs on complete funded-shaped witnesses and real published path data."""
import argparse
import copy
from hashlib import sha256
import json
from pathlib import Path
import secrets
import struct
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import encoding as e
import packed
sys.path.insert(0,str(e.EX/"funded-whir/relation"))
from controls import fixture, projection, sponge

f=e.f
W=101


def receipt_digest(params,receipts):
    if len(receipts)!=3584:
        raise ValueError("receipt width")
    raw=b"qnero/ct"+struct.pack("<I",2)
    for off in (0,1792):
        raw+=struct.pack("<I",1792)+receipts[off:off+1792]
    raw+=b"\1"
    raw+=bytes(-len(raw)%4)
    return sponge(params,[v for v, in struct.iter_unpack("<I",raw)])


def full(suite,params,w,programs,receipts):
    e.canonical(w)
    reference=w["public"]
    assert receipt_digest(params,receipts)==reference[22:26]
    changed=bytearray(receipts)
    changed[-1]^=1
    assert receipt_digest(params,bytes(changed))!=reference[22:26]
    roots=[]
    for compact,registered in zip((False,True),programs,strict=True):
        c,materialized=e.compile_program(suite,params,w,compact,register=True)
        assert materialized==registered and not c.failures and e.evaluate(registered,c.z,reference)
        assert all(r==tuple(w["header"][13:17]) for r,n in zip(c.path_roots,w["inputs"],strict=True) if not n["dummy"])
        roots.append(c.path_roots)
        groups=packed.pack(registered,c.z,W)
        assert packed.verify(registered,groups,reference,W)
        assert len(groups["w"])>len(c.z)-1-f.PUBLIC[suite]
        groups["w"][-1]=1
        assert not packed.verify(registered,groups,reference,W)
        groups["w"][-1]=0
        # A local nonlinear constraint still passes after replacing its inputs/output coherently.
        # The independent global wiring check must reject the replacement.
        if compact:
            groups["x"][0]=(groups["x"][0]+1)%f.P
            groups["y"][0]=pow(groups["x"][0],7,f.P)
        else:
            groups["a"][0]=(groups["a"][0]+1)%f.P
            groups["c"][0]=groups["a"][0]*groups["b"][0]%f.P
        assert not packed.verify(registered,groups,reference,W)
    assert roots[0]==roots[1]
    return dict(public_words=len(reference),packing_width=W,both_frozen_shapes_identical_to_registration=True,
                both_accept_all_full_witness_rows=True,all_real_paths_match_authenticated_root=True,
                direct_and_quadratic_all_path_roots_equal=True,both_packed_global_maps_checked=True,
                coherent_local_port_substitution_rejected=True,nonzero_padded_word_rejected=True,
                ordered_receipt_hash_matches=True,changed_receipt_rejected=True)


def synthetic(params,programs):
    out={}
    for suite in e.REG:
        w=fixture(suite)
        receipts=bytes((i%251) for i in range(3584))
        w["ct_digest"]=receipt_digest(params,receipts)
        projection(params,w,tree=True)
        status=full(suite,params,w,programs[suite],receipts)
        for field in ("asset","depth","dummy","fee","header","key_or_delta","currency","native_overspend","native_range","nullifier"):
            test=copy.deepcopy(w)
            if field=="asset":
                test["asset_id"][0]=1<<63
            elif field=="depth":
                test["inputs"][0]["positions"][0]^=1
            elif field=="dummy":
                test["inputs"][0]["dummy"]=True
            elif field=="fee":
                test["fee"]=4
            elif field=="header":
                test["header"][13]^=1
            elif field=="key_or_delta":
                if suite=="MNG1": test["delta"]=1
                else: test["auth_key"][0]=1<<32
            elif field=="currency":
                test["outputs"][0]["token"]+=1
            elif field=="native_overspend":
                test["outputs"][0]["value"]+=1
            elif field=="native_range":
                test["inputs"][0]["value"]+=1<<62
                test["outputs"][0]["value"]+=1<<62
            else:
                test["public"][5]=f.P
            if field=="nullifier":
                try:e.canonical(test)
                except ValueError:continue
                raise ValueError("noncanonical public word accepted")
            if field in ("asset","dummy","fee","key_or_delta","currency","native_overspend","native_range"):
                # Remove failure due to stale public hashes from the independent negative.
                projection(params,test,tree=True)
            for direct in (False,True):
                c=e.compile_program(suite,params,test,direct)
                assert c.failures,field
        assert receipt_digest(params,receipts[1792:]+receipts[:1792])!=w["ct_digest"]
        out[suite]=dict(**status,negative_controls=10,swapped_receipts_rejected=True)
    return out


def inner(raw):
    # Selected prefix fixtures include MSP1 and legacy AST1, with SWF1 in the extension.
    if raw.startswith(b"SWF1\1"):
        raw=raw[107+17088:]
    if raw.startswith(b"MSP1\1"):
        raw=raw[6+(32+8+32+17088 if raw[5] in (2,3) else 0):]
    assert raw[:5] in (b"SLG1\1",b"MNG1\1",b"AST1\1")
    n=34 if raw[:4]==b"SLG1" else 31
    size=int.from_bytes(raw[5:9],"little")
    end=9+size
    assert len(raw)==end+3584 and int.from_bytes(raw[end-8*n-8:end-8*n],"little")==n
    return list(struct.unpack(f"<{n}Q",raw[end-8*n:end])),raw[end:]


def tree(params,leaves,selected):
    nodes=leaves[:]
    index=selected
    path=[]
    slots=[]
    while True:
        up=[]
        for j in range(0,len(nodes),4):
            group=nodes[j:j+4]
            group+= [bytes(32)]*(4-len(group))
            ordered=sorted(group)
            if j<=index<j+4:
                pos=ordered.index(nodes[index])
                path.append([list(struct.unpack("<4Q",d)) for d in ordered[:pos]+ordered[pos+1:]])
                slots.append(pos)
            up.append(struct.pack("<4Q",*sponge(params,list(struct.unpack("<16Q",b"".join(ordered))))))
        index//=4
        if len(up)==1:
            return up[0],path,slots
        nodes=up


def public_capture(params,events):
    s=json.loads((events/"SOURCE.json").read_text())
    funded=s["common"]
    root_before=bytes.fromhex(funded["tip"])
    tip=root_before
    net=bytes.fromhex(s["network"])
    blocks=[]
    while tip!=sha256(b"AST1/PoW/genesis/v1\0"+net).digest():
        raw=(events/"blocks"/(tip.hex()+".bin")).read_bytes()
        work=sha256(b"PQDEV1/work\0"+sha256(b"PQDEV1/template\0"+raw[:-8]).digest()+raw[-8:]).digest()
        assert work==tip and int.from_bytes(tip,"big")<2**234 and raw[:41]==b"ASTPOW01"+net+bytes([22])
        blocks.append(raw)
        tip=raw[41:73]
    leaves=[]
    reward_positions=[]
    for h,raw in enumerate(reversed(blocks),1):
        assert int.from_bytes(raw[73:77],"little")==h and raw[213]<=4
        off=214
        for _ in range(raw[213]):
            n=int.from_bytes(raw[off:off+4],"little")
            off+=4
            words,cts=inner(raw[off:off+n])
            assert receipt_digest(params,cts)==words[22:26]
            leaves.extend(struct.pack("<4Q",*words[i:i+4]) for i in (13,17))
            off+=n
        assert off==len(raw)-8
        assert int.from_bytes(raw[109:117],"little")>=100
        reward_positions.append(len(leaves))
        leaves.append(raw[117:149])
        assert tree(params,leaves,0)[0]==raw[181:213]
    hdr=bytes.fromhex(funded["header"])
    assert len(leaves)==funded["notes"] and hdr[-32:]==blocks[0][181:213]
    chosen=secrets.choice(reward_positions)
    expected,neighbors,positions=tree(params,leaves,chosen)
    sample=dict(siblings=neighbors,positions=positions)
    for cls in (e.Circuit,e.Compact):
        c=cls([],params,None)
        leaf=c.wires(list(struct.unpack("<4Q",leaves[chosen])),4)
        flags=[c.bit(c.wire(int(j<len(neighbors)))) for j in range(f.DEPTH)]
        actual=c.path(leaf,sample,flags)
        c.equal4(actual,c.wires(list(struct.unpack("<4Q",expected)),4))
        assert not c.failures
        changed=copy.deepcopy(sample)
        changed["siblings"][0][0][0]=(changed["siblings"][0][0][0]+1)%f.P
        alternative=c.path(leaf,changed,flags)
        c.equal4(alternative,c.wires(list(struct.unpack("<4Q",expected)),4))
        assert c.failures
    pairs=[]
    bundle=(events/"released.swap").read_bytes()
    assert bundle[:5]==b"SWB1\1"
    off=5
    for _ in range(2):
        n=int.from_bytes(bundle[off:off+4],"little")
        pairs.append(bundle[off+4:off+4+n])
        off+=4+n
    assert off==len(bundle)
    released=[(events/"ordinary.released").read_bytes(),*pairs,(events/"restored-onward.transfer").read_bytes()]
    group=(events/"candidate.swap").read_bytes()
    assert group[:5]==b"FWB1\1"
    off=5
    legs=[]
    for _ in range(2):
        n=int.from_bytes(group[off:off+4],"little")
        legs.append(group[off+4+107+17088:off+4+n])
        off+=4+n
    assert off==len(group)
    proposed=[(events/"ordinary.candidate").read_bytes(),*legs,(events/"onward.candidate").read_bytes()]
    for i,(orig,other) in enumerate(zip(released,proposed,strict=True)):
        words,cts=inner(orig)
        n=len(words)
        assert other[:5]==(b"FWT1\1" if n==31 else b"FWL1\1")
        assert other[9:9+8*n]==struct.pack(f"<{n}Q",*words) and other[-3584:]==cts
        assert receipt_digest(params,cts)==words[22:26] and words[21]==(3,0,3,3)[i]
        if i<3:
            assert words[4]==funded["height"] and struct.pack("<4Q",*words[:4])==bytes.fromhex(funded["anchor"])
        if n==31: assert words[26:]==[0]*5
        else: assert all(v<2**32 for v in words[26:])
    return dict(common_tip=root_before.hex(),pow_blocks=len(blocks),full_depth_slots_evaluated=20,
                published_public_vectors_compared=[31,34,34,31],all_historical_funded_roots_match=True,
                both_path_encodings_match_selected_public_root=True,positive_mined_reward_path=True,both_refuse_changed_sibling=True,
                ordered_receipt_hashes_match=True)


if __name__=="__main__":
    if not __debug__:raise SystemExit("enable assertions")
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("constants",type=Path)
    p.add_argument("--events",type=Path)
    args=p.parse_args()
    params=f.constants(args.constants)
    _,programs=e.registration(params)
    result={"synthetic":synthetic(params,programs)}
    if args.events:result["public_funded_path"]=public_capture(params,args.events)
    print(json.dumps(result,indent=2))
