"""Compare the compiled monetary relation to the independent FS01 evaluator and actual wire encoder."""
from dataclasses import replace
import json
import secrets
import sys

from monetary import EXPERIMENTS, build_payment, private_witness, public_statement, ref, shape
import numpy as np

sys.path.insert(0,str(EXPERIMENTS/"fresh-spend/binding"))
from envelope import Body, pair_frame, SIGNATURE

K = 3


def random64():
    return secrets.token_bytes(64)


def fixture(inputs, outputs, common, active, fee):
    chain = random64()
    ask = random64()
    entries = []
    for native,asset,qty in inputs:
        occ,salt = random64(),random64()
        note = ref.Note(ref.owner(ask),native,asset,qty,salt)
        entries.append((occ,note))
    tree = ref.FundedTree([(occ,n.cm(chain)) for occ,n in entries])
    slots = [ref.Input(ask,n.native,n.asset,n.qty,n.salt,o,j,tree.path(j))
             for j,(o,n) in enumerate(entries)]
    if len(slots)==1:
        slots *= 2
    notes = tuple(ref.Note(random64(),native,asset,qty,random64()) for native,asset,qty in outputs)
    nfs = tuple(ref.h("dummy_nf" if i==1 and not active else "nf",x.ask,x.occ)
                for i,x in enumerate(slots))
    cms = tuple(n.cm(chain) for n in notes)
    # Receipt bytes here exercise the canonical encoder only. Sealing is external to the monetary relation.
    body = Body(1,0,random64(),fee,nfs,cms,(secrets.token_bytes(1792),secrets.token_bytes(1792)))
    intent = body.intent(chain,tree.root,tree.count)
    s = ref.Statement(chain,tree.root,tree.count,fee,nfs,cms,intent,ref.h("auth",ask,intent))
    return s,ref.Witness(tuple(slots),notes,active,common),body


def rows_satisfied(w):
    for columns,target in w.linear:
        if not np.array_equal(np.bitwise_xor.reduce([w.read(ids) for ids in columns],axis=0),target):
            return False
    for left,right,out in w.products:
        if not np.array_equal(w.read(left)&w.read(right),w.read(out)):
            return False
    for child,sibling,d,left in w.selectors:
        if not np.array_equal(w.read(left),w.read(sibling if w.values[d] else child)):
            return False
    return True


def verify_fixture(label,s,w,expect):
    if public_statement(s.encode()).encode()!=s.encode() or private_witness(w.encode()).encode()!=w.encode():
        raise AssertionError("binary parsing of FS01 data")
    try:
        hashes = ref.evaluate(s,w)
    except ValueError:
        oracle = False
    else:
        oracle = True
        if sum(n*(1+width//136) for (_,width),n in hashes.items())!=99:
            raise AssertionError("oracle SHAKE schedule")
    try:
        result = rows_satisfied(build_payment(s,K,w))
    except ValueError:
        result = False
    if (result,oracle)!=(expect,expect):
        raise AssertionError((label,result,oracle,expect))
    return label


def main():
    zero,aid = ref.ZERO,random64()
    pair = [(17,zero,0),(0,aid,60)]
    out = [(8,aid,25),(6,aid,35)]
    s,w,b = fixture(pair,out,aid,1,3)
    positives = [verify_fixture("two real inputs, token and native",s,w,True)]
    n,w1,_ = fixture([(17,zero,0)],[(14,zero,0),(0,zero,0)],zero,0,3)
    positives.append(verify_fixture("inactive duplicate, count one, empty change",n,w1,True))
    m64 = (1<<64)-1
    high,wh,_ = fixture([(m64,aid,m64),(m64,aid,m64)],
                         [(m64,aid,m64),(m64-1,aid,m64)],aid,1,1)
    positives.append(verify_fixture("65-bit true sums",high,wh,True))
    invalid = [
        ("fee mismatch",replace(s,fee=4),w),
        ("same scalar records forced inactive",s,replace(w,active=0)),
        ("wrong common asset",s,replace(w,asset=random64())),
        ("wrong intent",replace(s,intent=random64()),w),
        ("wrong authorization",replace(s,auth=random64()),w),
        ("duplicate public NF",replace(s,nfs=(s.nfs[0],s.nfs[0])),w),
        ("changed selected leaf",s,replace(w,inputs=(replace(w.inputs[0],occ=random64()),w.inputs[1]))),
        ("index outside public count",replace(s,count=1),w),
    ]
    for label,i,o,a,active,fee in [
        ("native wrap by 2^64",[(1,zero,0),(1,zero,0)],[(m64,zero,0),(3,zero,0)],zero,1,0),
        ("token wrap by 2^64",[(1,aid,1),(1,aid,1)],[(1,aid,m64),(1,aid,3)],aid,1,0),
        ("asset on zero qty",pair,[(8,aid,60),(6,aid,0)],aid,1,3),
        ("funded empty input",[(17,zero,0),(0,zero,0)],[(14,zero,0),(0,zero,0)],zero,1,3)]:
        sx,wx,_ = fixture(i,o,a,active,fee)
        invalid.append((label,sx,wx))
    negatives = [verify_fixture(name,sx,wx,False) for name,sx,wx in invalid]
    ranks = {}
    for count in (2, (1<<40)-1,1<<40):
        ranks[str(count)] = {str(k):shape(build_payment(replace(s,count=count),k))
                             for k in (1,2,3,4,6,8,12,24)}
    proof_B = ranks["2"][str(K)]["proof_B"]
    result = {"accepted_clear_traces":positives,"rejected_clear_traces":negatives,
              "two_input_shape":ranks["2"][str(K)],"shape_by_public_count_and_flattening":ranks}
    # Instantiate wire encoders on size markers only. These markers are never offered for admission.
    marker = bytes(proof_B)
    plain = b.core(s.auth,marker)
    bs = replace(b,role=1,terms=bytes(64),ephemeral=bytes(64),expiry=1)
    paired = replace(bs,role=2)
    c0,c1 = bs.core(s.auth,marker),paired.core(s.auth,marker)
    frame = pair_frame(c0,bytes(SIGNATURE),c1,bytes(SIGNATURE))
    result["FS01_extent_at_count_two"] = dict(proof=proof_B,ordinary=len(plain),
                                               signed_leg=len(c0)+SIGNATURE,pair=len(frame))
    print(json.dumps(result,indent=2))


if __name__ == "__main__":
    main()
