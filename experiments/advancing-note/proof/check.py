"""Exercise N7P2's funded 2x2 relation with fresh private inputs held in memory."""
import argparse
import copy
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

def run(binary, out, positive_only=False, single=False):
    out.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, RAYON_NUM_THREADS=os.environ.get("RAYON_NUM_THREADS", "4"))
    engine = subprocess.Popen([binary, "eval-stream"], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, text=True, env=env)
    def evaluate(op, **args):
        engine.stdin.write(json.dumps(dict(op=op, **args)) + "\n")
        engine.stdin.flush()
        return json.loads(engine.stdout.readline())
    def fresh():
        return [secrets.randbits(63) for _ in range(7)]
    def issue(sk, amounts):
        return {"owner":evaluate("owner",sk=sk), "salt":fresh(), "asset":[19,3,0,0,0,0,0,0],
                "native":amounts[0],"token":amounts[1]}
    sk=fresh()
    ins=[issue(sk,(5,11)),issue(sk,(7,23))]
    if single:
        ins=[issue(sk,(12,34))]
    outs=[issue(fresh(),(4,13)),issue(sk,(5,21))]
    commitments=[evaluate("note",note=n) for n in ins]
    empty=evaluate("empty")
    right=empty if single else commitments[1]
    paths=[[right]] if single else [[right],[commitments[0]]]
    root=evaluate("parent",level=0,left=commitments[0],right=right)
    for level in range(1,40):
        empty=evaluate("parent",level=level-1,left=empty,right=empty)
        for path in paths:
            path.append(empty)
        root=evaluate("parent",level=level,left=root,right=empty)
    statement=dict(root=root,count=len(ins),fee=3,context=[secrets.randbits(32) for _ in range(12)],
                   nullifiers=[evaluate("nf",sk=sk,index=i,commitment=cm) for i,cm in enumerate(commitments)],
                   outputs=[evaluate("note",note=n) for n in outs])
    if single:
        pad=evaluate("padding",sk=sk,nullifier=statement["nullifiers"][0])
        statement["nullifiers"].append(pad)
    witness=dict(inputs=[dict(note=n,sk=sk,index=i,path=path) for i,(n,path) in enumerate(zip(ins,paths))],outputs=outs)
    engine.stdin.close()
    assert engine.wait()==0
    cmd=[str(binary)]
    st=out/"statement.json"
    st.write_text(json.dumps(statement)+"\n")
    proof=out/"proof.bin"
    def invoke(role, stfile, pfile, private=None, expected=True):
        start=time.monotonic()
        proc=subprocess.run(cmd+[role,str(stfile),str(pfile)],input=json.dumps(private) if private else None,
                            text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE, env=env)
        success=proc.returncode==0
        if success!=expected:
            raise RuntimeError(f"{role} returned {proc.returncode}, expected success={expected}; {proc.stderr[:200]}")
        return {"exit_code":proc.returncode,"elapsed_s":time.monotonic()-start,
                "meter":json.loads(proc.stdout) if success else None}
    evidence={"prove":invoke("prove",st,proof,witness),"verify":invoke("verify",st,proof),"controls":{}}
    if positive_only:
        (out/"result.json").write_text(json.dumps(evidence,indent=2)+"\n")
        print(json.dumps(evidence))
        return
    service=subprocess.Popen(cmd+["verify-stream"], stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL,text=True,env=env)
    ready=json.loads(service.stdout.readline())
    assert ready["ready"] and ready["registered_vk_sha3_384"]==evidence["verify"]["meter"]["registered_vk_sha3_384"]
    def request(expected, other, file=proof):
        service.stdin.write(json.dumps({"statement":other,"proof":str(file)})+"\n")
        service.stdin.flush()
        result=json.loads(service.stdout.readline())
        if result["accepted"] != expected:
            raise RuntimeError("unexpected resident proof result")
        return result
    # One public canonical coordinate changes at a time; fee remains an allowed value.
    coordinates=[("root",i) for i in range(7)]+[("count",),("fee",)]+[("context",i) for i in range(12)]
    coordinates.extend((k,i,j) for k in ("nullifiers","outputs") for i in range(2) for j in range(7))
    for path in coordinates:
        other=copy.deepcopy(statement)
        node=other
        for key in path[:-1]:
            node=node[key]
        k=path[-1]
        node[k]=0 if k=="fee" else node[k]+1 if k=="count" else node[k]^1
        request(False,other)
    request(True,statement)
    for i,raw in enumerate((b"", proof.read_bytes()[:-1], proof.read_bytes()+b"x")):
        badproof=out/f"malformed{i}.bin"
        badproof.write_bytes(raw)
        request(False,statement,badproof)
        badproof.unlink()
    request(True,statement)
    service.stdin.close()
    assert service.wait()==0
    evidence["controls"]["public_words_rejected"]=len(coordinates)
    evidence["controls"]["malformed_encodings_rejected"]=3
    evidence["controls"]["service_survived_rejections"]=True
    # A mismatching statement must fail also when its transcript is chosen before proving.
    for field in ("root","nullifiers","outputs"):
        wrong=copy.deepcopy(statement)
        if field=="root":
            wrong[field][0]^=1
        else:
            wrong[field][-1][0]^=1
        changed=out/"wrong.json"
        changed.write_text(json.dumps(wrong))
        evidence["controls"]["prove_wrong_"+field]=invoke("prove",changed,out/"rejected.bin",witness,expected=False)
        changed.unlink()
    for label,edit in [
        ("ownership",lambda w:w["inputs"][0]["sk"].__setitem__(0,w["inputs"][0]["sk"][0]^1)),
        ("position",lambda w:w["inputs"][0].update(index=2)),
        ("duplicate",lambda w:w.update(inputs=[copy.deepcopy(w["inputs"][0])]*2)),
        ("missing_all",lambda w:w.update(inputs=[])),
        ("inflation",lambda w:w["outputs"][0].update(native=5)),
        ("asset",lambda w:w["outputs"][0]["asset"].__setitem__(0,20)),
        ("path",lambda w:w["inputs"][0]["path"][14].__setitem__(0,w["inputs"][0]["path"][14][0]^1)),
        ("range",lambda w:w["outputs"][0].update(native=1<<62)),
    ]:
        bad=copy.deepcopy(witness)
        edit(bad)
        evidence["controls"][label]=invoke("prove",st,out/"rejected.bin",bad,expected=False)
    (out/"result.json").write_text(json.dumps(evidence,indent=2)+"\n")
    print(json.dumps(evidence))

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary",type=Path)
    parser.add_argument("output",type=Path)
    parser.add_argument("--positive-only",action="store_true")
    parser.add_argument("--single",action="store_true")
    args=parser.parse_args()
    run(args.binary.resolve(), args.output.resolve(), args.positive_only, args.single)
