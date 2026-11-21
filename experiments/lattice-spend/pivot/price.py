"""Apply the preceding TCitH-MT cost model to actual full recompilations."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import pivot as v

sys.path.insert(0,str(v.EX/"packed-tcith/model"))
import model
import search
import certify


def run(census):
    groups={(suite,k):row["packing_groups"] for suite,enc in census.items() for k,row in enc.items()}
    cost=v.bound_function(model.cost,dict(GROUPS=groups,CENSUS=census))
    grid=v.bound_function(search.search,dict(GROUPS=groups,cost=cost))
    exact=v.bound_function(certify.prove_small_trees, dict(GROUPS=groups,cost=cost))
    result={}
    for suite in v.PUBLIC:
        result[suite]={}
        for name in ("degree7","r1cs"):
            rows=grid(suite,name)
            selected={}
            for b in (16,17,18,19,20):
                r=next(r for r in rows if r["profile"]["N"]==1<<b)
                # Actual deployed ordinary MSP1 has another 6-byte envelope.
                r["proof_plus_fixed_frame_B"]+=32+(6 if suite=="MNG1" else 0)
                selected[str(b)]=r
            result[suite][name]=selected
    cap=241084-32
    leg=result["SLG1"]["degree7"]
    b=next(int(k) for k,r in leg.items() if r["proof_B"]<=cap)
    cert=exact("SLG1","degree7",b-1,cap)
    assert cert["fit_count"]==0
    joint={}
    for bits in (16,b):
        p=leg[str(bits)]["profile"]
        for suite in v.PUBLIC:
            r=cost(suite,"degree7",bits,p["s"],p["ell"])
            r["proof_plus_fixed_frame_B"]+=32+(6 if suite=="MNG1" else 0)
            joint[f"{suite}_at_{bits}"]=r
    return dict(census=census,by_height=result,first_fitting_signed_height=b,
                excludes_lower_heights=cert,shared_leg_geometry=joint)


if __name__=="__main__":
    a=argparse.ArgumentParser()
    a.add_argument("constants",type=Path)
    args=a.parse_args()
    params=v.f.constants(args.constants)
    tables={}
    for suite in v.PUBLIC:
        w=v.f.blank(suite)
        w["public"].extend([0]*4)
        tables[suite]={}
        for enc,cls in (("r1cs",v.Quadratic),("degree7",v.Compact)):
            c,program=v.compile_full(suite,params,w,cls,True)
            tables[suite][enc]=v.census(suite,c,program)
    print(json.dumps(run(tables),indent=2))
