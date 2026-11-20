"""Selected exact-price profiles from the deterministic parameter search."""
import json
from search import search
from model import cost, CAP


def summary(rows):
    return {f"up_to_2^{k}": min((r for r in rows if r["profile"]["N"]<=1<<k),
            key=lambda x:x["proof_B"]) for k in [12,16,19,20,24,32,48,63]}


def results():
    out = {}
    for suite in ["MNG1","SLG1"]:
        for enc in ["r1cs","degree7"]:
            label=suite+"_"+enc
            rows = search(suite,enc)
            selected = summary(rows)
            out[label] = {key: dict(profile=r["profile"],proof_B=r["proof_B"])
                          for key,r in selected.items()}
            out[label]["practical_2^20_components"]=selected["up_to_2^20"]
            out[label]["first_grid_height_under_signed_proof_cap"]=next((
                r["profile"]["N"].bit_length()-1 for r in rows if r["proof_B"]<=CAP),None)
    out["shared_s101_ell25_N2^20"] = {suite: cost(suite,"degree7",20,101,25)
                                      for suite in ["MNG1","SLG1"]}
    for name,digest,target in [("sha3_384",48,256),("stage768",64,768)]:
        out[name]={k:dict(profile=r["profile"],proof_B=r["proof_B"])
                   for k,r in summary(search("SLG1","degree7",digest=digest,target=target)).items()}
    return out


if __name__=="__main__":
    print(json.dumps(results(),indent=2))
