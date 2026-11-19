"""Build live TKN1 wallet roles with the published circuit, receipts and public verifier."""
import argparse
import importlib.util
import json
from pathlib import Path
import tempfile

HERE=Path(__file__).resolve().parent
CANDIDATE=HERE.parents[1]/"token-profile/candidate"

def prepare(work,upstream,target):
    spec=importlib.util.spec_from_file_location("token_spend_build",CANDIDATE/"build.py")
    b=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(b)
    with tempfile.TemporaryDirectory() as tmp:
        overlay=Path(tmp)
        for name in ("PROFILE.md","profile.rs","pair_codec.rs"):
            (overlay/name).symlink_to(CANDIDATE/name)
        (overlay/"wallet.rs").symlink_to(HERE/"wallet.rs")
        b.HERE=overlay
        b.run(work,upstream,target)
    receipt=json.loads((work/"BUILD.json").read_bytes())
    receipt["live_wallet_source_sha256"]=b.direct.sha(HERE/"wallet.rs")
    receipt["candidate_profile_sha256"]=b.direct.sha(CANDIDATE/"profile.rs")
    (work/"BUILD.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("work","upstream","target"):p.add_argument(name,type=Path)
    a=p.parse_args()
    prepare(a.work.resolve(),a.upstream.resolve(),a.target.resolve())
