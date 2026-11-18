"""Prove the previously published synthetic fixture through a private stdin channel."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT/"scripts"))
import common

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--installation",required=True,type=Path)
    p.add_argument("--approve-installation",required=True)
    p.add_argument("--binary",required=True,type=Path)
    p.add_argument("--output",required=True,type=Path)
    a=p.parse_args()
    install=common.load_installation(a.installation,a.approve_installation)
    assert Path(install["repository"])==ROOT
    ref=Path(install["source_root"])/"experiments/compact-all-payments-v3/reference.py"
    spec=importlib.util.spec_from_file_location("public_cfw_fixture",ref)
    ref=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ref)
    bundle,_=ref.linked()
    assert hashlib.sha256(ref.canonical(bundle)).hexdigest()=="9d8dde618ce9ce60579d23549f552ff104ccfb8023a5fbdee0fbb1dfa8c95a95"
    fixture=bundle["fixtures"][2]
    a.output.mkdir(exist_ok=False)
    statement=a.output/"public.statement"
    proof=a.output/"public.proof"
    statement.write_bytes(bytes.fromhex(fixture["statement_hex"]))
    result={}
    for mode in ("prove","verify"):
        with tempfile.TemporaryDirectory() as td:
            timing=Path(td)/"time"
            cmd=["/usr/bin/time","-f","%U %S %e %M","-o",str(timing),str(a.binary.resolve()),mode,str(statement),str(proof)]
            proc=subprocess.run(cmd,input=ref.canonical(fixture) if mode=="prove" else b"",stdout=subprocess.PIPE,check=True)
            info=json.loads(proc.stdout)
            user,system,wall,rss=timing.read_text().split()
            info.update(process_user_s=float(user),process_system_s=float(system),process_wall_s=float(wall),maxrss_kib=int(rss))
            result[mode]=info
            (a.output/"RESULT.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps(result,sort_keys=True))

if __name__=="__main__":main()
