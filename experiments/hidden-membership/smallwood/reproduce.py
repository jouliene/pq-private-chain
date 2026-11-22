"""Generate ephemeral fixtures, measure separate processes, and keep only public data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import subprocess
import sys
import tempfile
import time

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent.parent/"fresh-spend"/"binding"))
# Load the independently published project's hashlib-based FS01 relation despite a name collision.
import importlib.util
spec = importlib.util.spec_from_file_location("fs01_reference", Path(sys.path[0])/"relation.py")
reference = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = reference
spec.loader.exec_module(reference)


def call(action,statement,proof,witness=None,*,reject=False):
    start = time.perf_counter()
    p = subprocess.run([sys.executable,str(HERE/"role.py"),action,str(statement),str(proof)],
                       input=witness if witness is not None else b"",capture_output=True,cwd=statement.parent)
    if reject:
        if p.returncode != 1 or not any(msg in p.stderr for msg in
                (b"rejected",b"truncated proof",b"trailing bytes")):
            raise RuntimeError(f"unexpected verifier outcome: {p.returncode} {p.stderr[-200:]!r}")
        return p.stderr.decode().strip()
    if p.returncode:
        raise RuntimeError(p.stderr.decode())
    return {**json.loads(p.stdout),"process_wall_s":time.perf_counter()-start}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("public_directory",type=Path)
    parser.add_argument("--wide",action="store_true")
    args = parser.parse_args()
    directory = args.public_directory.resolve()
    directory.mkdir(parents=True,exist_ok=False)
    profile = "gf256" if args.wide else "gf16"
    os.environ["SW_FIELD"] = profile
    results = {"profile":profile,"python":sys.version.split()[0],"numpy":np.__version__,
               "cpu":platform.machine(),"runs":[]}
    choices = [(0,0),(0,1),(1,0),(1,1)]
    secrets.SystemRandom().shuffle(choices)
    for i,(d0,d1) in enumerate(choices):
        # One costly full-size fixture; all choices are exercised in the small-field run.
        if args.wide and i != 2:
            continue
        level = (0,7,12,38)[i]
        a,b,c = (secrets.token_bytes(64) for _ in range(3))
        first = reference.parent(level,b,a) if d0 else reference.parent(level,a,b)
        root = reference.parent(level+1,c,first) if d1 else reference.parent(level+1,first,c)
        statement,proof = directory/f"case{i}.statement", directory/f"case{i}.proof"
        statement.write_bytes(bytes([level])+root)
        inp = a+b+c+bytes([d0,d1])
        stat = {"level":level, "calibration_case":i,"prove":call("prove",statement,proof,inp)}
        # Case identifiers describe synthetic branch coverage in the aggregate report. Production
        # verifiers receive only a level, the expected root and proof.
        stat["verify"] = call("verify",statement,proof)
        data = proof.read_bytes()
        stat.update(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            bad,other = tmp/"modified.proof",tmp/"other.statement"
            other.write_bytes(bytes([level])+bytes([root[0]^1])+root[1:])
            stat["wrong_root"] = call("verify",other,proof,reject=True)
            other.write_bytes(bytes([(level+1)%39])+root)
            stat["wrong_level"] = call("verify",other,proof,reject=True)
            for label,raw in (("opening_mutation",data[:len(data)//2]+bytes([data[len(data)//2]^1])+data[len(data)//2+1:]),
                              ("truncated",data[:-1]),("trailing",data+b"\x00")):
                bad.write_bytes(raw)
                stat[label] = call("verify",statement,bad,reject=True)
            # Both individual rounds hash honest inputs. The next round uses a fresh digest
            # instead of the computed first output. Only the mandatory glue rows disagree.
            disjoint = secrets.token_bytes(64)
            while disjoint == first:
                disjoint = secrets.token_bytes(64)
            end = reference.parent(level+1,c,disjoint) if d1 else reference.parent(level+1,disjoint,c)
            other.write_bytes(bytes([level])+end)
            call("detached",other,bad,inp+disjoint)
            stat["detached_link"] = call("verify",other,bad,reject=True)
        results["runs"].append(stat)
        (directory/"metrics.json").write_text(json.dumps(results,indent=2)+"\n")
    print(json.dumps(results))


if __name__ == "__main__":
    main()
