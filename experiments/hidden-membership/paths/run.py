"""Fresh private funded-path test with separate public checking and no private files."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parents[1]/"fresh-spend"/"binding"))
from relation import FundedTree, h


def run(work,profile):
    work.mkdir(mode=0o700)
    os.umask(0o077)
    fixture = work / "funding"
    helper = str(HERE / "funding_fixture.py")
    env = {"LANG":"C","OPENBLAS_NUM_THREADS":"1","FS_RECEIPT_NODE":os.environ["FS_RECEIPT_NODE"]}
    if profile == "mixed":
        env["PYTHONPATH"] = str(Path(os.environ["SW_NATIVE_DIR"]).resolve())
    openings = json.loads(subprocess.check_output(
        [sys.executable,"-IB",helper,"new",str(fixture)], env=env))
    pin = hashlib.sha256((fixture/"genesis.bin").read_bytes()).hexdigest()
    log = subprocess.check_output([sys.executable,"-IB",helper,"ledger",str(fixture),pin],env=env)
    if len(log)!=72+13*128 or log[:4]!=b"HMF1":
        raise ValueError("unexpected funding prefix")
    chain,count = log[4:68],int.from_bytes(log[68:72],"little")
    rows = [(log[j:j+64],log[j+64:j+128]) for j in range(72,len(log),128)]
    tree = FundedTree(rows)
    nfs = []
    for record in openings:
        i = record["index"]
        if rows[i] != (bytes.fromhex(record["occ"]),bytes.fromhex(record["cm"])):
            raise ValueError("opening does not match funded row")
        record["path"] = [v.hex() for v in tree.path(i)]
        nfs.append(h("nf",bytes.fromhex(record["ask"]),rows[i][0]))
    tags = work/"nullifiers.bin"
    tags.write_bytes(b"".join(nfs))
    def role(action, data, reverse=False):
        measure = work/(action+".time")
        cmd = ["/usr/bin/time","-f","%e %U %S %M","-o",str(measure),
               sys.executable,"-B",str(HERE/"role.py"),profile,action,str(fixture),pin,str(tags)]
        if reverse:
            cmd.append("reverse")
        return subprocess.run(cmd,input=data,stdout=subprocess.PIPE,check=True,env=env).stdout

    packet = role("prove",json.dumps(openings).encode())
    (work/"public.proof").write_bytes(packet)
    geometry = json.loads(role("verify",packet))
    if profile=="gf16":
        role("check-edges",json.dumps(openings).encode())
    role("reject",packet,reverse=True)
    def timing(action):
        wall,user,system,rss = (work/(action+".time")).read_text().split()
        return dict(wall_s=float(wall),user_s=float(user),sys_s=float(system),peak_KiB=int(rss))
    print(json.dumps(dict(profile=profile,public_rows=count,capacity=1<<40,private_inputs=2,proof_bytes=len(packet),
                          shape=geometry,prover=timing("prove"),verifier=timing("verify"),
                          other_branch_rejected=True,detached_edge_equations_tested=(profile=="gf16")),indent=2))


if __name__=="__main__":
    if len(sys.argv)!=3 or sys.argv[2] not in ("gf16","mixed"):
        raise SystemExit("expected NEW_DIRECTORY and gf16 or mixed")
    run(Path(sys.argv[1]).resolve(),sys.argv[2])
