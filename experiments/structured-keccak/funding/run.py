"""Generate a new signed funding prefix, then prove and verify from disjoint inputs."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
EXPERIMENTS = HERE.parents[1]
sys.path.insert(0,str(EXPERIMENTS/"fresh-spend"/"binding"))
from relation import FundedTree, h


def main(directory,native):
    os.umask(0o077)
    directory.mkdir(mode=0o700)
    env = dict(PATH="/usr/bin:/bin",LANG="C",OPENBLAS_NUM_THREADS="1",SW_FIELD="gf256",
               PYTHONDONTWRITEBYTECODE="1",PYTHONPATH=str(native),
               FS_RECEIPT_NODE=os.environ["FS_RECEIPT_NODE"])
    public = directory/"public"
    helper = EXPERIMENTS/"hidden-membership"/"paths"/"funding_fixture.py"
    def funding(*args):
        return subprocess.check_output([sys.executable,"-IB",str(helper),*args],env=env)
    openings = json.loads(funding("new",public))
    pin = hashlib.sha256((public/"genesis.bin").read_bytes()).hexdigest()
    prefix = funding("ledger",public,pin)
    count = int.from_bytes(prefix[68:72],"little")
    if prefix[:4]!=b"HMF1" or count!=13 or len(prefix)!=72+128*count:
        raise ValueError("wrong funding shape")
    rows = [(prefix[k:k+64],prefix[k+64:k+128]) for k in range(72,len(prefix),128)]
    tree = FundedTree(rows)
    nfs = bytearray()
    for w in openings:
        i = w["index"]
        if (bytes.fromhex(w["occ"]),bytes.fromhex(w["cm"])) != rows[i]:
            raise ValueError("funding witness/source mismatch")
        w["path"] = [v.hex() for v in tree.path(i)]
        nfs.extend(h("nf",bytes.fromhex(w["ask"]),rows[i][0]))
    nf = public/"nullifiers.bin"
    nf.write_bytes(nfs)
    proof = public/"funded.proof"
    def role(action,*extra,private=None,reject=False):
        timing = directory/(action+("-alternate" if extra else "")+".time")
        cmd = ["/usr/bin/time","-f","%e %U %S %M","-o",str(timing),sys.executable,
               "-B",str(HERE/"role.py"),action,str(public),pin,str(nf),str(proof),*extra]
        args = dict(input=private) if private is not None else dict(stdin=subprocess.DEVNULL)
        p = subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=public,env=env,**args)
        if reject:
            if p.returncode!=1 or b"rejected" not in p.stderr.lower():
                raise RuntimeError("expected a cryptographic rejection")
        elif p.returncode:
            raise RuntimeError(f"funding {action} failed: {p.stderr[-300:].decode()}")
        wall,user,system,rss = timing.read_text().splitlines()[-1].split()
        return dict(wall_s=float(wall),user_s=float(user),sys_s=float(system),peak_KiB=int(rss)),p.stdout
    prover,_ = role("prove",private=json.dumps(openings).encode())
    verifier,raw = role("verify")
    reject,_ = role("verify","reverse",reject=True)
    result = dict(public_rows=count,capacity=1<<40,private_inputs=2,genesis_sha256=pin,
                  proof_B=proof.stat().st_size,proof_sha256=hashlib.sha256(proof.read_bytes()).hexdigest(),
                  geometry=json.loads(raw),prover=prover,verifier=verifier,other_branch_rejection=reject)
    (directory/"metrics.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))


if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: run.py NEW_DIRECTORY NATIVE_BUILD_DIRECTORY")
    main(Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve())
