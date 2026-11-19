"""Build and verify the direct payment candidate in a new research workspace."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

HERE=Path(__file__).resolve().parent
DIRECT=HERE/"direct"

def python(script,*args,output=None):
    return subprocess.run([sys.executable,"-IB",str(script),*map(str,args)],check=True,stdout=output)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("work",type=Path,help="new directory for the pinned source, native program, private wallet homes and public evidence")
    p.add_argument("--public-only",type=Path,help="replay an existing public core campaign, without creating wallets")
    args=p.parse_args()
    os.umask(0o077)
    work=args.work.resolve()
    work.mkdir(parents=True,exist_ok=False)
    python(DIRECT/"build.py",work)
    native=work/"native"
    digest=hashlib.sha256(native.read_bytes()).hexdigest()
    if digest!=json.loads((work/"BUILD.json").read_bytes())["binary_sha256"]:
        raise ValueError("local source-built binary hash")
    derived=work/"derived-keys"
    registration=json.loads(subprocess.check_output([native,"register",derived],
        env=dict(os.environ,RAYON_NUM_THREADS="2")))
    if (registration!=json.loads((DIRECT/"REGISTER.json").read_bytes()) or
        (derived/"direct.vk").read_bytes()!=(DIRECT/"registry/direct.vk").read_bytes()):
        raise ValueError("fresh circuit differs from registered dimensions or verifier bytes")
    python(DIRECT/"stage.py",work,"--approve-native-sha",digest)
    deploy=work/"network"
    capture=args.public_only.resolve() if args.public_only else work/"public"
    if not args.public_only:
        python(DIRECT/"campaign.py",deploy,work/"private-home",capture)
    with (work/"PUBLIC-REPLAY.json").open("x") as stream:
        python(DIRECT/"replay.py",deploy,capture,output=stream)
    if not args.public_only:
        python(DIRECT/"busy.py",deploy,work/"busy-private-home",work/"busy-public")
    print("Independently replayed public core evidence:",work/"PUBLIC-REPLAY.json")

if __name__=="__main__":
    main()
