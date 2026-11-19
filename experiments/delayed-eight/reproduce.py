"""Build both registered cryptographic programs and reproduce the D8 historical-validation decision."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys

HERE=Path(__file__).resolve().parent
DIRECT=HERE.parent/"payment-architecture/direct"


def call(path,*args):
    subprocess.run([sys.executable,"-IB",str(path),*map(str,args)],check=True)


def run(work,public_only):
    os.umask(0o077)
    work.mkdir(parents=True,exist_ok=False)
    direct=work/"direct"
    call(DIRECT/"build.py",direct)
    vk=direct/"new-registration"
    dims=json.loads(subprocess.check_output([direct/"native","register",vk]))
    if dims!=json.loads((DIRECT/"REGISTER.json").read_bytes()) or (vk/"direct.vk").read_bytes()!=(DIRECT/"registry/direct.vk").read_bytes():
        raise ValueError("source-derived inner verifier mismatch")
    net=work/"network"
    call(HERE/"stage.py",direct,net,"--approve-native-sha",sha256((direct/"native").read_bytes()).hexdigest())
    outer=work/"outer"
    call(HERE/"crypto/build.py",direct/"upstream",direct/"target",outer)
    keys=work/"keys"
    result=json.loads(subprocess.check_output([sys.executable,"-IB",HERE/"crypto/register.py",outer,keys]))
    expected=json.loads((HERE/"crypto/registry.json").read_bytes())
    if any(result[k]!=expected[k] for k in ("key_sha256","parameters","dimensions")):
        raise ValueError("source-derived outer verifier mismatch")
    (work/"REGISTER.json").write_text(json.dumps(result,indent=2)+"\n")
    runtime=work/"runtime"
    call(HERE/"install.py",outer,keys,runtime,"--approve-native-sha",sha256((outer/"native").read_bytes()).hexdigest())
    if public_only:
        call(HERE/"replay.py",net,runtime,HERE/"evidence",work/"replay")
        return
    call(HERE/"live.py",net,work/"home",work/"live")
    call(HERE/"crypto/run.py",outer,keys,net,work/"live/packets",work/"cert")
    call(HERE/"exercise.py",net,"accept",work/"home",work/"live",runtime,work/"cert",work/"accept")
    call(HERE/"replay.py",net,runtime,work/"accept",work/"replay")
    call(HERE/"costs.py",work/"live",work/"cert/CERTIFICATES.json",work/"accept/ACCEPT.json",work/"COSTS.json")


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("work",type=Path);p.add_argument("--public-only",action="store_true")
    a=p.parse_args();run(a.work.resolve(),a.public_only)
