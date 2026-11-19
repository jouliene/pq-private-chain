"""Create an operator-approved certificate runtime using two locally checked verifier keys."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import shutil
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/"crypto"))
from certrole import checked_keys


def install(build,keys,target,approved):
    receipt=json.loads((build/"BUILD.json").read_text())
    if (build/"native").is_symlink() or sha256((build/"native").read_bytes()).hexdigest()!=approved or receipt["binary_sha256"]!=approved:
        raise ValueError("operator certificate binary identity mismatch")
    checked_keys(keys)
    target.mkdir()
    shutil.copy2(build/"native",target/"native")
    shutil.copytree(keys,target/"keys")
    (target/"approval.sha256").write_text(approved+"\n")


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for key in ("build","keys","target"):p.add_argument(key,type=Path)
    p.add_argument("--approve-native-sha",required=True)
    a=p.parse_args();install(a.build,a.keys,a.target,a.approve_native_sha)
