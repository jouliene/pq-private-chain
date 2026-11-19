"""Check a local native executable and its build receipt against this checkout's approved devnet sources."""
import argparse
import hashlib
import json
from pathlib import Path


HERE=Path(__file__).resolve().parent
BASE=HERE.parents[1]/"experiments/advancing-payments"
PROFILE="af88a0ac0caa5f0aa27d38d687b6cc39495a0aa2659ed4a7e5e74653724cc1b1"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(binary, receipt):
    approved=json.loads((HERE/"evidence/BUILD.json").read_bytes())
    actual=json.loads(Path(receipt).read_bytes())
    # Different install directories can change machine code identities. Parameter registration
    # and source identities are stable and must independently match the reviewed checkout.
    if set(actual)!=set(approved) or any(actual[k]!=approved[k] for k in approved if k!="binary_sha256"):
        raise ValueError("unapproved native compiler, source, profile or dependency")
    if actual["registered_profile_sha256"]!=PROFILE or sha(BASE/"evidence/BUILD.json")!=actual["base_build_sha256"]:
        raise ValueError("APV2 source receipt")
    base=json.loads((BASE/"evidence/BUILD.json").read_bytes())
    for name,digest in base["sources_sha256"].items():
        if sha(BASE/"crypto"/name)!=digest:
            raise ValueError("stale APV2 build source: "+name)
    for name in ("build.py","wallet.rs"):
        if sha(HERE/name)!=actual["devnet_overlay_sha256"][name]:
            raise ValueError("stale devnet build source: "+name)
    digest=sha(Path(binary))
    if digest!=actual["binary_sha256"]:
        raise ValueError("binary does not match supplied build receipt")
    return digest


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary",type=Path);p.add_argument("receipt",type=Path)
    a=p.parse_args()
    print(validate(a.binary,a.receipt))
