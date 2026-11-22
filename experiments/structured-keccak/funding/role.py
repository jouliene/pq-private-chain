"""Build and check a public-prefix-derived two-input funding statement."""
from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import sys

from plan import build
from argument import FLATTEN, run, shape

PREVIOUS = Path(__file__).resolve().parents[2] / "hidden-membership" / "paths"
spec = spec_from_file_location("signed_funding_replay", PREVIOUS/"role.py")
replay = module_from_spec(spec)
spec.loader.exec_module(replay)


def main():
    if len(sys.argv) not in (6,7) or (len(sys.argv)==7 and sys.argv[6]!="reverse"):
        raise ValueError("expected action, prefix directory, genesis pin, nullifier file and proof path")
    action,directory,pin,nf_file,proof_file = sys.argv[1:6]
    raw = Path(nf_file).read_bytes()
    if len(raw)!=128 or action not in ("prove","verify","shape"):
        raise ValueError("bad public arguments")
    chain,root,count = replay.public_state(directory,pin,len(sys.argv)==7)
    nfs = raw[:64],raw[64:]
    domain = b"SGF1/funded-two/v1" + bytes.fromhex(pin) + chain + root + count.to_bytes(6,"little") + raw
    private = json.load(sys.stdin) if action=="prove" else None
    w = build(chain,root,count,nfs,FLATTEN,private)
    p = Path(proof_file)
    if action=="shape":
        print(json.dumps(shape(w)))
    elif action=="prove":
        p.write_bytes(run(w,domain))
    else:
        limit = shape(w)["proof_B"]
        with p.open("rb") as stream:
            packet = stream.read(limit+1)
        run(w,domain,packet)
        print(json.dumps(shape(w)))


if __name__=="__main__":
    try:
        main()
    except ValueError as error:
        sys.exit(f"funded verification rejected: {error}")
