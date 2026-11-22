"""Fixed mixed-field proof role; expected level and root are separate verifier inputs."""
import argparse
import json
from pathlib import Path
import os
import resource
import sys
import time

os.environ["SW_FIELD"] = "gf256"
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from field import random_fields
from relation import Circuit, bits
from sumcheck import run
from transcript import Transcript
from backend import MixedCommitment, PROFILE_ID, packed_length, pack_coeff, pack_secret

PROOF_BYTES = 241664


def execute(level,root,*,secret=None,packet=None,detached=None):
    if (secret is None) == (packet is None):
        raise ValueError("select exactly one role")
    c = Circuit(level,root,secret,detached)
    tr = Transcript(PROFILE_ID+bytes([level])+root,packet)
    tlen = 3*c.ell+5
    masks = random_fields((tlen,)) if tr.producing else None
    wt = pack_secret(c.w,masks) if tr.producing else None
    com = MixedCommitment(tr,packed_length(c.width,tlen),wt)
    coef,target = run(c,tr,masks)
    com.open(tr,pack_coeff(coef,c.width),target,invalid_calibration=detached is not None)
    if (not tr.producing and tr.pos != len(packet)) or len(tr.packet) != PROOF_BYTES:
        raise ValueError("wire size rejected")
    return bytes(tr.packet) if tr.producing else True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action",choices=("prove","verify","detached"))
    ap.add_argument("statement",type=Path)
    ap.add_argument("packet",type=Path)
    args = ap.parse_args()
    st = args.statement.read_bytes()
    if len(st) != 65:
        raise ValueError("public statement length rejected")
    clock = time.perf_counter()
    if args.action == "verify":
        if args.packet.stat().st_size != PROOF_BYTES:
            raise ValueError("wire size rejected")
        execute(st[0],st[1:],packet=args.packet.read_bytes())
    else:
        data = sys.stdin.buffer.read(259)
        if len(data) != (258 if args.action=="detached" else 194):
            raise ValueError("wrong witness length")
        w = data[:64],data[64:128],data[128:192],data[192],data[193]
        pr = execute(st[0],st[1:],secret=w,detached=bits(data[194:]) if len(data)==258 else None)
        args.packet.write_bytes(pr)
    print(json.dumps({"seconds":time.perf_counter()-clock,
                      "max_rss_kib":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}))


if __name__ == "__main__":
    try:
        main()
    except ValueError as err:
        sys.exit(str(err))
