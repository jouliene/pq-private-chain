"""Measure repeated public verification at each occupancy with one isolated verifier process."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from run import verify_keys
from wire import Role, need


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for arg in ("binary","keys","packets"):
        parser.add_argument(arg,type=Path)
    for arg in ("binary_sha","profile_sha"):
        parser.add_argument(arg)
    args=parser.parse_args()
    verify_keys(args.keys,args.profile_sha)
    # Published traces include a deliberately corrupted packet. Select only packets from accepted
    # blocks if the enclosing trace is available. A cold verifier accepts every selected proof.
    trace=args.packets.parent/"TRACE.json"
    if trace.is_file():
        ids=sorted({item["packet"] for item in json.loads(trace.read_bytes())["blocks"].values() if item["packet"]})
    else:
        ids=sorted(p.stem for p in args.packets.glob("*.bin"))
    role=Role(args.binary,args.binary_sha,["verify","/keys"],args.keys)
    try:
        chosen={}
        for identity in ids:
            raw=(args.packets/(identity+".bin")).read_bytes()
            need(hashlib.sha256(raw).hexdigest()==identity,"public packet hash")
            k=raw[4]
            if k not in chosen and role.call(raw).startswith(b"1"):
                chosen[k]=(identity,raw)
        need(set(chosen)==set(range(1,5)), "four valid public widths")
        measurements=[]
        for i in range(8):
            for index in range(4):
                k=(i+index)%4+1
                identity,raw=chosen[k]
                start=time.monotonic()
                response=role.call(raw)
                dt=time.monotonic()-start
                need(len(response)==1+k*(172+3584) and response[:1]==b"1", "fresh proof verification")
                measurements.append(dict(k=k,packet_sha256=identity,wall_including_pipe_s=dt))
        meters=role.close()
        for m,row in zip(meters[-len(measurements):],measurements,strict=True):
            need(m["operation"]=="public_verify","public verifier timing")
            row.update(m)
        print(json.dumps(dict(binary_sha256=args.binary_sha,profile_sha256=args.profile_sha,
            source="eight fresh verifications of one fixed public packet per occupancy, alternating widths",
            cold_setup=meters[0],measurements=measurements),indent=2,sort_keys=True))
    finally:
        role.abort()


if __name__=="__main__":
    main()
