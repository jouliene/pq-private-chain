"""Rebuild a previous public packet's statement from its signed prefix and time real native checks."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import resource
import sys
import time

from verify import verify

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"structured-keccak"/"harness"))
from payment_codec import parse_head

spec = importlib.util.spec_from_file_location("funding_role",ROOT/"hidden-membership"/"paths"/"role.py")
funding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(funding)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("public_run",type=Path)
    parser.add_argument("genesis_sha256")
    args = parser.parse_args()
    p = args.public_run
    raw = (p/"payment.bin").read_bytes()
    pin = bytes.fromhex(args.genesis_sha256)
    chain,root,count = funding.public_state(str(p/"prefix"),args.genesis_sha256,False)
    if not 3990 < len(raw) <= 262144 or int.from_bytes(raw[3982:3990],"little") != len(raw)-3990:
        raise ValueError("noncanonical SGM1 payment frame")
    st = parse_head(raw[:3982],args.genesis_sha256,chain,root,count).encode()
    pr = raw[3990:]
    samples = []
    for _ in range(5):
        wall,cpu = time.perf_counter(),time.process_time()
        verify(pin,st,pr)
        samples.append({"wall_s":time.perf_counter()-wall,"cpu_s":time.process_time()-cpu})
    rejected = {}
    def flip(raw,i):
        return raw[:i]+bytes([raw[i]^1])+raw[i+1:]
    cases = [(name,pin,flip(st,i),pr) for i,name in ((0,"chain"),(64,"root"),(128,"count"),
             (134,"fee"),(142,"nf0"),(206,"nf1"),(270,"cm0"),(334,"cm1"),(398,"intent"),(462,"auth"))]
    cases.extend([("genesis",flip(pin,0),st,pr),("truncation",pin,st,pr[:-1]),
                  ("trailing",pin,st,pr+b"\x00"),("trace",pin,st,flip(pr,150)),
                  ("final_opening",pin,st,flip(pr,len(pr)-1))])
    for name,pin2,st2,pr2 in cases:
        try:
            verify(pin2,st2,pr2)
        except ValueError as err:
            rejected[name] = str(err)
        else:
            raise AssertionError("accepted invalid "+name)
    print(json.dumps({"packet_sha256":hashlib.sha256(raw).hexdigest(),
                      "proof_bytes":len(pr),"count":count,"samples":samples,
                      "max_rss_kib":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                      "rejections":rejected},indent=2))


if __name__ == "__main__":
    main()
