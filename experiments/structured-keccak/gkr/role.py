"""Trusted SGP1 role. The selector and register are local inputs, never interpreted from a proof."""
import argparse
import json
from pathlib import Path
import resource
import sys
import time

from parents import PathLayout, parse
from proof import execute
from ring_switch import wire_bytes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action",choices=("prove","verify","detached"))
    ap.add_argument("statement",type=Path)
    ap.add_argument("packet",type=Path)
    ap.add_argument("--flatten",type=int,choices=(1,2,3,4,6,8,12,24),default=24)
    a = ap.parse_args()
    stmt = a.statement.read_bytes()
    paths = parse(stmt)
    if sum(d for _,d,_ in paths)>256:
        raise ValueError("research role permutation limit")
    clock = time.perf_counter()
    public = a.action=="verify"
    n = sum(64+65*d for _,d,_ in paths)+(64 if a.action=="detached" else 0)
    sec = None if public else sys.stdin.buffer.read(n+1)
    layout = PathLayout(stmt,a.flatten,sec,detached=a.action=="detached")
    expected = wire_bytes(layout.nbits,layout.ntrace)+32*layout.ntrace
    if public and a.packet.stat().st_size!=expected:
        raise ValueError("invalid wire length rejected")
    packet = a.packet.read_bytes() if public else None
    value = execute(b"SGP1-registered-v1"+bytes([a.flatten])+stmt,layout.nbits,layout.ntrace,
                    layout.constraints,bits=layout.bits,packet=packet,invalid_calibration=a.action=="detached")
    if not public:
        if len(value)!=expected:
            raise ValueError("unexpected prover wire size")
        a.packet.write_bytes(value)
    print(json.dumps(dict(wall_s=time.perf_counter()-clock,bytes=expected,flatten=a.flatten,
                          bit_count=layout.nbits,trace_count=layout.ntrace,
                          peak_rss_KiB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)))


if __name__ == "__main__":
    try:
        main()
    except ValueError as e:
        sys.exit(str(e))
