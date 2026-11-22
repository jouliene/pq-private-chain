"""Fixed process roles. Private 194-byte fixture enters prover only through stdin."""
import argparse
import json
import resource
import sys
import time
from pathlib import Path

from engine import execute, WIDE
from relation import bits


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action",choices=("prove","detached","verify"))
    parser.add_argument("statement",type=Path)
    parser.add_argument("packet",type=Path)
    args = parser.parse_args()
    raw = args.statement.read_bytes()
    if len(raw) != 65:
        raise ValueError("wrong statement length")
    level, root = raw[0],raw[1:]
    start = time.perf_counter()
    if args.action == "verify":
        expected_length = 6926976 if WIDE else 87760
        if args.packet.stat().st_size > expected_length:
            raise ValueError("trailing bytes")
        if args.packet.stat().st_size < expected_length:
            raise ValueError("truncated proof")
        execute(level,root,packet=args.packet.read_bytes())
    else:
        data = sys.stdin.buffer.read(259)
        if len(data) != (258 if args.action == "detached" else 194):
            raise ValueError("wrong witness length")
        secret = (data[:64],data[64:128],data[128:192],data[192],data[193])
        proof = execute(level,root,secret=secret,
                        detached=bits(data[194:]) if args.action == "detached" else None)
        args.packet.write_bytes(proof)
    print(json.dumps(dict(seconds=time.perf_counter()-start,
                          max_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)))


if __name__ == "__main__":
    try:
        main()
    except ValueError as exc:
        sys.exit(str(exc))
