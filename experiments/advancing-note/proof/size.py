"""Count canonical N7P2 proof bytes from the FRI query indices."""
import argparse
import json
import math
from pathlib import Path
import struct

QUERIES = 32
CAP_BITS = 4
PREFIX = 9 * 16 * 48 + 233 * 32
FOOTER = 4 * 32 + 8
INITIAL_LEAF = 243 * 8
HEIGHTS = (17, 15, 13, 11, 9, 7)


def count(occupancy):
    # At level d there are 2*n[d-1] children of visited parents and n[d]
    # visited children. The remaining child digests must be transmitted once.
    def siblings(height):
        return sum(2 * occupancy(d - 1) - occupancy(d) for d in range(CAP_BITS + 1, height + 1))
    size = PREFIX + FOOTER + QUERIES * 4
    size += occupancy(19) * (INITIAL_LEAF + 4) + 4 * 48 * siblings(19)
    for height in HEIGHTS:
        size += occupancy(height) * (3 * 32 + 1) + 48 * siblings(height)
    return size


def occupied(indices, depth):
    return len({i >> (19 - depth) for i in indices})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("proof", nargs="?", type=Path)
    args = parser.parse_args()
    result = {
        "expanded_fixed_bytes": 267504,
        "compact_shape_max_bytes": count(lambda d: min(2**d, QUERIES)),
        "independent_uniform_expected_bytes": count(
            lambda d: -(2**d) * math.expm1(QUERIES * math.log1p(-1.0 / (2**d)))
        ),
    }
    if args.proof:
        data = args.proof.read_bytes()
        indices = struct.unpack_from("<32I", data, PREFIX)
        if any(i >= 2**19 for i in indices):
            raise ValueError("invalid FRI indices")
        predicted = count(lambda depth: occupied(indices, depth))
        if predicted != len(data):
            raise ValueError("encoded length disagrees with query-shape model")
        result["measured_bytes"] = predicted
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
