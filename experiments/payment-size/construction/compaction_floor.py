"""Compute a coordinate-independent lower bound for this CP03 transport grammar."""

import argparse
from hashlib import sha256
import json
from pathlib import Path

QUERY_COUNT = 160
DIGEST_BYTES = 64
SALT_BYTES = 64
BODY_PREFIX = 4876
HEAD = 206 + 60364
TAIL = 56


def floor(path):
    body = path.read_bytes()
    if (body[:8] != b"CPBODY03" or int.from_bytes(body[10:12], "little") != 528
            or body[BODY_PREFIX:BODY_PREFIX+8] != b"CPFRI003"):
        raise ValueError("expected a public CP03 2x2 body")
    offset = BODY_PREFIX + HEAD
    fixed_bytes = 0
    repeated_upper = 0
    main_rows = 0
    frontier_bytes = 0
    # Wire-order widths include all matrices in a single query row. Each
    # matrix has an eight-u64 salt. FRI carries one EF5 sibling per query.
    batches = [("random", 80, SALT_BYTES), ("main", 584*8, SALT_BYTES),
               ("quotient", 80*8, 8*SALT_BYTES), ("fixed", 114*8, SALT_BYTES)]
    batches.extend((f"fold_{i}", 40, SALT_BYTES) for i in range(10))
    for name, width, salt_width in batches:
        start = offset
        for column_width in (width, salt_width):
            rows = {body[pos:pos+column_width] for pos in
                    range(offset, offset + QUERY_COUNT*column_width, column_width)}
            if any(len(row) != column_width for row in rows):
                raise ValueError("truncated rows")
            offset += QUERY_COUNT * column_width
            if name != "fixed":
                repeated_upper += (QUERY_COUNT - len(rows))*column_width
            if name == "main" and column_width == width:
                main_rows = len(rows)
        count = int.from_bytes(body[offset:offset+4], "little")
        if count > QUERY_COUNT*14:
            raise ValueError("implausible frontier")
        offset += 4 + DIGEST_BYTES*count
        if name == "fixed":
            fixed_bytes = offset - start
        else:
            frontier_bytes += DIGEST_BYTES*count
    if offset + TAIL != len(body):
        raise ValueError("fixture does not match the expected complete grammar")
    minimum = len(body) - fixed_bytes - repeated_upper
    return {"body": path.name, "sha256": sha256(body).hexdigest(), "baseline_bytes": len(body),
            "omitted_fixed_bytes": fixed_bytes, "repeat_saving_upper_bytes": repeated_upper,
            "minimum_this_transport_bytes": minimum,
            "maximum_this_transport_saving_percent": round(100*(1-minimum/len(body)), 6),
            "distinct_main_row_values": main_rows,
            "retained_main_value_bytes_floor": main_rows*584*8,
            "retained_nonfixed_frontier_digest_bytes": frontier_bytes}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("public_bodies", nargs="+", type=Path)
    print(json.dumps([floor(path) for path in parser.parse_args().public_bodies], indent=2))
