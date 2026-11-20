"""Bound the stronger schedule's frame admission probability under uniform query draws."""
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
LIMIT = 262144
ORDINARY_FIXED = 9 + 31*8 + 2*1792
SIGNED_FIXED = 9 + 34*8 + 2*1792 + 107 + 17088


def compare(profile):
    mean = profile["expected_proof_payload_B"]
    maximum = profile["maximum_proof_payload_B"]
    # Revealing an extra distinct leaf consumes at most one frontier node and
    # introduces at most h new siblings. Total serialized bytes are monotone
    # since every new leaf carries at least one 64-byte salt. Replacing a draw
    # changes size by at most the larger of the two insertion costs.
    differences = [
        (2 if last else 1) * (40*(1 if last else 16) + 64 + 64*depth)
        for depth, last in [(19,False),(17,False),(16,False),(17,True)]
    ]
    squares = sum(q*c*c for q,c in zip(profile["q"], differences, strict=True))
    result = {}
    for name, fixed in [("transfer", ORDINARY_FIXED), ("signed_leg", SIGNED_FIXED)]:
        row = dict(constant_B=fixed, max_allowed_proof_B=LIMIT-fixed, maximum_frame_B=maximum+fixed,
                   expected_frame_B=round(mean+fixed, 3))
        # Round the persisted mean *down* by 0.001 B for a conservative lower tail.
        gap = mean - 0.001 - (LIMIT-fixed)
        if gap > 0:
            row["log2_upper_probability_fits_single_uniform_tape"] = math.ceil(-2*gap*gap/(squares*math.log(2))*1000)/1000
        result[name] = row
    return result

if __name__ == "__main__":
    r = json.loads((HERE/"review/PROFILE.json").read_text())
    print(json.dumps({k:compare(v) for k,v in r.items()}, indent=2, sort_keys=True))
