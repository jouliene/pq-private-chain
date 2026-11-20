"""Bound first-tree admission and exercise the coin-to-opening geometry only."""
from collections import Counter
from hashlib import sha3_512, shake_256
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent


def siblings(indices, levels):
    nodes = set(indices)
    total = 0
    for _ in range(levels):
        total += sum((node ^ 1) not in nodes for node in nodes)
        nodes = {node >> 1 for node in nodes}
    return total


def check(profile):
    stage = profile["stages"][0]
    draws, bits = stage["queries"], stage["log_n"]
    n = 1 << bits
    value_width = stage["width"] * stage["d"] * 40
    # Fitting even the raw distinct leaf values requires this many repeat draws.
    max_distinct = profile["cap_B"] // value_width
    repeats = draws - max_distinct
    if repeats <= 0:
        raise ValueError("this price no longer excludes the registered first-stage values")
    # For any r specified repeats, whichever preceding indices occurred,
    # each is a repeat with conditional probability at most (q-1)/N.
    numerator = math.comb(draws, repeats) * (draws - 1)**repeats
    denominator = n**repeats
    exponent = max(0, denominator.bit_length() - numerator.bit_length() - 1)
    while numerator << (exponent+1) <= denominator:
        exponent += 1
    assert numerator << exponent <= denominator
    hist = Counter()
    sizes = []
    for case in range(256):
        seed = sha3_512(b"amplified-spend/public-geometry-probe/v1" + case.to_bytes(4, "little")).digest()
        raw = shake_256(seed).digest(8 * draws)
        indices = {int.from_bytes(raw[i:i+8], "little") & (n-1) for i in range(0, len(raw), 8)}
        hist[len(indices)] += 1
        sizes.append(64 + len(indices)*(64 + value_width) + 64*siblings(indices, bits))
    return dict(draws=draws, positions=n, distinct_value_bytes=value_width,
                maximum_distinct_allowed_ignoring_everything_else=max_distinct,
                minimum_repeated_draws_necessary=repeats,
                ideal_uniform_probability_fits_at_most_two_to_minus=exponent,
                component_samples=len(sizes), distinct_leaf_counts=dict(sorted(hist.items())),
                opening_B_min=min(sizes), opening_B_max=max(sizes), includes_one_root=True,
                scope="Public SHAKE256 seed expansion only. No witness, funded proof, proof-generation timing or fiat-shamir grinding experiment.")


if __name__ == "__main__":
    config = json.loads((HERE/"primary/MODEL.json").read_bytes())["primary"]
    print(json.dumps(check(config), indent=2))
