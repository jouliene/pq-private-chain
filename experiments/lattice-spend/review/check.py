"""Recount the two independent LLNW Figure 2 path proofs for the funded split."""

import json
from math import comb, factorial
from pathlib import Path


def bits_for(choices):
    return (choices - 1).bit_length()


def repetitions(error_bits):
    count = 0
    while 3**count < (1 << error_bits) * 2**count:
        count += 1
    return count


def price():
    n, q, depth = 256, 256, 40
    k = bits_for(q)
    half = n * k
    m = 2 * half
    # Figure 2 opens depth-1 m-vectors plus two depth-long groups of 2m-vectors.
    field_words = (depth - 1) * m + 2 * depth * (2 * m)
    classes = {"balance_rank_bits": bits_for(comb(m, half)),
               "permutation_rank_bits": bits_for(factorial(m))}
    common = (3 * n * k) + (2 * m) + depth + field_words * k
    branch = {"challenge1": (common + 2 * depth * classes["balance_rank_bits"] + 7) // 8,
              "challenge2_or_3": (common + 2 * depth * classes["permutation_rank_bits"] + 7) // 8}
    two = {}
    for target in (128, 256):
        rounds = repetitions(target)
        two[str(target)] = {"repetitions": rounds,
                            "two_all_challenge1_B": 2 * rounds * branch["challenge1"],
                            "two_all_challenge2_or_3_B": 2 * rounds * branch["challenge2_or_3"]}
    experiment = Path(__file__).resolve().parents[2]
    net = json.loads((experiment / "packed-tcith/resources/NETWORK.json").read_bytes())
    residual = net["counterfactual_SLG1_no_membership"]["16"]["residual_B"]
    budget = 262144 - 21060 - residual
    assert budget == 33676 and field_words * k // 8 > budget
    return {"parameters": {"n": n, "q": q, "k": k, "m": m, "depth": depth},
            "one_path_one_response_literal_dense_B": field_words * k // 8,
            "per_object_ranks": classes, "one_path_one_round_with_commitments_B": branch,
            "two_independent_paths_without_bridge": two, "available_two_paths_and_binding_B": budget}


if __name__ == "__main__":
    print(json.dumps(price(), sort_keys=True, indent=2))
