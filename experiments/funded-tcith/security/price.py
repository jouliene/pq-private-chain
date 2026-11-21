"""Reproduce public finite-field, compiler and complete single-challenge codec costs."""
import json
from math import comb, factorial, log2
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXPERIMENTS = HERE.parents[1]
P = 2**64 - 2**32 + 1
N, S, OPEN, RHO, ETA = 2**18, 117, 32, 5, 33
D = S + OPEN - 1
TRIALS = 480
QUERY_BITS = 128


def current():
    batch = P**-RHO
    degree = comb(N, D + 2) / P**ETA
    subset = comb(7 * D, OPEN) / comb(N, OPEN)
    bound = batch + degree + (1 - batch) * subset
    q = 1 << QUERY_BITS
    dfm = 6 * log2(2*q + 4) - log2(factorial(3))
    return {
        "interactive_negative_log2": {
            "batch": -log2(batch), "degree": -log2(degree),
            "subset": -log2(subset), "sum": -log2(bound),
        },
        "dfm_log2_loss": dfm,
        "dfm_log2_soundness_product": dfm + log2(bound),
        "log2_terminal_challenges": log2(comb(N, OPEN)),
        "dfm_log2_ordering_term_if_native_terminal_range": dfm + log2(6) - log2(comb(N, OPEN)),
        "ideal_parent_log2": {
            "capacity": 4*log2(P), "output": 4*log2(P),
            "classical_capacity_matching": 2*log2(P),
            "quantum_capacity_matching": 4*log2(P)/3,
            "generic_digest_only_target_search": 2*log2(P),
            "capacity_matching_table_bytes_at_four_limbs": 4*log2(P)/3 + 5,
        },
    }


def raw_three_view(suite, shape):
    """Canonical simple encoding, fixed-length vectors; no entropy or compression credit."""
    n = shape["private_columns"]
    rows = shape["rows"]
    quadratic = shape["rows_by_degree"]["2"]
    sboxes = shape["rows_by_degree"]["7"]
    mult = quadratic + 4*sboxes
    assert rows == sum(shape["rows_by_degree"].values())
    # The two public residual vectors determine the third using sum = zero.
    # Each view includes one independent salt, its witness shares, mask words and product shares.
    view = 64 + 8*(n + 2*mult)
    ordinary = suite == "MNG1"
    parts = {
        "common_residual_share_vectors": TRIALS * 2*rows*8,
        "all_individual_commitments": TRIALS * 3*64,
        "two_complete_openings": TRIALS * 2*view,
    }
    proof = sum(parts.values())
    # Includes network context derived locally, public fields, two original receipts,
    # nested length tags, and for signed legs the original joint-auth signature and frame.
    wrapper = (3847 if ordinary else 21060) + 32
    framed = proof + wrapper
    return {
        "registered_shape": shape["serialized_shape_sha256"], "private_words": n,
        "residuals": rows, "multiplications_per_repetition": mult,
        "raw_view_bytes": view, "proof_parts": parts, "proof_bytes": proof,
        "framing_bytes": wrapper, "total_bytes": framed, "physical_limit": 262144,
        "over_limit_bytes": framed - 262144,
        "two_leg_submission_bytes": None if ordinary else 2*framed + 13,
        "minimum_opened_private_share_bytes_in_this_raw_codec": TRIALS*2*n*8,
    }


def main():
    shapes = json.loads((EXPERIMENTS / "lattice-spend/pivot/PRICE.json").read_bytes())["census"]
    challenge_bits = (3**TRIALS).bit_length() - 1
    # Per DFMS Remark 3.6, use a wide random oracle, truncate commitments to n=512.
    # Each component considered for 2^128 adversarial queries includes verifier surcharge.
    q = 2*(2**QUERY_BITS) + 2*TRIALS + 2
    ptriv_bound = 2**TRIALS / 2**challenge_bits
    collision = (22*3*TRIALS + 60) * q**3 / 2**512
    extraction = 20 * q**2 * ptriv_bound
    result = {
        "current_TCITH": current(),
        "single_challenge": {
            "repetitions": TRIALS, "challenge_bits": challenge_bits,
            "log2_max_without_extractable_repetition": log2(ptriv_bound),
            "query_budget_after_surcharge": str(q),
            "dfms42_log2_collision_term": log2(collision),
            "dfms42_log2_challenge_term": log2(extraction),
            "dfms42_log2_sum": log2(collision + extraction),
            "suites": {name: raw_three_view(name, shape["degree7"]) for name, shape in shapes.items()},
        },
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
