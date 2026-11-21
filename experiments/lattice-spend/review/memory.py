"""Count coexisting coefficient payload allocations in the literal 38-bit backend."""

import json
from pathlib import Path


def count(row):
    vectors = row["binary_polynomials"]
    products = row["private_quadratic_rows"]
    canonical = row["canonical_words"]
    carries = row["carry_bit_planes"]
    poly = 256 * 2
    slot = 6 * poly + 8
    # At dch_addchecks: aggregated linear vector, challenge, left and right rows.
    node = slot * (vectors + products * (1 + (1 + 1 + 1) + (1 + 2)))
    # sx, input and output witness arrays coexist with those added checks.
    wallet = node + (slot + 2 * poly) * vectors
    # One source coefficient slot per masked support vector, value/slack/carry
    # in each canonical check, and each carry plane in its equation.
    source = slot * (vectors + 3 * canonical + carries)
    # The published stage-one floor counts two RHS copies for all linear rows
    # and one for each source quadratic; support rows and masks are deep-copied.
    rhs = slot * (2*row["full_ring_equations"] - products)
    support_copies = 2 * slot * (vectors + row["support_checks"])
    stage1_node = node + rhs + support_copies
    stage1_wallet = stage1_node + (slot + 3*poly)*vectors
    # Outside that floor: two copies of three operands per canonical linear row
    # and one use per carry plane. These are coefficient arrays, separate from RHS.
    omitted = slot * (6*canonical + carries)
    return dict(integrated_stage1_node_B=stage1_node,integrated_stage1_wallet_B=stage1_wallet,
                omitted_canonical_operand_copies_and_source_carry_coefficients_B=omitted,
                dachshund_node_payload_B=node,dachshund_wallet_payload_B=wallet,
                source_public_coefficient_payload_B=source,
                node_plus_source_B=node+source,wallet_plus_source_B=wallet+source)


if __name__ == "__main__":
    shapes = json.loads((Path(__file__).resolve().parents[1]/"funded/SHAPES.json").read_bytes())
    integrated = json.loads((Path(__file__).resolve().parents[1]/"funded/COSTS.json").read_bytes())["lift"]
    results = {suite:count(row) for suite,row in shapes.items()}
    for suite,item in results.items():
        assert item["integrated_stage1_node_B"] == integrated[suite]["stage1_node_allocated_B_at_least"]
        assert item["integrated_stage1_wallet_B"] == integrated[suite]["stage1_wallet_allocated_B_at_least"]
    print(json.dumps(results,indent=2,sort_keys=True))
