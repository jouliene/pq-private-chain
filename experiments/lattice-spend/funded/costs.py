"""Compute complete packet projections and source-level allocation floors."""
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]/"amplified-spend"))
from traffic import project


def memory(shape):
    v = shape["binary_polynomials"]
    q = shape["private_quadratic_rows"]
    rows = shape["full_ring_equations"]
    support_rows = shape["support_checks"]
    # Pinned x86-64 LN=256, K=6, six CRT projections of 512 B plus one width.
    tracked = 6 * 512 + 8
    reduced = tracked * (v + 7*q)
    # Each full equation has a constant vector. Each linear equation is deep-copied.
    constants = tracked * (2*rows-q)
    # Every binary vector has forbidden tail positions that must be zeroed.
    # The support checks have unit rank and one sparse linear term per vector.
    # These Zq sparse equations are copied into the reduced public statement.
    support = 2 * tracked * (v + support_rows)
    node = reduced + constants + support
    return dict(stage1_node_allocated_B_at_least=node,
                stage1_wallet_allocated_B_at_least=node+(3*512+tracked)*v,
                included_support_statement_B=support,
                wallet_input_forward_NTT256=6*v,
                direct_C_API_offset_bytes_written=8*v*(rows+support_rows))


def network(ordinary, leg, extra_header):
    result = project(ordinary, [leg, leg], "comparison")
    mixed = []
    for row in result["scenarios"]:
        if row["swap_percent"] != 10:
            continue
        mixed.append(dict(operations=row["operations"], packed_blocks=row["minimum_blocks"],
                          final_wallet_RPC_B=row["one_final_submission_each_RPC_B"],
                          pending_body_B=row["pending_bodies_B"],
                          packed_archive_B=row["packed_archive_B"] + extra_header*row["minimum_blocks"],
                          sparse_archive_B=row["one_operation_per_block_archive_B"] + extra_header*row["operations"]))
    return dict(transfer_B=ordinary, signed_leg_B=leg, swap_B=result["swap_submission_B"], mixed=mixed)


def run():
    shape = json.loads((HERE/"SHAPES.json").read_text())
    p = (HERE/"PLAN.txt").read_text()
    plans = {k: int(v) for k,v in re.findall(r"(MNG1|SLG1)\nEstimated proof size: [^\n]+\nfield_arrays_B=(\d+)", p)}
    pivot = json.loads((HERE.parent/"pivot/PRICE.json").read_text())["shared_leg_geometry"]
    tree_height = 18
    pivot_frame = lambda suite: pivot[f"{suite}_at_{tree_height}"]["proof_plus_fixed_frame_B"]
    return dict(lift={k:memory(s) for k,s in shape.items()},
                network=dict(live=network(143233, 160446, 0),
                             toolkit_fixed_raw_projection=network(plans["MNG1"]+4+3847,plans["SLG1"]+4+21060,0),
                             fixed_parent_tcith_projection=network(pivot_frame("MNG1"),pivot_frame("SLG1"),32)))


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
