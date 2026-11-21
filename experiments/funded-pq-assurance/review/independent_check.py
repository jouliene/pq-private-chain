#!/usr/bin/env python3
"""Independent arithmetic and verifier-key checks for funded profile C.

This script deliberately does not import the milestone calculators or their key
decoder.  It checks only facts encoded in the two committed verifier keys and
recomputes the ideal-function and proof-serialization arithmetic.  The output
is not a security estimate for the payment system.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import math
from pathlib import Path
import struct


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
P = 2**64 - 2**32 + 1

ROLES = {
    "MNG3": {
        "file": "managed.vk",
        "sha256": "6cb89745c94ec7b2ff97173ec0819b8567ae5672991b2fdbbe3cbe5810ebadf2",
        "public_inputs": 32,
        "gates": 548,
        "frame_overhead": 3_599,
    },
    "SLG3": {
        "file": "swap.vk",
        "sha256": "7acd892eb041260a90efe30fc19771922da2be083707dec4116f8b3af9765c4a",
        "public_inputs": 35,
        "gates": 558,
        "frame_overhead": 20_788,
    },
}

# DefaultGateSerializer tags in qp-plonky2 1.5.5.  Only tags present in the C
# keys are accepted, so this parser fails closed on an unexpected gate.
GATES = {
    0: ("Arithmetic", 1, 3),
    2: ("BaseSum2", 1, 2),
    3: ("Constant", 1, 1),
    9: ("Noop", 0, 0),
    11: ("Poseidon", 0, 7),
    14: ("Poseidon2", 0, 7),
    15: ("PublicInput", 0, 1),
}


class Reader:
    def __init__(self, raw: bytes):
        self.raw = raw
        self.offset = 0

    def take(self, size: int) -> bytes:
        end = self.offset + size
        if end > len(self.raw):
            raise ValueError("truncated verifier key")
        out = self.raw[self.offset:end]
        self.offset = end
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def words(self, count: int) -> list[int]:
        return list(struct.unpack(f"<{count}Q", self.take(8 * count)))


def read_fri(reader: Reader) -> dict[str, object]:
    out = {
        "rate_bits": reader.u64(),
        "cap_height": reader.u64(),
        "queries": reader.u64(),
        "grinding_bits": reader.u32(),
    }
    if reader.u8() != 1:
        raise ValueError("unexpected FRI reduction strategy")
    out["constant_arity_bits"] = [reader.u64(), reader.u64()]
    return out


def decode_key(raw: bytes) -> dict[str, object]:
    reader = Reader(raw)
    cap_height = reader.u64()
    if cap_height != 4:
        raise ValueError("unexpected key cap height")
    reader.words(4 * (1 << cap_height))
    circuit_digest = reader.words(4)
    config = {
        name: reader.u64()
        for name in (
            "wires",
            "routed",
            "constants",
            "configured_security_bits",
            "plonk_repetitions",
            "max_quotient_factor",
        )
    }
    if reader.u8() != 1:
        raise ValueError("base arithmetic gate disabled")
    config["row_blinding"] = reader.u8()
    config["fri"] = read_fri(reader)
    trace_bits = reader.u64()
    if read_fri(reader) != config["fri"]:
        raise ValueError("inconsistent duplicated FRI configuration")
    folds = [reader.u64() for _ in range(reader.u64())]
    degree_bits = reader.u64()
    leaf_hiding = reader.u8()
    if reader.u64() != trace_bits or degree_bits != trace_bits:
        raise ValueError("inconsistent trace degree")
    selector_indices = [reader.u64() for _ in range(reader.u64())]
    groups = [[reader.u64(), reader.u64()] for _ in range(reader.u64())]
    common = {
        name: reader.u64()
        for name in ("quotient_factor", "gate_constraints", "constant_polys", "public_inputs")
    }
    if reader.u64() != config["routed"]:
        raise ValueError("sigma count mismatch")
    reader.words(config["routed"])
    common["partial_products"] = reader.u64()
    if reader.words(3) != [0, 0, 0]:
        raise ValueError("unexpected lookup metadata")
    gates = []
    for _ in range(reader.u64()):
        tag = reader.u32()
        if tag not in GATES:
            raise ValueError(f"unexpected gate tag {tag}")
        name, arguments, degree = GATES[tag]
        gates.append({"name": name, "arguments": reader.words(arguments), "degree": degree})
    if reader.offset != len(raw):
        raise ValueError("trailing verifier-key bytes")
    if len(gates) != len(selector_indices):
        raise ValueError("selector/gate mismatch")
    filtered_degrees = []
    for start, end in groups:
        if not 0 <= start < end <= len(gates):
            raise ValueError("invalid selector group")
        filtered_degrees.append((end - start) + max(g["degree"] for g in gates[start:end]))
    return {
        "bytes": len(raw),
        "sha256": sha256(raw).hexdigest(),
        "circuit_digest": circuit_digest,
        "config": config,
        "trace_rows": 1 << trace_bits,
        "folds": folds,
        "leaf_hiding": leaf_hiding,
        "selector_groups": groups,
        "gates": gates,
        "filtered_gate_degrees": filtered_degrees,
        "common": common,
    }


def folds(degree_bits: int) -> list[int]:
    result = []
    while degree_bits > 3 and degree_bits + 5 - 2 >= 4:
        result.append(2)
        degree_bits -= 2
    return result


def geometry(gates: int, queries: int) -> dict[str, object]:
    trace_rows = 1 << ((gates - 1).bit_length())
    while True:
        degree_bits = trace_rows.bit_length() - 1
        reductions = folds(degree_bits)
        final_coefficients = trace_rows >> sum(reductions)
        folding_points = sum((1 << arity) - 1 for arity in reductions)
        fri_masks = queries * (1 + 2 * folding_points + 2 * final_coefficients)
        regular = 2 + fri_masks
        z_pairs = 4 + fri_masks
        blinded = regular + 2 * z_pairs
        if gates + blinded <= trace_rows:
            return {
                "trace_rows": trace_rows,
                "folds": reductions,
                "final_extension_coefficients": final_coefficients,
                "fri_masks_per_polynomial": fri_masks,
                "regular_blinding_rows": regular,
                "z_blinding_pairs": z_pairs,
                "total_blinding_rows": blinded,
            }
        trace_rows *= 2


def proof_size(gates: int, public_inputs: int, queries: int, repetitions: int) -> dict[str, object]:
    row = geometry(gates, queries)
    trace_rows = int(row["trace_rows"])
    reductions = list(row["folds"])
    lde_points = trace_rows << 5
    initial_width = 4 + 60 + 135 + repetitions * 8 + repetitions * 8
    initial_path = lde_points.bit_length() - 1 - 4
    initial_query = (initial_width + 12) * 8 + 4 * (1 + initial_path * 32)
    depth = initial_path
    folded_query = 0
    siblings = 4 * depth
    for arity in reductions:
        depth -= arity
        folded_query += 16 * (1 << arity) + 1 + depth * 32
        siblings += depth
    fixed = (
        (3 + len(reductions)) * 16 * 32
        + 16 * (initial_width + repetitions)
        + 16 * int(row["final_extension_coefficients"])
        + 8
        + 8
        + 8 * public_inputs
    )
    proof = fixed + queries * (initial_query + folded_query)
    return row | {
        "lde_points": lde_points,
        "initial_query_bytes": initial_query,
        "folded_query_bytes": folded_query,
        "fixed_bytes": fixed,
        "proof_bytes": proof,
        "merkle_sibling_hashes": queries * siblings,
        "fri_fold_extension_values": queries * sum(1 << arity for arity in reductions),
    }


def oplonky_analogy(trace_rows: int, repetitions: int) -> dict[str, object]:
    # These substitutions reproduce the proposed calculator.  They are kept
    # explicitly as an unproved analogy: no source-to-OPlonky index map is
    # established by this script or by the key fields alone.
    r_prime = 60
    u = s = 8
    k = 123
    d = 9
    terms = {
        "epsilon1_negative_log2": repetitions * math.log2(P / (3 * trace_rows * (r_prime + u))),
        "epsilon2_negative_log2": repetitions * math.log2(P / (k + (s + 2) * repetitions - 1)),
        "epsilon3_negative_log2": math.log2((P**2 - trace_rows) / (max(d, u + 1) * trace_rows)),
    }
    return {
        "status": "arithmetic_reproduced_but_source_to_theorem_mapping_unproved",
        "substitution": {"k": k, "d": d, "u": u, "s": s, "r_prime": r_prime},
        "epsilon3_denominator": f"|K\\D| = p^2 - {trace_rows}",
        "terms": terms,
        "minimum_term_negative_log2": min(terms.values()),
        "valid_conclusion": "this analogy does not certify 128-bit security",
        "invalid_conclusion": "the actual construction has fewer than 128 bits of security",
    }


def attack_models() -> dict[str, object]:
    targets = 4_400_000_000
    entropy = 4 * math.log2(P)
    target_bits = math.log2(targets)
    return {
        "scenario": {
            "targets": targets,
            "status": "researcher_defined_20y_100pct_mixed_output_scenario",
        },
        "four_word_ideal_multi_target_search": {
            "query_exponent": (entropy - target_bits) / 2,
            "success_convention": "Theta estimate for unspecified constant success; constants omitted",
            "unit_cost_assumption": "one coherent membership-oracle call per query",
            "target_table_raw_bytes": targets * 32,
            "not_priced": ["reversible lookup circuit", "qRAM or non-qRAM lookup time", "oracle construction"],
        },
        "four_word_ideal_BHT_collision": {
            "query_exponent": entropy / 3,
            "success_convention": "Theta estimate for unspecified constant success; constants omitted",
            "textbook_table_entries_exponent": entropy / 3,
            "textbook_table_raw_bytes_exponent": entropy / 3 + 5,
            "unit_cost_assumption": "coherent lookup in the stored collision table",
            "not_priced": ["qRAM construction", "coherent memory faults", "parallel depth", "non-qRAM lookup time"],
        },
        "scope": "query exponents are not total time, memory, energy, or monetary attack costs",
    }


def calculate() -> dict[str, object]:
    decoded = {}
    profiles = {"registered_C": {}, "S64_model": {}}
    registry = ROOT / "experiments/funded-membership/registry"
    for suite, expected in ROLES.items():
        raw = (registry / expected["file"]).read_bytes()
        key = decode_key(raw)
        if key["sha256"] != expected["sha256"]:
            raise ValueError(f"unexpected {suite} key identity")
        if key["common"]["public_inputs"] != expected["public_inputs"]:
            raise ValueError(f"unexpected {suite} public-input count")
        if key["config"]["fri"]["queries"] != 32 or key["config"]["plonk_repetitions"] != 2:
            raise ValueError(f"unexpected {suite} proof configuration")
        if key["trace_rows"] != 8192 or key["folds"] != [2, 2, 2, 2, 2]:
            raise ValueError(f"unexpected {suite} geometry")
        decoded[suite] = key
        for label, queries, repetitions in (("registered_C", 32, 2), ("S64_model", 64, 3)):
            profile = proof_size(expected["gates"], expected["public_inputs"], queries, repetitions)
            profile["frame_bytes"] = profile["proof_bytes"] + expected["frame_overhead"]
            profile["oplonky_parameter_analogy"] = oplonky_analogy(
                int(profile["trace_rows"]), repetitions
            )
            profiles[label][suite] = profile
    expected_sizes = {
        ("registered_C", "MNG3"): (179_264, 182_863),
        ("registered_C", "SLG3"): (179_288, 200_076),
        ("S64_model", "MNG3"): (387_952, 391_551),
        ("S64_model", "SLG3"): (387_976, 408_764),
    }
    for (profile, suite), (proof, frame) in expected_sizes.items():
        actual = profiles[profile][suite]
        if (actual["proof_bytes"], actual["frame_bytes"]) != (proof, frame):
            raise ValueError(f"{profile} {suite} size mismatch")
    return {
        "schema": "funded-pq-independent-review-v1",
        "keys": decoded,
        "profiles": profiles,
        "ideal_attack_resource_models": attack_models(),
        "review_boundary": (
            "Exact key parsing and arithmetic reproduction only. The OPlonky mapping, "
            "proof security, Poseidon security, and monetary composition are not established."
        ),
    }


def summary(result: dict[str, object]) -> dict[str, object]:
    keys = {}
    for suite, row in result["keys"].items():
        keys[suite] = {
            "sha256": row["sha256"],
            "bytes": row["bytes"],
            "circuit_digest": row["circuit_digest"],
            "public_inputs": row["common"]["public_inputs"],
            "trace_rows": row["trace_rows"],
            "fri_queries": row["config"]["fri"]["queries"],
            "plonk_repetitions": row["config"]["plonk_repetitions"],
            "routed_wires": row["config"]["routed"],
            "partial_products_per_repetition": row["common"]["partial_products"],
            "quotient_factor": row["common"]["quotient_factor"],
            "maximum_gate_constraint_vector": row["common"]["gate_constraints"],
            "selector_groups": row["selector_groups"],
            "filtered_gate_degrees": row["filtered_gate_degrees"],
            "folds": row["folds"],
        }
    profiles = {}
    for label, suites in result["profiles"].items():
        common = suites["MNG3"]
        profiles[label] = {
            "trace_rows": common["trace_rows"],
            "lde_points": common["lde_points"],
            "fri_masks_per_polynomial": common["fri_masks_per_polynomial"],
            "total_blinding_rows": common["total_blinding_rows"],
            "proof_and_frame_bytes": {
                suite: {"proof": row["proof_bytes"], "frame": row["frame_bytes"]}
                for suite, row in suites.items()
            },
            "oplonky_parameter_analogy": common["oplonky_parameter_analogy"],
        }
    return {
        "schema": result["schema"],
        "keys": keys,
        "profiles": profiles,
        "ideal_attack_resource_models": result["ideal_attack_resource_models"],
        "review_boundary": result["review_boundary"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", type=Path)
    parser.add_argument("--full", action="store_true")
    args = parser.parse_args()
    result = calculate()
    encoded = json.dumps(result if args.full else summary(result), indent=2, sort_keys=True) + "\n"
    if args.check:
        if args.check.read_text() != encoded:
            raise SystemExit(f"independent result differs: {args.check}")
        print("Independent funded C key and arithmetic result matched.")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
