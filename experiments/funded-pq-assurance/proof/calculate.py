#!/usr/bin/env python3
"""Reproduce funded C proof geometry and a proof-only stronger profile.

The stronger profile is a sizing and conditional-bound calculation, not a
registered verifier and not a security claim.  It keeps the MNG3/SLG3
relations, raises PLONK repetitions from two to three and FRI query rounds
from 32 to 64, and otherwise keeps the registered proof configuration.
"""

from __future__ import annotations

from hashlib import sha256
import importlib.util
import json
import math
from pathlib import Path
import statistics


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
P = 2**64 - 2**32 + 1
EXTENSION_DEGREE = 2
RATE_BITS = 5
CAP_HEIGHT = 4
FINAL_POLY_BITS = 3
ARITY_BITS = 2
WIRES = 135
ROUTED = 60
CONSTANT_POLYS = 4
PARTIAL_PRODUCTS = 7
QUOTIENT_FACTOR = 8
GATE_CONSTRAINT_VECTOR = 123
GATE_DEGREE_BOUND = 9
PERMUTATION_CHUNK = 8

ROLES = {
    "MNG3": {
        "key": "managed.vk",
        "key_sha256": "6cb89745c94ec7b2ff97173ec0819b8567ae5672991b2fdbbe3cbe5810ebadf2",
        "gates_before_blinding": 548,
        "public_inputs": 32,
        "proof_bytes": 179_264,
        "frame_overhead_bytes": 3_599,
        "signed_frame_overhead_bytes": 20_759,
    },
    "SLG3": {
        "key": "swap.vk",
        "key_sha256": "7acd892eb041260a90efe30fc19771922da2be083707dec4116f8b3af9765c4a",
        "gates_before_blinding": 558,
        "public_inputs": 35,
        "proof_bytes": 179_288,
        "frame_overhead_bytes": 20_788,
    },
}


def load_key_decoder():
    source = ROOT / "experiments/token-profile/parameters.py"
    spec = importlib.util.spec_from_file_location("funded_pq_key_decoder", source)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load committed key decoder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.read_key


def folds_for_degree(degree_bits: int) -> list[int]:
    folds = []
    while (
        degree_bits > FINAL_POLY_BITS
        and degree_bits + RATE_BITS - ARITY_BITS >= CAP_HEIGHT
    ):
        folds.append(ARITY_BITS)
        degree_bits -= ARITY_BITS
    return folds


def geometry(gates: int, queries: int) -> dict:
    """Mirror qp-plonky2 CircuitBuilder::blinding_counts fixed point."""
    degree = 1 << (gates - 1).bit_length()
    while True:
        degree_bits = degree.bit_length() - 1
        folds = folds_for_degree(degree_bits)
        final_coefficients = degree >> sum(folds)
        folding_points = sum((1 << fold) - 1 for fold in folds)
        fri_openings = queries * (
            1
            + EXTENSION_DEGREE * folding_points
            + EXTENSION_DEGREE * final_coefficients
        )
        regular_openings = EXTENSION_DEGREE + fri_openings
        z_openings = 2 * EXTENSION_DEGREE + fri_openings
        blinding_rows = regular_openings + 2 * z_openings
        if gates + blinding_rows <= degree:
            break
        degree *= 2
    return {
        "trace_rows": degree,
        "degree_bits": degree.bit_length() - 1,
        "folds": folds,
        "final_extension_coefficients": final_coefficients,
        "fri_openings_per_polynomial": fri_openings,
        "regular_blinding_rows": regular_openings,
        "z_blinding_pairs": z_openings,
        "total_blinding_rows": blinding_rows,
        "rows_before_padding": gates + blinding_rows,
        "padding_rows": degree - gates - blinding_rows,
    }


def fixed_set_bits(queries: int, lde_points: int, accepted: int) -> float:
    """Exact modulo-biased all-query term for a set fixed before sampling."""
    numerator = (P // lde_points) * accepted + min(P % lde_points, accepted)
    return queries * math.log2(P / numerator)


def proof_profile(gates: int, public_inputs: int, queries: int, challenges: int) -> dict:
    row = geometry(gates, queries)
    trace_rows = row["trace_rows"]
    lde_points = trace_rows << RATE_BITS
    folds = row["folds"]
    cap_size = 1 << CAP_HEIGHT
    path_depth = lde_points.bit_length() - 1 - CAP_HEIGHT
    oracle_widths = {
        "constants_and_sigmas": CONSTANT_POLYS + ROUTED,
        "wires": WIRES,
        "z_and_partials": challenges * (1 + PARTIAL_PRODUCTS),
        "quotient_chunks": challenges * QUOTIENT_FACTOR,
    }

    # Mirrors experiments/funded-upgrade/profile.py::wire_cost and the
    # qp-plonky2 1.5.5 uncompressed serializer.
    initial_query_bytes = (
        (sum(oracle_widths.values()) + 12) * 8
        + 4 * (1 + path_depth * 32)
    )
    depth = path_depth
    folded_query_bytes = 0
    sibling_hashes_per_query = 4 * depth
    for fold in folds:
        depth -= fold
        folded_query_bytes += 16 * (1 << fold) + 1 + depth * 32
        sibling_hashes_per_query += depth
    fixed_bytes = (
        (3 + len(folds)) * cap_size * 32
        + 16 * (sum(oracle_widths.values()) + challenges)
        + 16 * row["final_extension_coefficients"]
        + 8  # proof-of-work witness
        + 8  # public-input vector length
        + 8 * public_inputs
    )
    proof_bytes = fixed_bytes + queries * (initial_query_bytes + folded_query_bytes)

    initial_committed_base_words = (
        WIRES + 4
        + challenges * (1 + PARTIAL_PRODUCTS) + 4
        + challenges * QUOTIENT_FACTOR + 4
    ) * lde_points
    folded_committed_base_words = sum(
        2 * (1 << fold) * (lde_points >> sum(folds[: i + 1]))
        for i, fold in enumerate(folds)
    )
    fft_scale_units = (
        WIRES + 2 * challenges * QUOTIENT_FACTOR
    ) * lde_points * math.log2(lde_points)

    row.update(
        {
            "extension_degree": EXTENSION_DEGREE,
            "plonk_challenges": challenges,
            "fri_queries": queries,
            "rate_bits": RATE_BITS,
            "cap_height": CAP_HEIGHT,
            "lde_points": lde_points,
            "query_index_remainder": P % lde_points,
            "oracle_leaf_widths_base_words": oracle_widths,
            "initial_query_bytes": initial_query_bytes,
            "folded_query_bytes": folded_query_bytes,
            "fixed_proof_bytes": fixed_bytes,
            "proof_bytes": proof_bytes,
            "merkle_sibling_hashes": queries * sibling_hashes_per_query,
            "fri_fold_extension_values": queries * sum(1 << fold for fold in folds),
            "initial_committed_base_words": initial_committed_base_words,
            "folded_committed_base_words": folded_committed_base_words,
            "fft_scale_units": fft_scale_units,
            "conditional_fixed_set_bits": {
                "rate_1_over_32": fixed_set_bits(queries, lde_points, trace_rows),
                "one_quarter": fixed_set_bits(queries, lde_points, lde_points // 4),
                "one_half": fixed_set_bits(queries, lde_points, lde_points // 2),
            },
            "transcript_config_prefix": [
                RATE_BITS,
                CAP_HEIGHT,
                0,
                1,
                ARITY_BITS,
                FINAL_POLY_BITS,
                queries,
                1,
                trace_rows.bit_length() - 1,
                *folds,
            ],
        }
    )
    return row


def oplonky_screen(trace_rows: int, challenges: int) -> dict:
    """Illustrative substitution only; correspondence is not established."""
    first = challenges * math.log2(
        P / (3 * trace_rows * (ROUTED + PERMUTATION_CHUNK))
    )
    second = challenges * math.log2(
        P / (GATE_CONSTRAINT_VECTOR + (PERMUTATION_CHUNK + 2) * challenges - 1)
    )
    third = math.log2(
        (P**EXTENSION_DEGREE - trace_rows)
        / (max(GATE_DEGREE_BOUND, PERMUTATION_CHUNK + 1) * trace_rows)
    )
    return {
        "status": "illustrative_unproved_source_mapping",
        "permutation_term_negative_log2": first,
        "gate_batching_term_negative_log2": second,
        "single_extension_point_term_negative_log2": third,
        "minimum_individual_term_negative_log2": min(first, second, third),
    }


def measured_c_resources() -> dict:
    raw = json.loads(
        (ROOT / "experiments/funded-membership/evidence/COSTS.json").read_text()
    )
    wallets = [
        row
        for row in raw["wallet_measurements"].values()
        if row.get("packet_B") == 182_863
    ]
    groups = [
        row
        for row in raw["groups"]
        if row.get("submission_B") == 182_863 and row.get("operation") == "transfer"
    ]
    return {
        "source": "experiments/funded-membership/evidence/COSTS.json",
        "machine": raw["execution"],
        "proving_samples": len(wallets),
        "proving_wall_median_s": statistics.median(
            row["proving_wall_s"] for row in wallets
        ),
        "prover_cpu_median_s": statistics.median(row["prover_cpu_s"] for row in wallets),
        "prover_peak_rss_median_KiB": statistics.median(
            row["prover_role_peak_rss_KiB"] for row in wallets
        ),
        "warm_transfer_verification_samples": len(groups),
        "warm_transfer_native_cpu_median_s": statistics.median(
            row["warm_native_cpu_median_s"] for row in groups
        ),
        "warm_transfer_wall_median_s": statistics.median(
            row["warm_wall_median_s"] for row in groups
        ),
    }


def checked_sources() -> dict:
    paths = [
        "experiments/funded-membership/build_c.py",
        "experiments/funded-membership/hardening.patch",
        "experiments/managed-assets/native/profile.rs",
        "experiments/atomic-swap/native/profile.rs",
    ]
    return {
        path: sha256((ROOT / path).read_bytes()).hexdigest()
        for path in paths
    }


def calculate() -> dict:
    read_key = load_key_decoder()
    keys = {}
    for suite, role in ROLES.items():
        path = ROOT / "experiments/funded-membership/registry" / role["key"]
        raw = path.read_bytes()
        if sha256(raw).hexdigest() != role["key_sha256"]:
            raise ValueError(f"unexpected {suite} registration")
        parsed = read_key(raw)
        expected = {
            "pi": role["public_inputs"],
            "queries": 32,
            "trace_rows": 8192,
            "folds": [2, 2, 2, 2, 2],
            "challenges": 2,
        }
        actual = {
            "pi": parsed["common"]["pi"],
            "queries": parsed["config"]["fri"]["queries"],
            "trace_rows": parsed["trace_rows"],
            "folds": parsed["folds_bits"],
            "challenges": parsed["config"]["plonk_repetitions"],
        }
        if actual != expected:
            raise ValueError(f"unexpected {suite} parameters: {actual}")
        keys[suite] = {
            "sha256": role["key_sha256"],
            "bytes": len(raw),
            "circuit_digest": parsed["circuit_digest"],
            "decoded": actual,
        }

    profiles = {}
    for label, queries, challenges in (
        ("registered_C", 32, 2),
        ("proof_only_S64", 64, 3),
    ):
        profiles[label] = {}
        for suite, role in ROLES.items():
            profile = proof_profile(
                role["gates_before_blinding"],
                role["public_inputs"],
                queries,
                challenges,
            )
            if label == "registered_C" and profile["proof_bytes"] != role["proof_bytes"]:
                raise ValueError(f"{suite} proof size failed to reproduce")
            profile["ordinary_or_leg_frame_bytes"] = (
                profile["proof_bytes"] + role["frame_overhead_bytes"]
            )
            if suite == "MNG3":
                profile["signed_supply_frame_bytes"] = (
                    profile["proof_bytes"] + role["signed_frame_overhead_bytes"]
                )
            else:
                profile["complete_two_leg_swap_bytes"] = 13 + 2 * profile[
                    "ordinary_or_leg_frame_bytes"
                ]
            profile["illustrative_oplonky_terms"] = oplonky_screen(
                profile["trace_rows"], challenges
            )
            profiles[label][suite] = profile

    baseline = profiles["registered_C"]["MNG3"]
    stronger = profiles["proof_only_S64"]["MNG3"]
    comparison = {
        "status": "calculated_not_benchmarked",
        "proof_bytes_ratio": stronger["proof_bytes"] / baseline["proof_bytes"],
        "trace_rows_ratio": stronger["trace_rows"] / baseline["trace_rows"],
        "initial_commitment_cells_ratio": stronger["initial_committed_base_words"]
        / baseline["initial_committed_base_words"],
        "fft_scale_units_ratio": stronger["fft_scale_units"]
        / baseline["fft_scale_units"],
        "merkle_sibling_hashes_ratio": stronger["merkle_sibling_hashes"]
        / baseline["merkle_sibling_hashes"],
        "fri_fold_values_ratio": stronger["fri_fold_extension_values"]
        / baseline["fri_fold_extension_values"],
        "physical_frame_limit_bytes": 262_144,
        "S64_ordinary_excess_bytes": stronger["ordinary_or_leg_frame_bytes"] - 262_144,
    }

    return {
        "schema": "funded-pq-proof-parameters-v1",
        "claim_boundary": (
            "Exact key/geometry/serialization calculations and conditional screens; "
            "no end-to-end soundness, knowledge, zero-knowledge, or post-quantum claim."
        ),
        "field_prime": P,
        "qp_plonky2": {
            "crate_version": "1.5.5",
            "vcs_revision": "632f23ca07712bfa5bc8ed082bc05c41c5929dfb",
            "identity_check": (
                "not_performed; version and revision are project-declared pins, "
                "not hashes verified by this calculator"
            ),
        },
        "keys": keys,
        "profiles": profiles,
        "comparison": comparison,
        "registered_C_measured_resources": measured_c_resources(),
        "checked_project_sources": checked_sources(),
    }


if __name__ == "__main__":
    print(json.dumps(calculate(), indent=2, sort_keys=True))
