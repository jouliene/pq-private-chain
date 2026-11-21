#!/usr/bin/env python3
"""Deterministic ideal-function lifetime target calculations.

This calculator prices only generic search and collision benchmarks.  It does
not assign a security level to Poseidon2, the payment proof, or their
composition.
"""

from __future__ import annotations

import argparse
import json
from decimal import Context, Decimal, ROUND_CEILING
from pathlib import Path


GOLDILOCKS_ORDER = 2**64 - 2**32 + 1
OWNER_OFFERED_PAYMENTS_PER_YEAR = 100_000_000
DEFAULT_YEARS = 20
TARGET_QUANTUM_BITS = 128
REPRESENTATIVE_QUERY_EXPONENTS = (64, 96, 112, 128)
ILLUSTRATIVE_ORACLE_QUERIES_PER_SECOND = 10**12
SECONDS_PER_JULIAN_YEAR = 31_557_600
CONTEXT = Context(prec=90)
SIX_PLACES = Decimal("0.000001")


def log2_integer(value: int) -> Decimal:
    if type(value) is not int or value <= 0:
        raise ValueError("log2 input must be a positive integer")
    return CONTEXT.divide(CONTEXT.ln(Decimal(value)), CONTEXT.ln(Decimal(2)))


def bits(value: Decimal) -> str:
    return str(value.quantize(SIX_PLACES, rounding=ROUND_CEILING))


def ceil_div(numerator: int, denominator: int) -> int:
    if denominator <= 0 or numerator < 0:
        raise ValueError("invalid nonnegative ratio")
    return (numerator + denominator - 1) // denominator


def ceil_cube_root(value: int) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError("cube-root input must be a positive integer")
    low, high = 0, 1
    while high**3 < value:
        high *= 2
    while high - low > 1:
        middle = (low + high) // 2
        if middle**3 < value:
            low = middle
        else:
            high = middle
    return high


def scientific_ratio(numerator: int, denominator: int) -> str:
    return format(CONTEXT.divide(Decimal(numerator), Decimal(denominator)), ".12E")


def serial_years(query_bits: Decimal) -> dict[str, str]:
    divisor = ILLUSTRATIVE_ORACLE_QUERIES_PER_SECOND * SECONDS_PER_JULIAN_YEAR
    log_years = query_bits - log2_integer(divisor)
    years = CONTEXT.divide(CONTEXT.power(Decimal(2), query_bits), Decimal(divisor))
    return {"log2_years": bits(log_years), "years_scientific": format(years, ".12E")}


def grover_probability_rows(limbs: int, targets: int) -> list[dict[str, object]]:
    space = GOLDILOCKS_ORDER**limbs
    rows = []
    for target_label, usable in (("single_target", 1), ("scenario_targets", targets)):
        trials = []
        for exponent in REPRESENTATIVE_QUERY_EXPONENTS:
            queries = 1 << exponent
            numerator = (2 * queries + 1) ** 2 * usable
            capped = numerator >= space
            ratio = scientific_ratio(min(numerator, space), space)
            raw = CONTEXT.divide(Decimal(numerator), Decimal(space))
            trials.append(
                {
                    "q": f"2^{exponent}",
                    "success_probability_upper_bound": ratio,
                    "small_angle_success_estimate": format(raw, ".12E") if raw <= Decimal("0.01") else None,
                    "regime": "small-angle" if raw <= Decimal("0.01") else "bound-saturated-or-post-first-peak",
                    "upper_bound_capped_at_one": capped,
                }
            )
        rows.append({"target_set": target_label, "usable_targets": usable, "queries": trials})
    return rows


def lifetime_union_bound(attempts: int, per_attempt_bits: int = 128) -> dict[str, object]:
    denominator = 1 << per_attempt_bits
    return {
        "attempts": attempts,
        "per_attempt_failure_bound": f"2^-{per_attempt_bits}",
        "any_failure_probability_upper_bound": scientific_ratio(min(attempts, denominator), denominator),
        "remaining_negative_log2_bound": bits(Decimal(per_attempt_bits) - log2_integer(attempts)),
        "requires_each_attempt_bound_conditioned_on_complete_prior_transcript": True,
    }


def scenario_targets() -> list[dict[str, object]]:
    offered = OWNER_OFFERED_PAYMENTS_PER_YEAR * DEFAULT_YEARS
    return [
        {
            "id": "one_target_per_offered_payment_20y",
            "targets": offered,
            "owner_inputs": {
                "offered_payments_per_year": OWNER_OFFERED_PAYMENTS_PER_YEAR,
            },
            "researcher_assumptions": {
                "years": DEFAULT_YEARS,
                "usable_targets_per_offered_payment": 1,
                "accepted_fraction": "1/1",
                "reward_targets": 0,
            },
        },
        {
            "id": "mixed_outputs_20y_100pct",
            "targets": offered * 22 // 10,
            "owner_inputs": {
                "offered_payments_per_year": OWNER_OFFERED_PAYMENTS_PER_YEAR,
            },
            "researcher_assumptions": {
                "years": DEFAULT_YEARS,
                "accepted_fraction": "1/1",
                "ordinary_fraction": "9/10",
                "ordinary_outputs": 2,
                "swap_fraction": "1/10",
                "swap_outputs": 4,
                "reward_targets": 0,
            },
        },
        {
            "id": "mixed_outputs_20y_95pct",
            "targets": offered * 22 * 95 // 1000,
            "owner_inputs": {
                "offered_payments_per_year": OWNER_OFFERED_PAYMENTS_PER_YEAR,
            },
            "researcher_assumptions": {
                "years": DEFAULT_YEARS,
                "accepted_fraction": "19/20",
                "ordinary_fraction": "9/10",
                "ordinary_outputs": 2,
                "swap_fraction": "1/10",
                "swap_outputs": 4,
                "reward_targets": 0,
            },
        },
        {
            "id": "four_outputs_per_offer_20y",
            "targets": offered * 4,
            "owner_inputs": {
                "offered_payments_per_year": OWNER_OFFERED_PAYMENTS_PER_YEAR,
            },
            "researcher_assumptions": {
                "years": DEFAULT_YEARS,
                "accepted_fraction": "1/1",
                "usable_targets_per_offered_payment": 4,
                "reward_targets": 0,
            },
        },
    ]


def minimum_limbs(targets: int, security_bits: int, game: str) -> int:
    target_log = log2_integer(targets)
    limb_entropy = log2_integer(GOLDILOCKS_ORDER)
    limbs = 1
    while True:
        entropy = limb_entropy * limbs
        if game == "multi_target_preimage":
            work = (entropy - target_log) / 2
        elif game == "arbitrary_collision":
            work = entropy / 3
        else:
            raise ValueError("unknown game")
        if work >= security_bits:
            return limbs
        limbs += 1


def profile(limbs: int, targets: int) -> dict[str, object]:
    entropy = log2_integer(GOLDILOCKS_ORDER) * limbs
    target_log = log2_integer(targets)
    pair_count = targets * (targets - 1) // 2
    accidental = log2_integer(pair_count) - entropy if pair_count else Decimal("-Infinity")
    target_queries = (entropy - target_log) / 2
    collision_queries = entropy / 3
    bht_entries = ceil_cube_root(GOLDILOCKS_ORDER**limbs)
    target_table_bytes = targets * limbs * 8
    return {
        "limbs": limbs,
        "encoded_bytes": limbs * 8,
        "ideal_range_log2": bits(entropy),
        "classical_single_target_preimage_query_bits": bits(entropy),
        "quantum_single_target_preimage_query_bits": bits(entropy / 2),
        "classical_multi_target_preimage_query_bits": bits(entropy - target_log),
        "quantum_multi_target_preimage_query_bits": bits(target_queries),
        "quantum_arbitrary_collision_query_bits": bits(collision_queries),
        "honest_pair_collision_union_bound_log2": bits(accidental),
        "usable_target_table": {
            "entries": targets,
            "raw_digest_bytes": target_table_bytes,
            "raw_digest_gib": format(CONTEXT.divide(Decimal(target_table_bytes), Decimal(1 << 30)), ".12E"),
            "lookup_assumption": "unit-cost coherent membership over all entries (qRAM/oracle); excludes addressing, loading, error correction and circuit gates",
        },
        "grover_probability_examples": grover_probability_rows(limbs, targets),
        "bht_original": {
            "query_exponent_log2": bits(collision_queries),
            "time_exponent_log2_in_unit_cost_oracle_model": bits(collision_queries),
            "list_entries_at_least": bht_entries,
            "raw_digest_list_bytes_at_least": bht_entries * limbs * 8,
            "raw_digest_list_bytes_log2": bits(log2_integer(bht_entries * limbs * 8)),
            "qualification": "original sampled-list plus Grover construction; storage excludes indices, reversible lookup circuitry and fault tolerance",
        },
        "bht_sampled_list_tradeoff": {
            "parameter": "for list memory M=|range|^s, setup M and Grover search sqrt(|range|/M) give query/time exponent max(s,(1-s)/2)",
            "constant_memory_endpoint_query_bits": bits(entropy / 2),
            "one_fifth_memory_query_bits": bits(entropy * Decimal(2) / 5),
            "one_fifth_memory_bits": bits(entropy / 5),
            "optimal_bht_memory_and_query_bits": bits(entropy / 3),
            "qualification": "conservative parameterization of the original BHT construction, not a physical low-memory implementation",
        },
        "cns_no_qram_collision_screen": {
            "query_exponent_log2_soft_O": bits(entropy * Decimal(2) / 5),
            "time_exponent_log2_soft_O_single_processor": bits(entropy * Decimal(2) / 5),
            "classical_memory_exponent_log2_soft_O": bits(entropy / 5),
            "quantum_memory": "O(n) qubits",
            "nominal_range_bits_n": bits(entropy),
            "rough_linear_qubit_scale_without_hidden_constant": limbs * 64,
            "source": "Chailloux-Naya-Plasencia-Schrottenloher, IACR ePrint 2017/847",
            "qualification": "ideal random-function soft-O screen without qRAM; nominal exponents substitute log2(p^limbs) for n and do not establish Poseidon2 or monetary security",
        },
        "illustrative_serial_unit_cost_runtime": {
            "oracle_queries_per_second": ILLUSTRATIVE_ORACLE_QUERIES_PER_SECOND,
            "multi_target_preimage": serial_years(target_queries),
            "arbitrary_collision_bht": serial_years(collision_queries),
            "qualification": "query-model conversion only; one oracle query is not one CPU operation and no reversible Poseidon2/qRAM cost is included",
        },
    }


def calculate() -> dict[str, object]:
    scenarios = []
    for source in scenario_targets():
        targets = int(source["targets"])
        scenarios.append(
            source
            | {
                "target_log2": bits(log2_integer(targets)),
                "lifetime_union_bound_if_one_attempt_per_usable_target": lifetime_union_bound(targets),
                "profiles": [profile(limbs, targets) for limbs in (4, 5, 6, 7)],
                "minimum_goldilocks_limbs_for_128_bit_quantum_multi_target_preimage": minimum_limbs(
                    targets, TARGET_QUANTUM_BITS, "multi_target_preimage"
                ),
                "minimum_goldilocks_limbs_for_128_bit_quantum_arbitrary_collision": minimum_limbs(
                    targets, TARGET_QUANTUM_BITS, "arbitrary_collision"
                ),
            }
        )
    return {
        "schema": "funded-binding-lifetime-v2",
        "field": {
            "name": "Goldilocks",
            "order": GOLDILOCKS_ORDER,
            "order_expression": "2^64 - 2^32 + 1",
        },
        "model": {
            "multi_target_preimage": "ideal constant-success Grover/Boyer query scale (log2(|range|/T))/2; probability rows use min(1,(2q+1)^2*T/|range|) as an upper envelope and show the same expression as a small-angle estimate only at <=0.01",
            "arbitrary_collision": "original BHT ideal query/time exponent log2(|range|)/3 with at least |range|^(1/3) list entries",
            "no_qram_collision_screen": "CNS 2017 ideal soft-O query/time 2n/5, polynomial O(n) quantum memory and classical memory exponent n/5; n is instantiated as log2(|range|)",
            "honest_pair_collision": "union bound C(T,2)/|range|",
            "target_membership": "multi-target query exponents assume unit-cost coherent membership in a complete usable-target table; raw bytes are reported but qRAM construction is not",
            "physical_runtime": f"illustrative serial conversion at {ILLUSTRATIVE_ORACLE_QUERIES_PER_SECOND} ideal oracle queries/second; not a hardware or Poseidon2 runtime estimate",
            "lifetime_composition": "R*epsilon union bound requires a conditional epsilon after every prior adaptive transcript and does not convert a query exponent into such an epsilon",
            "qualification": "generic ideal-function query benchmarks only; not a reduction, Poseidon2 analysis, proof-system bound or monetary-security claim",
        },
        "representative_query_counts": [f"2^{value}" for value in REPRESENTATIVE_QUERY_EXPONENTS],
        "researcher_lifetime_attempt_example": lifetime_union_bound(
            OWNER_OFFERED_PAYMENTS_PER_YEAR * DEFAULT_YEARS
        ),
        "scenarios": scenarios,
    }


def encoded() -> bytes:
    return (json.dumps(calculate(), indent=2, sort_keys=True) + "\n").encode()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", type=Path, metavar="PATH")
    mode.add_argument("--check", type=Path, metavar="PATH")
    args = parser.parse_args()
    result = encoded()
    if args.write:
        args.write.write_bytes(result)
    elif args.check:
        if args.check.read_bytes() != result:
            raise SystemExit(f"stale result: {args.check}")
    else:
        print(result.decode(), end="")


if __name__ == "__main__":
    main()
