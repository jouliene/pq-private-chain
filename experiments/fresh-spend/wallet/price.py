"""Price the widened ZKB++/Unruh wire and component work."""
import argparse
import json
from math import ceil, log2
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "binding"))
from side import schedule

PERMUTATIONS = 99
GATES = sum(schedule().values())
VIEW_BYTES = (GATES + 7) // 8
WITNESS_BYTES = 6_155
DIGEST_BYTES = 64
ORDINARY_NONPROOF_BYTES = 3_990
SIGNED_NONPROOF_BYTES = 33_918
SWAP_FRAMING_BYTES = 20
SECONDS_PER_YEAR = 365.25 * 24 * 60 * 60


def proof_bytes(rounds, seed_bytes, transcript_bytes=VIEW_BYTES, witness_bytes=WITNESS_BYTES):
    return (rounds + 3) // 4 + 32 + rounds * (
        DIGEST_BYTES + 3 * seed_bytes + 2 * transcript_bytes + witness_bytes
    )


def work(rounds, seeds):
    a, w, d = VIEW_BYTES, WITNESS_BYTES, DIGEST_BYTES
    challenge = rounds * (3 * (a + seeds) + w + 3 * d + 1)
    # Count the longer hidden image on every second-pass repetition and
    # the explicit correction share on every opened verifier pair.
    return {
        "prover": {
            "permutation_calls": 2 * rounds * PERMUTATIONS,
            "tape_xof_bytes": 2 * rounds * (3 * a + 2 * w),
            "view_hash_bytes": rounds * 3 * (a + w + d + 1),
            "g_absorb_bytes": rounds * (4 * (a + d + 4) + 2 * w),
            "g_squeeze_bytes": rounds * (4 * (a + seeds) + 2 * w),
            "challenge_absorb_bytes": challenge,
            "planned_buffers_bytes": 3 * rounds * seeds + 7 * a + 6 * w + seeds + 65536,
        },
        "verifier": {
            "permutation_calls": rounds * PERMUTATIONS,
            "tape_xof_bytes": rounds * (2 * a + 2 * w),
            "view_hash_bytes": rounds * 2 * (a + w + d + 1),
            "g_absorb_bytes": rounds * (2 * (a + d + 4) + w),
            "g_squeeze_bytes": rounds * (2 * (a + seeds) + w),
            "challenge_absorb_bytes": challenge,
            "planned_buffers_bytes": 6 * a + 6 * w + seeds + 65536,
        },
    }


def cpu_subtotal(role, amounts, sample):
    kernel = "prover" if role == "prover" else "verifier"
    return (
        amounts["permutation_calls"] * sample[f"{kernel}_cpu_ns_per_keccak_f"] / 1e9
        + (amounts["tape_xof_bytes"] + amounts["g_squeeze_bytes"])
        / sample["shake256_squeeze_B_per_cpu_s"]
        + (amounts["g_absorb_bytes"] + amounts["challenge_absorb_bytes"] + amounts["view_hash_bytes"])
        / sample["shake256_absorb_B_per_cpu_s"]
    )


def traffic(ordinary, swap):
    # Comparison scenario, with every offered economic operation accepted.
    legs = 110_000_000
    per_node = 90_000_000 * ordinary + 10_000_000 * swap
    return {
        "one_archive_or_one_relay_copy_bytes_per_year": per_node,
        "mean_ingest_Gbps": round(per_node * 8 / SECONDS_PER_YEAR / 1e9, 3),
        "twenty_year_archive_bytes": 20 * per_node,
        "ordinary_wallet_upload_s_at_20Mbps": round(ordinary * 8 / 20e6, 3),
        "ordinary_node_download_s_at_100Mbps": round(ordinary * 8 / 100e6, 3),
        "whole_swap_upload_s_at_20Mbps": round(swap * 8 / 20e6, 3),
        "legs_per_year": legs,
    }


def result(samples):
    assert proof_bytes(438, 32, 143, 32) == 209_506
    options = []
    for rounds, seeds in ((438, 32), (438, 64), (560, 64), (660, 64), (797, 64), (879, 64)):
        p = proof_bytes(rounds, seeds)
        ordinary = p + ORDINARY_NONPROOF_BYTES
        signed = p + SIGNED_NONPROOF_BYTES
        swap = SWAP_FRAMING_BYTES + 2 * signed
        workload = traffic(ordinary, swap)
        operations = work(rounds, seeds)
        timings = {
            role: [round(cpu_subtotal(role, counts, sample), 3) for sample in samples]
            for role, counts in operations.items()
        }
        options.append({
            "repetitions": rounds, "seed_bytes": seeds,
            "proof_bytes": p, "ordinary_bytes": ordinary, "signed_leg_bytes": signed,
            "swap_bytes": swap, "signed_leg_excess_over_262144": signed - 262_144,
            "bad_challenge_log2_upper_at_2pow128_ideal_queries": round(
                1 + log2(2**128 + 1) - rounds * log2(1.5) / 2, 4
            ),
            "work": operations, "modeled_kernel_cpu_s_by_sample": timings,
            "traffic": workload,
            "mean_cores_verification_subtotal": [
                round(t * workload["legs_per_year"] / SECONDS_PER_YEAR, 2)
                for t in timings["verifier"]
            ],
        })
    return {
        "relation_permutations": PERMUTATIONS, "relation_and_gates": GATES,
        "one_packed_and_trace_bytes": VIEW_BYTES, "witness_bytes": WITNESS_BYTES,
        "stock_lowmc_l5_signature_bytes": proof_bytes(438, 32, 143, 32),
        "max_ands_under_ordinary_frame_at_438_rounds_even_ignoring_other_bytes":
            (262_144 - ORDINARY_NONPROOF_BYTES) // (2 * 438) * 8,
        "max_ands_under_signed_frame_at_438_rounds_even_ignoring_other_bytes":
            (262_144 - SIGNED_NONPROOF_BYTES) // (2 * 438) * 8,
        "comparison_profiles": options,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("components", type=Path, nargs="?", default=HERE / "COMPONENTS.json")
    args = parser.parse_args()
    components = json.loads(args.components.read_text())
    print(json.dumps(result(components["calibration"]), indent=2))
