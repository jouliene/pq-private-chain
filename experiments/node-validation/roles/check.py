#!/usr/bin/env python3
"""Check key projections independently from the implementation functions."""
import hashlib
import json
import struct
import subprocess
import sys
from fractions import Fraction
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def execute(*options):
    return json.loads(subprocess.check_output([
        sys.executable, "-I", str(HERE / "project.py"), "--masked-body-bytes", "262850",
        "--aggregate-proof-bytes", "200000", *options,
    ]))


def exact(value):
    return Fraction(value["numerator"], value["denominator"]) if isinstance(value, dict) else Fraction(value)


def main():
    # An independent public-body readback checks the statement and two receipts
    # at their actual offsets. The standard Gate2 receipts check aggregate bytes.
    raw = (ROOT / "fixtures/cp03-reference/payer2x2.body").read_bytes()
    magic, version, statement, proof, authorization, reserved = struct.unpack_from("<8sHHIHH", raw)
    assert (magic, version, statement, authorization, reserved) == (b"CPBODY03", 3, 528, 0, 0)
    assert len(raw) - proof == 4876
    assert raw[548:556] == raw[2712:2720] == b"CPR3\x03\x01\0\0"

    baseline = execute()
    enhanced = execute("--block-reuse-percent", "100", "--extra-fork-blocks-per-year", "12",
                       "--reorg-wallet-resubmissions-per-year", "100",
                       "--wallet-deep-replays-at-first-year-end", "1",
                       "--wallet-blocks-per-range", "32", "--masked-mempool-us", "80000",
                       "--masked-block-payment-us", "100000", "--cp03-mempool-us", "73000",
                       "--capsule-block-payment-us", "100", "--aggregate-block-us", "50000")
    for identity in baseline["actual_public_cp03_evidence"]["files"].values():
        assert hashlib.sha256((ROOT / identity["path"]).read_bytes()).hexdigest() == identity["sha256"]
    assert baseline["actual_public_cp03_evidence"]["cp03"]["mean_body_bytes"] == {
        "numerator": 7005063, "denominator": 4,
    }

    masked = baseline["projections"]["masked_whir"]
    aggregate = baseline["projections"]["aggregate_cp03"]
    for inclusion, payments, blocks, last in (("100", 100_000_000, 1_041_667, 64),
                                              ("95", 95_000_000, 989_584, 32)):
        primary, fallback = masked[inclusion], aggregate[inclusion]
        assert primary["included_blocks"] == fallback["included_blocks"] == blocks
        assert primary["last_canonical_block_payments"] == last
        assert primary["canonical_block_bytes_per_one_retaining_copy_per_year"] == 262918 * payments + 228 * blocks
        assert fallback["canonical_block_bytes_per_one_retaining_copy_per_year"] == 5020 * payments + 200240 * blocks
        assert primary["validation"]["standalone_block_proof_checks_per_year"] == payments
        assert fallback["validation"]["ordered_aggregate_block_proof_checks_per_year"] == blocks
        assert fallback["validation"]["aggregate_prover_inner_cp03_checks_per_year_minimum"] == payments
        assert fallback["validation"]["mempool_checks_per_year"] == 100_000_000
        assert fallback["wallet"]["annual_network_wide_originator_upload_bytes_including_nonincluded"] == 175_127_775_000_000
        assert fallback["relay_default"]["mempool"]["ingress_bytes"] == 175_178_175_000_000
        public_scan = 5020 * payments + 232 * blocks
        live = fallback["wallet"]["ordinary_synchronized_wallet_common_history"]
        assert live["history_frames_bytes"] == public_scan
        assert live["response_bytes"] == public_scan + 436 * blocks
        assert live["ingress"] == public_scan + 692 * blocks
        assert live["egress"] == 508 * blocks
        cold = fallback["cold_recovery_by_years"]["5"]["wallet_delegating_validity"]
        assert cold["ingress"] == 5 * public_scan + 692
        assert cold["cold_total_ingress_bytes"] == 5 * public_scan + 692 + 254_584 + 52
        assert cold["cold_total_egress_bytes"] == 508 + 52
        assert cold["trial_decapsulation_upper_counts_by_retained_keys"]["32"] == 320 * payments
        block_only = fallback["independent_block_only_validator"]
        assert block_only["mempool_checks"] == 0
        assert block_only["relay"]["ingress_bytes"] == 5020 * payments + 200756 * blocks
        assert block_only["steady_link_can_service_mean"]
        assert not fallback["home_service"]["steady_link_can_service_mean_default"]
        adjusted = enhanced["projections"]["aggregate_cp03"][inclusion]
        assert adjusted["block_body_or_capsule_bytes_each"] == 4952
        assert adjusted["validation"]["mempool_checks_per_year"] == 100_000_100
        assert adjusted["validation"]["block_state_checks_per_payment"] == payments + 1152
        assert adjusted["validation"]["annual_cpu_microseconds_if_explicitly_supplied"] == (
            100_000_100 * 73000 + (payments + 1152) * 100 + (blocks + 12) * 50000
        )
        assert adjusted["wallet"]["ordinary_synchronized_wallet_common_history"]["history_frames_bytes"] == (
            public_scan * 2 + 12 * (5020 * 96 + 232)
        )
        assert adjusted["relay_default"]["block"]["egress_bytes"] == (
            (payments + 1152) * 68 + (blocks + 12) * 200756
        )
        assert adjusted["independent_block_only_validator"]["relay"]["egress_bytes"] > adjusted["relay_default"]["block"]["egress_bytes"]

    primary = masked["100"]
    steady = primary["home_service"]
    assert exact(primary["relay_default"]["total"]["mean_egress_bps"]) > 13_000_000
    assert steady["steady_link_can_service_mean_default"] and not steady["network_only_burst"]["clears_within_research_target"]
    block_only = primary["independent_block_only_validator"]
    assert block_only["network_only_burst"]["clears_within_research_target"]
    cpu = block_only["masked_standalone_block_cpu_budget_if_applicable"]
    rates = Fraction(100_000_000, 365 * 86400) + Fraction(100_000_000, 90 * 86400)
    assert exact(cpu["total_payments_per_second_while_catching_up"]) == rates
    by_cores = cpu["budgets_by_available_core_seconds_per_second"]
    assert exact(by_cores["2"]["cold_while_live_total_cpu_seconds_per_payment_ceiling"]) == 2 / rates
    assert exact(by_cores["4"]["cold_while_live_total_cpu_seconds_per_payment_ceiling"]) == 4 / rates
    matrix = baseline["actual_public_masked_matrix_component_evidence_if_present"]
    if matrix is not None:
        samples = [exact(value) for value in matrix["public_matrix_guard_and_first_main_fold_thread_cpu_seconds"]]
        assert all(sample > 2 / rates for sample in samples)
        assert min(samples) < 4 / rates < max(samples)
        assert all(sample < exact(by_cores["2"]["steady_total_cpu_seconds_per_payment_ceiling"]) for sample in samples)
    ceilings = primary["masked_whir_network_body_ceiling_if_applicable"]
    assert 275881 < exact(ceilings["independent_block_only"]["burst_drain_max_mean_complete_body_bytes"]) < 275882
    assert 137682 < exact(ceilings["mempool_and_blocks"]["burst_drain_max_mean_complete_body_bytes"]) < 137683
    assert block_only["pruned_disk_by_years"]["5"]["covered_pruned_disk_fits_research_disk"]
    assert not block_only["pruned_disk_by_years"]["10"]["covered_pruned_disk_fits_research_disk"]
    assert sum(block_only["pruned_disk_by_years"]["1"]["selected_permanent_state_fields_bytes"].values()) == 83_200_001_216
    retained = aggregate["100"]["archive"]["single_copy_disk_payload_bytes_by_policy_and_years"]
    assert retained["canonical"]["1"] == 710_583_400_080
    assert retained["canonical_plus_inner_proofs_for_included_and_fork_records"]["1"] == 175_349_970_900_084
    assert retained["canonical_plus_all_offered_full_cp03_and_fork_only_inner_proofs"]["1"] == 175_837_570_900_084
    print("PASS: public byte readback and 95%/100% role arithmetic, custody, burst and recovery controls")


if __name__ == "__main__":
    main()
