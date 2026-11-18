"""Recalculate role projections from actual whole-payment, durable and two-wallet evidence."""
import argparse
import hashlib
import importlib.util
import json
import math
from fractions import Fraction
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OLD = HERE.parent / "node-validation/roles"
spec = importlib.util.spec_from_file_location("node_validation_roles", OLD / "project.py")
roles = importlib.util.module_from_spec(spec)
spec.loader.exec_module(roles)
TB = 10**12
DAY = roles.DAY
SOURCE = {}


def read(path):
    path = Path(path)
    data = path.read_bytes()
    SOURCE[str(path.relative_to(ROOT))] = hashlib.sha256(data).hexdigest()
    return json.loads(data, parse_float=Fraction)


def avg(values):
    return sum(values, Fraction()) / len(values)


def rounded(x):
    if isinstance(x, dict):
        return {k: rounded(v) for k, v in x.items()}
    if isinstance(x, list):
        return [rounded(v) for v in x]
    if isinstance(x, Fraction):
        return x.numerator if x.denominator == 1 else round(float(x), 9)
    return x


def archive(bytes_per_year, yearsize_days=365):
    return {
        "single_archive_B_per_year": bytes_per_year,
        "three_independent_copies_B_per_year": 3 * bytes_per_year,
        "max_retention_days_by_decimal_TB": {
            str(tb): tb * TB * yearsize_days / bytes_per_year for tb in (1, 5)
        },
    }


def cpu_replay(accepted, seconds, cores, cost):
    live = accepted / Fraction(seconds)
    remaining = cores / cost - live
    return accepted / (remaining * DAY) if remaining > 0 else None


def structured(profile, receipt, durable):
    created = receipt["generated"]["produced"]
    records = durable["backend"]["backend"]["records"]
    assert len(created) == len(records) == durable["records"] == 3
    assert all(a["accepted"] and r["accepted"] and a["proof_bytes"] == r["proof_bytes"]
               and a["body_bytes"] == a["proof_bytes"] + roles.BODY_PREFIX
               for a, r in zip(created, records, strict=True))
    ledger = durable["ledger_cpu_s"] / 3
    crypto = avg([r["post_preparation_thread_cpu_s"] for r in records])
    setup = durable["backend"]["backend"]["matrix_preparation_thread_cpu_s"]
    cost = crypto + ledger
    ticks = Fraction(1, 3 * durable["cpu_tick_hz"])
    assert abs(cost * 3 - durable["post_preparation_proof_plus_ledger_group_cpu_s"]) < Fraction(1, 10**9)
    assert durable["retained_body_bytes"] == sum(p["body_bytes"] for p in created)
    mean = avg([p["body_bytes"] for p in created])
    cold = receipt["public_replay"]["admissions"]
    cold_proof = avg([r["cpu_user_s"] + r["cpu_system_s"] for r in cold])
    # A second pre-inclusion cryptographic pass is charged at the observed
    # post-preparation mean. Current-state reads specific to a live pool are extra.
    costs = dict(mempool_payment_us=math.ceil(crypto * 10**6),
                 block_payment_us=math.ceil(cost * 10**6), block_aggregate_us=None)
    sizes = dict(mempool=mean, included=mean, aggregate=0,
                 mempool_max=272556, included_max=272556)
    profile["archive"]["cold_genesis_context_bytes"] = receipt["files"]["genesis.bin"]["bytes"]
    data = {}
    for percent in profile["include_percentages"]:
        s = roles.project_route("masked_whir", percent, profile, sizes, costs, None)
        home = profile["home"]
        included = s["annual_included"]
        blocks = s["included_blocks"]
        seconds = profile["year_days"] * DAY
        rate = Fraction(profile["annual_offers"], seconds)
        accepted_rate = Fraction(included, seconds)
        cores = home["validation_core_seconds_per_second"]
        one_year = s["independent_block_only_validator"]["block_only_cold_recovery_by_years"]["1"]
        wallet_live = s["wallet"]["ordinary_synchronized_wallet_common_history"]
        wallet_cold = s["cold_recovery_by_years"]["1"]["wallet_delegating_validity"]
        block_only = s["independent_block_only_validator"]
        net = block_only["network_only_offers_per_second_equivalent"]
        cpu_ceiling = cores / (cost * Fraction(percent, 100))
        serial_ledger_ceiling = 1 / ((durable["ledger_elapsed_s"] / 3) * Fraction(percent, 100))
        capacity = min(net, cpu_ceiling, serial_ledger_ceiling)
        burst = profile["burst"]
        tx = lambda row: row["mean_egress_bps"] / 10**6
        fit = archive(s["canonical_block_bytes_per_one_retaining_copy_per_year"])
        fit.update({
            "wallets_total_originated_B_including_12B_framing": s["wallet"]["annual_network_wide_originator_upload_bytes_including_nonincluded"],
            "builder_wallet_intake_B_before_peer_egress": profile["annual_offers"] * mean,
            "distributed_wallet_proving_mean_cores_for_all_offers": rate*avg([x["cpu_user_s"]+x["cpu_system_s"] for x in created]),
            "strict_tip_no_speculation_fixture_path_s_per_dependent_payment": avg([x["elapsed_s"] for x in created])+avg([x["admission_elapsed_s"] for x in cold]),
            "fits_1_and_5_decimal_TB_archive": [fit["single_archive_B_per_year"] <= limit * TB for limit in (1, 5)],
            "builder_mempool_plus_block_proof_and_state_core_floor": (
                profile["annual_offers"] * crypto + included * cost) / seconds,
            "primary_archive_two_replica_payload_only_Mbps": fit["single_archive_B_per_year"] * 16 / seconds / 10**6,
            "primary_archive_two_replicas_plus_full_stream_Mbps_with_RPC": tx(s["archive"]["primary_replication_and_full_stream"]),
            "mempool_plus_blocks_upload_Mbps": tx(s["relay_default"]["total"]),
            "block_only_upload_Mbps": tx(block_only["relay"]),
            "mempool_only_upload_Mbps": tx(s["relay_default"]["mempool"]),
            "mempool_and_block_all_six_copy_upload_Mbps": tx(s["relay_all_inventory_peers_fetch_payloads_sensitivity"]["total"]),
            "mempool_and_block_perfect_phase_reuse_lower_upload_Mbps": tx(s["relay_perfect_cross_phase_cache_sensitivity"]["total"]),
            "block_only_mean_warm_core_seconds_per_second": accepted_rate * cost,
            "block_only_90d_plus_live_cpu_budget_s": cores / (accepted_rate + Fraction(included, 90*DAY)),
            "block_only_90d_plus_live_warm_cores_required": cost * (accepted_rate + Fraction(included, 90*DAY)),
            "cold_process_per_body_steady_cryptographic_cores_before_ledger": accepted_rate * cold_proof,
            "requested_90d_combined_ingress_Mbps": one_year["required_application_ingress_bps_plus_live_for_research_deadline"]/10**6,
            "one_year_replay_link_only_days_while_live": one_year["link_only_ideal_seconds_at_residual_after_live"] / DAY,
            "one_year_replay_cpu_only_days_while_live_warm": cpu_replay(included, seconds, cores, cost),
            "one_year_replay_cpu_only_days_while_live_setup_once_per_three": cpu_replay(included, seconds, cores, cost+setup/3),
            "one_year_replay_cpu_only_days_while_live_setup_once_per_96": cpu_replay(included, seconds, cores, cost+setup/96),
            "one_year_replay_cpu_only_days_while_live_one_process_per_body": cpu_replay(included, seconds, cores, cold_proof+ledger),
            "one_year_replay_links_cpu_independent_floor_days": max(one_year["link_only_ideal_seconds_at_residual_after_live"]/DAY, cpu_replay(included,seconds,cores,cost)),
            "one_year_pruned_disk_B_block_only": block_only["pruned_disk_by_years"]["1"]["planned_pruned_disk_bytes"],
            "five_year_pruned_disk_B_block_only": block_only["pruned_disk_by_years"]["5"]["planned_pruned_disk_bytes"],
            "blocks_per_year": blocks,
            "block_only_10x600s_drain_s_including_warm_cpu_serial_ledger_sensitivity": roles.burst_case(rate,rate*10,seconds,burst,capacity,profile["payments_per_block"],mean)["drain_after_burst_seconds_if_stable"],
            "mempool_and_block_10x600s_drain_s_network_and_cpu": s["home_service"]["network_and_cpu_burst_if_supplied"]["drain_after_burst_seconds_if_stable"],
            "block_only_100_per_s_for_600s_drain_s_network_and_cpu": roles.burst_case(rate,Fraction(100),seconds,burst,capacity,profile["payments_per_block"],mean)["drain_after_burst_seconds_if_stable"],
            "cold_validity_delegating_wallet": {key: wallet_cold[key] for key in
                ("cold_total_ingress_bytes","ideal_downlink_only_seconds","trial_decapsulation_upper_counts_by_retained_keys")},
            "live_validity_delegating_wallet_ingress_and_egress_B": [wallet_live["ingress"],wallet_live["egress"]],
            "full_verifying_wallet_replay_B_before_own_scan": s["cold_recovery_by_years"]["1"]["full_verifying_wallet"]["raw_block_download_bytes"],
        })
        data[str(percent)] = fit
    return {"measurements":{"body_B_mean":mean,"proof_B":[x["proof_bytes"] for x in created],
                            "prover_wall_s":[x["elapsed_s"] for x in created],"prover_peak_kib":max(x["peak_rss_kib"] for x in created),
                            "cold_per_body_verifier_cpu_mean_s":cold_proof,"cold_whole_admission_wall_mean_s":avg([x["admission_elapsed_s"] for x in cold]),
                            "warm_proof_cpu_per_body_s":crypto,"ordered_durable_ledger_cpu_per_body_s":ledger,
                            "ledger_group_child_tick_resolution_per_body_s":ticks,
                            "durable_ledger_wall_per_body_s":durable["ledger_elapsed_s"]/3,"warm_proof_plus_ledger_s":cost,
                            "cold_prepare_cpu_s":setup,"three_body_cold_verify_plus_state_elapsed_s":durable["whole_path_elapsed_s"],
                            "sqlite_B_3_payments":durable["sqlite_bytes"],"SQLite_retained_body_B":durable["retained_body_bytes"]},
            "scenarios":data}


def native(profile, receipt):
    """One packet per observed two-payment native transition; no wider occupancy."""
    submissions = receipt["wallet_submissions"]
    assert len(submissions) == 2 and receipt["opened_notes_per_wallet"] == [2, 2]
    assert receipt["published_ciphertexts"] == 4 and receipt["final_state"] == [3, 10, 6, 9]
    pair = receipt["pair_body_bytes"]
    assert pair == receipt["pair_proof_bytes"] + 8 + 4 * 1792
    scan = receipt["pair_history_bytes"]
    assert scan == 4 * (32 + 1792)
    meters = receipt["roles"]

    def measured(role, op):
        return [r for r in meters[role] if r["operation"] == op]

    wallet = [measured(role, "wallet_create")[0] for role in ("wallet_a", "wallet_b")]
    builder, = measured("builder", "verify_two_and_prove_pair")
    accepted = measured("node", "accepted")
    assert len(accepted) == 2
    verify, singleton = accepted
    # Each new height/parent is selected only after successful application.
    chain = max(v["elapsed_s"] for v in wallet) + builder["elapsed_s"] + verify["elapsed_s"]
    seconds = profile["year_days"] * DAY
    home = profile["home"]
    offers = profile["annual_offers"]
    mean = Fraction(offers, seconds)
    up = home["line_upload_bps"] * home["useful_application_percent"] // 100
    down = home["line_download_bps"] * home["useful_application_percent"] // 100
    relay = profile["relay"]
    peers = relay["inventory_peers"]
    packet = avg(submissions)
    data = {}
    for pct in profile["include_percentages"]:
        included = offers * pct // 100
        assert included % 2 == 0
        pairs = included // 2
        # Both the originating private wallet proof and the final pair transcript
        # are transmitted. A cached wallet proof cannot reconstruct the outer argument.
        pending = roles.gossip(offers, offers * packet, peers, relay["mempool_payload_peers"])
        blocks = roles.gossip(pairs, pairs * pair, peers, relay["block_payload_peers"])
        def mbps(raw):
            return Fraction(raw * 8, seconds * 10**6)
        def capacity(ingress, egress):
            return mean * min(Fraction(down * seconds, 8 * ingress), Fraction(up * seconds, 8 * egress))
        def drain(cap):
            return roles.burst_case(mean, mean * 10, seconds, profile["burst"], cap, 2, packet)["drain_after_burst_seconds_if_stable"]

        link = capacity(blocks["ingress"], blocks["egress"])
        both = capacity(blocks["ingress"] + pending["ingress"], blocks["egress"] + pending["egress"])
        canonical = pairs * pair
        history = pairs * scan
        pair_rate = Fraction(pairs, seconds)
        fit = archive(canonical)
        fit.update({
            "committed_pairs_per_year":pairs, "wallet_submission_payload_B_all_offers":offers*packet,
            "wallet_submission_B_with_4B_local_frame_all_offers":offers*(packet+4),
            "builder_private_proof_input_B_all_offers":offers*avg(receipt["wallet_proofs"]),
            "pair_body_savings_vs_two_wallet_packets_B_each":sum(submissions)-pair,
            "archive_B_if_CP03_framing_applied_to_each_native_pair_separately":roles.wire_bytes(pairs,pairs,pair),
            "archive_B_if_48_sequential_native_pairs_share_one_transport_header":roles.wire_bytes(pairs, roles.divide_up(pairs,48),pair),
            "fits_1_and_5_decimal_TB_archive": [canonical <= limit * TB for limit in (1, 5)],
            "single_archive_B_if_every_included_payment_uses_observed_singleton":included*receipt["followup_body_bytes"],
            "origin_packet_and_committed_packet_application_payload_B_before_peer_replication":offers*packet+canonical,
            "pool_block_and_both_upload_Mbps":[mbps(pending["egress"]),mbps(blocks["egress"]),mbps(pending["egress"]+blocks["egress"])],
            "primary_archive_two_replica_payload_egress_Mbps":mbps(canonical*2),
            "tenfold_for_600s_block_and_both_link_only_drain_s":[drain(link),drain(both)],
            "ideal_residual_link_1y_catchup_days_while_live":canonical*8/(down-blocks["ingress"]*8/Fraction(seconds))/DAY,
            "required_90d_down_plus_live_Mbps":mbps(blocks["ingress"])+Fraction(canonical*8,90*DAY*10**6),
            "90d_plus_live_required_pairs_per_s":pair_rate+Fraction(pairs,90*DAY),
            "max_CPU_budget_s_per_pair_90d_plus_live":2/(pair_rate+Fraction(pairs,90*DAY)),
            "node_fixture_check_CPU_cores_at_90d_plus_live_if_cost_held":verify["cpu_s"]*(pair_rate+Fraction(pairs,90*DAY)),
            "mean_builder_core_s_per_s_at_required_inclusion":builder["cpu_s"]*pair_rate,
            "latest_anchor_fixture_serial_service_payments_per_s":2/chain,
            "required_serial_time_per_pair_s":1/pair_rate,
            "max_measured_serial_chain_inclusions_per_365d_before_retries":math.floor(2*seconds/chain),
            "compact_local_receipt_history_B_one_year":history,
            "wallet_cold_scan_link_only_hours_80Mbps":Fraction(history*8,down*3600),
            "potential_trial_decryptions_per_retained_key":2*included,
            "prunable_node_raw_state_identifiers_floor_B_after_year":included*(2*32+2*32),
            # header() serializes all prior 32-byte commitments into the ordered-list hash.
            # With four funded leaves initially and four more per accepted pair, sum 32*(4+4j).
            "current_header_ordered_leaf_hash_input_B_1y_replay":64*pairs*(pairs+1),
            "current_header_ordered_leaf_hash_input_GBs_for_90d_backlog_only":Fraction(64*pairs*(pairs+1),90*DAY*10**9),
        })
        data[str(pct)] = fit
    return dict(measurements={"wallet_packets_B":submissions,"wallet_separate_proof_B":receipt["wallet_proofs"],
                              "pair_committed_B":pair,"pair_proof_B":receipt["pair_proof_bytes"],
                              "receipt_scan_B_per_pair":scan,"paired_payer_observed_wall_s":[x["elapsed_s"] for x in wallet],
                              "pair_builder_cpu_s":builder["cpu_s"],"pair_builder_wall_s":builder["elapsed_s"],
                              "pair_node_cpu_s":verify["cpu_s"],"pair_node_wall_s":verify["elapsed_s"],
                              "node_singleton_cpu_s":singleton["cpu_s"],
                              "adjacent_height_serial_wallet_builder_node_wall_s":chain}, scenarios=data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native",type=Path,default=HERE/"native/evidence/RESULT.json")
    parser.add_argument("--whir-only",action="store_true",help="omit the independent native pair measurement")
    args = parser.parse_args()
    profile=read(OLD/"PROFILE.json")
    wallet=read(HERE/"wallet/evidence/RESULT.json")
    durable=read(HERE/"wallet/evidence/DURABLE.json")
    stock=read(HERE/"qnero/evidence/roles.json")
    result={"research_profile":"NODE-ROLE-PROFILE01; one full payload peer in each phase, 96 payments/block, 80/16 useful Mb/s, 2 validation core-seconds/s",
            "whir":structured(profile,wallet,durable),
            "stock_qnero":{"standalone_extrinsic_B":stock["data_bytes"],"public_runtime_optimistic_inclusions_per_year":stock["upper_bound_per_year_without_other_normal_transactions"],
                           "source":"qnero/ROLES.md"},
            "sources":SOURCE}
    if not args.whir_only:
        result["native"]=native(profile,read(args.native))
    print(json.dumps(rounded(result),sort_keys=True,indent=2))


if __name__=="__main__":
    main()
