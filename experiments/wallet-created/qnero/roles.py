"""Calculate Qnero application payload floors and source-level capacity ceilings."""
import json
from math import ceil
from pathlib import Path

HERE = Path(__file__).resolve().parent
measured = json.loads((HERE / "evidence/public/wallet.json").read_text())
body = measured["extrinsic_bytes"]
proof = measured["proof_bytes"]
ct = sum(measured["ciphertext_lengths"])
assert body == 154508 and proof + ct + 16 == body
year = 365 * 86400
offers = 100_000_000
interval = 120
blocks = year // interval
normal = 5 * 1024**2 * 75 // 100
per_block = normal // body
runtime_tps = per_block / interval
down, up = 80e6 / 8, 16e6 / 8
cpu_budget = 2
tools = [json.loads(x) for x in (HERE / "evidence/public-process.jsonl").read_text().splitlines()]
verify_cpu = tools[-1]["user_s"] + tools[-1]["system_s"]
# This amount of payload is assumed to fit a phase, with actual P2P framing
# omitted. Inventory sizes are profile assumptions from node-validation.
inv_up = 6 * 72
request_up = 72
frame = 12

def burst_drain(service, base):
    burst = 10 * base
    if service <= base:
        return None
    return max(0, burst - service) * 600 / (service - base)


def scenario(share):
    included = offers * share // 100
    annual = body * included
    mean, accepted = offers / year, included / year
    one_block_sec = blocks / year
    # One requested payload, inventory to six neighbors, request to one.
    pool_up = mean * (body + frame + inv_up + request_up)
    block_payload = accepted * body
    block_ctrl = one_block_sec * (frame + inv_up + request_up)
    block_up = block_payload + block_ctrl
    txs_per_block = accepted / one_block_sec
    return {
        "inclusion_percent": share, "included_payments_demand": included,
        "included_per_120s_block_demand": txs_per_block,
        "accepted_over_byte_ceiling": accepted / runtime_tps,
        "annual_one_binary_extrinsic_per_offer_TB": offers * body / 1e12,
        "annual_wallet_submit_json_request_TB": offers * measured["submit"]["json_rpc_request_bytes"] / 1e12,
        "annual_block_extrinsics_one_copy_TB": annual / 1e12,
        "annual_three_archives_TB_before_other_data": 3 * annual / 1e12,
        "one_and_five_TB_max_B_per_payment": [cap / included for cap in [1e12, 5e12]],
        "archive_one_and_five_TB_days_capacity_at_demand": [365 * cap / annual for cap in [1e12, 5e12]],
        "standalone_extrinsic_only_relay_Mbps": {
            "pre_inclusion_one_peer": 8 * pool_up / 1e6,
            "qnero_transactions_1_notification_one_unknown_full_peer": 8 * mean * (body + 1) / 1e6,
            "qnero_transactions_1_notifications_six_unknown_full_peers": 6 * 8 * mean * (body + 1) / 1e6,
            "block_only_one_peer": 8 * block_up / 1e6,
            "mempool_plus_full_block": 8 * (pool_up + block_up) / 1e6,
            "perfect_cross_phase_payload_cache_lower_bound": 8 * (pool_up + block_ctrl) / 1e6,
            "archive_primary_two_replica_payload_egress": 16 * block_payload / 1e6,
        },
        "burst_10x600s_network_only_drain_s": {
            "block_only": burst_drain((up - block_ctrl) / (body * share / 100), mean),
            "mempool_plus_block": burst_drain((up - block_ctrl) / (body + frame + inv_up + request_up + body * share / 100), mean),
            "runtime_normal_bytes": burst_drain(runtime_tps, accepted)
        },
        "100_offers_per_s_600s_extrinsic_MB": 100 * 600 * body / 1e6,
        "steady_validation_CPU_cores_native_component": {
            "block_only_two_checks": accepted * 2 * verify_cpu,
            "mempool_plus_block_three_checks": (mean + 2 * accepted) * verify_cpu
        },
        "one_year_link_only_catchup_while_live_days_raw_binary": annual / (down - block_up) / 86400,
        "ninety_days_download_including_live_binary_Mbps": 8*(annual / (90*86400) + block_up)/1e6,
        "ninety_days_two_native_checks_cores_including_live": 2*verify_cpu*(included/(90*86400) + accepted),
        "one_year_cold_uncompressed_wallet_JSON_hex_min_TB": 2 * annual / 1e12,
        "wallet_hex_only_duration_at_80Mbps_hours_excluding_live": 2 * annual / down / 3600,
        "commitment_bytes_per_local_spend_at_year_end_excluding_keys_proofs": 32*(2*included+blocks),
        "new_nullifier_and_commitment_and_leaf_height_logical_bytes_per_year": 136 * included,
        "nullifier_prefix_entry_cap_reached_days_at_demand": 500_000 / accepted / 86400,
        "pruned_256_block_window_projected_extrinsic_B_at_demand": ceil(256*interval*accepted)*body,
        "live_cache_600s_offers_B_before_indices": ceil(mean*600)*body,
        "burst_cache_600s_offers_B_before_indices": ceil(mean*600*10)*body,
    }


result = {"scope":"Qnero direct default wallet, byte floors; transfer rates are scenarios, no annual throughput run",
          "data_bytes":body, "max_normal_bytes":normal, "maximum_by_normal_bytes_per_block":per_block,
          "upper_bound_per_year_without_other_normal_transactions":per_block*blocks,
          "upper_bound_by_full_block_bytes_before_reservation":(5*1024**2)//body,
          "raw_256_block_window_B_at_normal_tx_ceiling":256*per_block*body,
          "cold_archive_one_and_five_TB_fit_payments": [int(cap//body) for cap in [1e12,5e12]],
          "offers_per_second_at_100M":offers/year,
          "scenarios":[scenario(n) for n in (95,100)]}
print(json.dumps(result, indent=2))
