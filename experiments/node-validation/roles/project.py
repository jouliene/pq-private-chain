#!/usr/bin/env python3
"""Project two private-payment routes from retained public measurements."""
import argparse
import hashlib
import json
import math
from fractions import Fraction
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DAY = 86400
BODY_PREFIX = 4876
CP03_2X2_MAX_BODY = BODY_PREFIX + 2_097_152
REDUCED_RECORD = BODY_PREFIX + 12 + 64
BLOCK_FIXED = 228
BLOCK_PER_PAYMENT = 68
SCAN_FIXED = BLOCK_FIXED + 4
CONTINUATION = 436
AGGREGATE_FIELD = 12
ARCHIVE_RPC = 52
PEER_ID_MESSAGE = 72
PEER_BODY_FRAME = 12
WALLET_ENDPOINT_REQUEST = 72
WALLET_ENDPOINT_RESPONSE = 256
DEPTH = 40


def public_json(relative):
    raw = (ROOT / relative).read_bytes()
    return json.loads(raw, parse_float=Fraction), hashlib.sha256(raw).hexdigest()


def actual_evidence():
    paths = {
        "producer": "experiments/network-feasibility/producer/evidence/GATE2_FULL_GENERATION01_READBACK.json",
        "transport": "experiments/network-feasibility/transport/GATE2_FULL01.json",
        "storage": "experiments/network-feasibility/evidence/RESOURCE_MODEL01.json",
        "genesis": "experiments/network-feasibility/evidence/gate2-96x8-01-network/PREPARED.json",
        "range": "experiments/incremental-sync/evidence/trace01/RESULT.json",
        "restore": "experiments/incremental-sync/evidence/sync-private01/RESULT.json",
    }
    observed = {key: public_json(path) for key, path in paths.items()}
    producer, transport, storage, genesis, scan, restore = (row[0] for row in observed.values())
    costs = producer["proof_resources"]["ordinary"]
    ordinary_count = costs["count"]
    frame_bytes = sum(batch["frame_bytes"] for batch in transport["per_batch"])
    count = transport["finite_result"]["accepted_ordinary_payments"]
    gate1 = storage["measured"]
    assert count == ordinary_count == 768 and len(transport["per_batch"]) == 8
    assert costs["body_bytes"] == frame_bytes - 8 * BLOCK_FIXED - BLOCK_PER_PAYMENT * count
    assert costs["body_bytes"] - costs["proof_bytes"] == BODY_PREFIX * count
    assert gate1["reduced_bytes_each"] == REDUCED_RECORD
    assert gate1["public_scan_frame_bytes_funding_ordinary"][1] == scan_bytes(96, 1)
    assert scan["passed"] and restore["passed"]
    long = scan["summaries"][-1]
    assert long["actual_request_bytes"] == CONTINUATION * long["actual_requests"]
    assert long["actual_response_bytes"] == long["server_serving"]["history_frame_bytes"] + long["actual_request_bytes"]
    native = transport["resources"]["native_receiver_two_incarnations"]
    cold_actor, = (actor for actor in restore["actors"] if actor["restore"])
    return {
        "files": {key: {"path": paths[key], "sha256": pair[1]} for key, pair in observed.items()},
        "cp03": {
            "ordinary_bodies": count,
            "genesis_context_bytes": genesis["objects"]["genesis"]["bytes"],
            "separate_funding_frame_bytes": genesis["objects"]["funding"]["bytes"],
            "ordinary_body_bytes_sum": costs["body_bytes"],
            "mean_body_bytes": Fraction(costs["body_bytes"], count),
            "min_body_bytes": costs["proof_bytes_min"] + BODY_PREFIX,
            "max_body_bytes": costs["proof_bytes_max"] + BODY_PREFIX,
            "ordinary_full_frame_bytes_sum": frame_bytes,
            "ordinary_proof_worker_cpu_seconds": costs["worker_system_seconds_sum"] + costs["worker_user_seconds_sum"],
            "ordinary_proof_worker_peak_rss_kib": costs["maximum_individual_worker_peak_rss_kib"],
            "funding_and_ordinary_validator_cpu_self_seconds": native["self_CPU_seconds"],
            "validator_cpu_waited_helpers_seconds": native["already_waited_helper_CPU_seconds"],
            "ordinary_validator_native_self_cpu_seconds": sum(row["inclusive_native_self_CPU_seconds"] for row in transport["per_batch"]),
            "ordinary_block_durable_admission_wall_seconds_min": min(row["admit_durable_retain_wall_seconds"] for row in transport["per_batch"]),
            "ordinary_block_durable_admission_wall_seconds_max": max(row["admit_durable_retain_wall_seconds"] for row in transport["per_batch"]),
            "validator_tree_rss_kib_sampled_max": native["sampled_simultaneous_role_tree_peak_rss_kib"],
            "actual_validator_final_db": transport["physical_output_copies"]["destination_final"],
            "actual_archive_final_disk": transport["resources"]["archive"]["final_disk"],
            "actual_archive_rpc_application_bytes": transport["RPC_bytes"]["flows"],
            "scope": "Finite paced-loopback RETAIN campaign with genuine CP03 proofs, separate funding, restart and one archive recipient. Neither timings nor RSS transfer unchanged to a candidate or to large state.",
        },
        "wallet": {
            "batches_in_scan_control": long["actual_wallet_blocks"],
            "payment_records_in_scan_control": long["actual_wallet_records"],
            "request_bytes": long["actual_request_bytes"],
            "response_bytes": long["actual_response_bytes"],
            "logical_server_reads": long["server_serving"],
            "wallet_scan_cpu_scope": long["sync_cost"],
            "actual_one_cold_restore": {
                "observed_counts": cold_actor["terminal_metrics"]["counts"],
                "node_cpu": cold_actor["terminal_cpu"],
            },
            "scope": "The continuation trace uses zero owned notes. The separate restore is one finite genuine wallet operation, including a newly proved spend.",
        },
    }


def measured_matrix_component(path):
    raw = path.read_bytes()
    receipt = json.loads(raw, parse_float=Fraction)
    runs = receipt["runs"]
    assert len(runs) == 3 and all(row["combined_sparse_matrix_terms"] == 6047930 for row in runs)
    samples = [row["through_guard_and_main_fold_cpu_s"] for row in runs]
    assert all(value > 0 for value in samples)
    return {
        "path": str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else path.name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "matrix_preparation_wall_seconds_outside_samples": receipt["matrix_prepare_seconds"],
        "public_sparse_terms": runs[0]["combined_sparse_matrix_terms"],
        "public_matrix_guard_and_first_main_fold_thread_cpu_seconds": samples,
        "scope": "Three public statements, reusable sparse matrices and synthetic challenges. Times are one measured component and omit mask/OOD entries, further folds, PCS parsing, authentication, openings, full transcripts and ledger work. The final postcheck digest and preparation are outside the samples.",
    }


def divide_up(value, divisor):
    return -(-value // divisor)


def scan_bytes(payments, blocks):
    return SCAN_FIXED * blocks + (REDUCED_RECORD + BLOCK_PER_PAYMENT) * payments


def wire_bytes(payments, blocks, body_bytes, block_proof=0):
    fixed = BLOCK_FIXED + (AGGREGATE_FIELD if block_proof else 0)
    return blocks * (fixed + block_proof) + payments * (BLOCK_PER_PAYMENT + body_bytes)


def traffic(ingress, egress, seconds):
    return {
        "ingress_bytes": ingress,
        "egress_bytes": egress,
        "mean_ingress_bps": Fraction(ingress * 8, seconds),
        "mean_egress_bps": Fraction(egress * 8, seconds),
    }


def gossip(objects, payload, peers, payload_peers):
    """Every object is fetched once inbound, then forwarded to actual requesters."""
    inventory = PEER_ID_MESSAGE * peers * objects
    request = PEER_ID_MESSAGE * objects
    send_overhead = PEER_BODY_FRAME * objects
    return {
        "ingress": inventory + request * payload_peers + payload + send_overhead,
        "egress": inventory + request + (payload + send_overhead) * payload_peers,
    }


def common_wallet(payments, blocks, ranges):
    # A sized external endpoint exchange is charged separately from continuation.
    history = scan_bytes(payments, blocks)
    return {
        "history_frames_bytes": history,
        "response_bytes": history + CONTINUATION * ranges,
        "request_bytes": CONTINUATION * ranges,
        "separate_endpoint_request_bytes": WALLET_ENDPOINT_REQUEST * ranges,
        "separate_endpoint_response_bytes": WALLET_ENDPOINT_RESPONSE * ranges,
        "ingress": history + (CONTINUATION + WALLET_ENDPOINT_RESPONSE) * ranges,
        "egress": (CONTINUATION + WALLET_ENDPOINT_REQUEST) * ranges,
        "ranges": ranges,
    }


def occupied(leaves):
    return sum(divide_up(leaves, 1 << level) for level in range(DEPTH + 1))


def reorg_undo(payments, blocks, batch, years, window):
    """Count stored undo keys and old digest payloads over the selected suffix."""
    rows = old_digests = 0
    for height in range(max(0, years * blocks - window), years * blocks):
        year, batch_index = divmod(height, blocks)
        start = 2 * (year * payments + batch_index * batch)
        end = 2 * (year * payments + min(payments, (batch_index + 1) * batch))
        for level in range(DEPTH + 1):
            width = 1 << level
            rows += (end - 1) // width - start // width + 1
            old_digests += int(start % width != 0)
    return rows, old_digests


def state_disk(payments, blocks, batch, years, home, block, batch_block, mempool_disk):
    horizon_payments = payments * years
    horizon_blocks = blocks * years
    if horizon_payments * 2 > 1 << DEPTH:
        raise ValueError("scenario exceeds the depth-40 tree capacity")
    undo_rows, old_digests = reorg_undo(payments, blocks, batch, years, home["reorg_blocks"])
    fields = {
        "nullifier_keys": horizon_payments * 2 * 64,
        "core_keys": horizon_payments * 64,
        "leaf_origin_commitment_body_id": horizon_payments * 2 * 192,
        "tree_digests": occupied(2 * horizon_payments) * 64,
    }
    allowances = {
        "nullifier_and_core_additional_index_and_rows": horizon_payments * 3 * 112,
        "leaf_additional_index_and_rows": horizon_payments * 2 * 192,
        "tree_keys_and_rows": occupied(2 * horizon_payments) * 32,
        "blocks_headers_indexes_backlink_and_values": horizon_blocks * 504 + horizon_payments * 64,
        "common_history_reduced_with_record_indexes": horizon_payments * (REDUCED_RECORD + 192),
        "bounded_undo_keys_indexes_and_old_values": undo_rows * 64 + old_digests * 64,
        "bounded_anchor_pair_table": (home["reorg_blocks"] + 1) * 160,
        "archive_catalog_by_block": horizon_blocks * 128,
        "fixed_database_metadata": 64 << 20,
    }
    sql = Fraction(5, 4) * (sum(fields.values()) + sum(allowances.values()))
    staged = batch_block * (
        home["reorg_blocks"] * (1 + home["fork_copies_staged"]) + home["inflight_blocks"]
    )
    # At the first horizon a partially filled last block is harmlessly budgeted
    # at full size for staging. Physical allocation is a researcher allowance.
    peak = sql + staged + mempool_disk + 2 * batch_block
    return {
        "selected_permanent_state_fields_bytes": fields,
        "covered_database_rows_bytes_assumptions": allowances,
        "recent_undo_rows": undo_rows,
        "recent_undo_old_digests": old_digests,
        "database_bytes_including_25pct_page_allowance": math.ceil(sql),
        "selected_recent_blocks_bytes_budget": home["reorg_blocks"] * batch_block,
        "one_fork_and_inflight_bytes_budget": staged - home["reorg_blocks"] * batch_block,
        "mempool_disk_bytes_budget": mempool_disk,
        "extra_atomic_file_and_journal_spool_bytes_budget": 2 * batch_block,
        "planned_pruned_disk_bytes": math.ceil(peak),
        "planned_unpruned_replacing_recent_canonical_bytes_with_all_bytes": math.ceil(peak + block * years - home["reorg_blocks"] * batch_block),
        "additional_disk_to_rebuild_database_beside_old_copy_bytes": math.ceil(sql),
        "covered_pruned_disk_fits_research_disk": peak <= home["usable_disk_bytes"],
    }


def relay_traffic(offers, block_count, mempool_body, block_wire, included_payload, relay,
                  payload_peers=None, reuse_percent=None):
    reuse = relay["block_reuse_percent"] if reuse_percent is None else reuse_percent
    mempool_peers = relay["mempool_payload_peers"] if payload_peers is None else payload_peers
    block_peers = relay["block_payload_peers"] if payload_peers is None else payload_peers
    inv_peers = relay["inventory_peers"]
    pending = gossip(offers, offers * mempool_body, inv_peers, mempool_peers)
    # Per-payment length words are left in the transmitted block for all entries.
    replay = gossip(block_count, block_wire - Fraction(reuse, 100) * included_payload,
                    inv_peers, block_peers)
    return pending, replay


def burst_case(offer_rate, burst_rate, annual_seconds, burst, service, batch, mempool_bytes):
    duration = burst["duration_seconds"]
    background = (offer_rate * annual_seconds - burst_rate * duration) / (annual_seconds - duration)
    backlog = max(0, burst_rate - service) * duration
    drain = (backlog / (service - background) if service > background else None) if backlog else 0
    # The discrete queue reserve is one full block above the fluid approximation.
    return {
        "burst_offers_per_second": burst_rate,
        "background_offers_per_second_with_equal_annual_volume": background,
        "maximum_extra_pending_offers_fluid": backlog,
        "maximum_extra_pending_offers_rounded_with_one_block_reserve": math.ceil(backlog) + batch,
        "spool_bytes_for_rounded_extra_pending_offers": math.ceil((math.ceil(backlog) + batch) * mempool_bytes),
        "drain_after_burst_seconds_if_stable": drain,
        "clears_within_research_target": drain is not None and drain <= burst["drain_after_burst_seconds"],
    }


def masked_link_body_limits(offers, mempool_deliveries, relayed_payments, relayed_blocks,
                            seconds, relay, burst, down, up):
    """Solve the affine relay byte budget at the rate needed to drain the burst."""
    mean = Fraction(offers, seconds)
    duration = burst["duration_seconds"]
    recovery = burst["drain_after_burst_seconds"]
    peak = mean * burst["mean_multiplier"]
    background = (offers - peak * duration) / (seconds - duration)
    required_rate = (peak * duration + background * recovery) / (duration + recovery)
    profiles = {"steady": mean, "burst_drain": required_rate}
    limits = {"absolute_network_service_offers_per_second_for_burst_deadline": required_rate}
    for role in ("mempool_and_blocks", "independent_block_only"):
        block_only = role == "independent_block_only"
        reuse = 0 if block_only else relay["block_reuse_percent"]
        baseline_wire = wire_bytes(relayed_payments, relayed_blocks, 0)
        roles_fixed = relay_traffic(mempool_deliveries, relayed_blocks, 0, baseline_wire, 0,
                                    relay, reuse_percent=reuse)
        roles_one = relay_traffic(mempool_deliveries, relayed_blocks, 1, baseline_wire + relayed_payments,
                                  relayed_payments, relay, reuse_percent=reuse)
        fixed = {direction: roles_fixed[1][direction] + (0 if block_only else roles_fixed[0][direction])
                 for direction in ("ingress", "egress")}
        slope = {direction: roles_one[1][direction] + (0 if block_only else roles_one[0][direction]) - fixed[direction]
                 for direction in ("ingress", "egress")}
        limits[role] = {}
        for label, rate in profiles.items():
            remaining = {"ingress": Fraction(down * seconds, 8) * mean / rate - fixed["ingress"],
                         "egress": Fraction(up * seconds, 8) * mean / rate - fixed["egress"]}
            ceilings = [remaining[direction] / slope[direction] for direction in fixed if slope[direction] > 0]
            limits[role][label + "_max_mean_complete_body_bytes"] = max(0, min(ceilings)) if all(
                amount >= 0 for amount in remaining.values()) else 0
    return limits


def time_to_transfer(payload, residual_bps):
    return Fraction(payload * 8, residual_bps) if residual_bps > 0 else None


def recovery(work, requests, intake, outtake, block_cpu_us, live_cpu_cores, home, archive, replay_counts):
    work += archive["cold_genesis_context_bytes"]
    requests += 1
    inbound = time_to_transfer(work + requests * ARCHIVE_RPC, intake)
    outbound = time_to_transfer(requests * ARCHIVE_RPC, outtake)
    request_latency = Fraction(requests * archive["serial_request_latency_ms"], 1000)
    transfer_floor = max(inbound, outbound) if inbound is not None and outbound is not None else None
    remaining_cores = (home["validation_core_seconds_per_second"] - live_cpu_cores
                       if live_cpu_cores is not None else None)
    replay_cpu = (Fraction(block_cpu_us, 1_000_000) / remaining_cores
                  if block_cpu_us is not None and remaining_cores is not None and remaining_cores > 0 else None)
    payload = {
        "cold_replay_rx_bytes_including_genesis_and_archive_replies": work + requests * ARCHIVE_RPC,
        "archive_get_request_tx_bytes": requests * ARCHIVE_RPC,
        "link_only_ideal_seconds_at_residual_after_live": transfer_floor,
        "get_request_rtt_if_fully_serial_seconds": request_latency,
        "fully_serial_get_link_plus_rtt_seconds": None if transfer_floor is None else transfer_floor + request_latency,
        "verification_elapsed_seconds_floor_at_residual_parallel_cpu_if_supplied": replay_cpu,
        "independent_link_or_cpu_floor_seconds": (None if transfer_floor is None or replay_cpu is None
                                                         else max(transfer_floor, replay_cpu)),
    }
    payload.update(replay_counts)
    return payload


def archive_plan(sizes, blocks, annual_seconds, archive, wallet_live, years):
    copies = archive["replicas_in_independent_failure_domains"]
    live_streams = archive["live_full_streams_from_primary"]
    wallet_streams = archive["live_wallet_scan_streams"]
    canonical = sizes["canonical"]
    transfer = canonical + blocks * ARCHIVE_RPC
    requests = blocks * ARCHIVE_RPC
    storage = {name: {str(year): math.ceil(size * year) for year in years}
               for name, size in sizes.items()}
    replicated = {name: {str(year): math.ceil(size * year * copies) for year in years}
                  for name, size in sizes.items()}
    return {
        "single_copy_disk_payload_bytes_by_policy_and_years": storage,
        "all_replicas_disk_payload_bytes_by_policy_and_years": replicated,
        "one_time_genesis_context_bytes_per_copy_additional_to_storage_table": archive["cold_genesis_context_bytes"],
        "primary_replication_and_full_stream": traffic(transfer + requests * (copies - 1 + live_streams),
                                                        requests + transfer * (copies - 1 + live_streams),
                                                        annual_seconds),
        "per_replica_put_receive_and_ack": traffic(transfer, requests, annual_seconds),
        "secondary_policy_additional_annual_ingress_or_replica_egress_payload_bytes": {
            name: amount - canonical for name, amount in sizes.items()
        },
        "public_wallet_range_service_separate_from_archive_full_stream": traffic(
            wallet_live["egress"] * wallet_streams, wallet_live["ingress"] * wallet_streams, annual_seconds),
        "one_copy_repair_retransmit_payload_bytes_by_policy_and_years": storage,
        "scope": "Raw frame payload. PUT/GET exchanges use 52 bytes each in each direction. Physical allocation, object manifests/indexes, scrub I/O, third-party repair traffic and fees require a measured service. A full-stream recipient uses archive data instead of a duplicate gossip fetch for that block.",
    }


def standalone_block_cpu_budget(included, live_payments, annual_seconds, home, matrix):
    """Give optimistic per-payment CPU ceilings for a block-only validator."""
    live_rate = Fraction(live_payments, annual_seconds)
    historic_rate = Fraction(included, home["cold_one_year_days"] * DAY)
    combined_rate = live_rate + historic_rate
    samples = [] if matrix is None else matrix["public_matrix_guard_and_first_main_fold_thread_cpu_seconds"]
    budgets = {}
    for cores in (home["validation_core_seconds_per_second"], home["physical_cores"]):
        budgets[str(cores)] = {
            "steady_total_cpu_seconds_per_payment_ceiling": cores / live_rate,
            "cold_while_live_total_cpu_seconds_per_payment_ceiling": cores / combined_rate,
            "remaining_cpu_seconds_per_payment_after_measured_component_if_same_source": [
                cores / combined_rate - sample for sample in samples
            ],
            "historical_catchup_elapsed_days_with_measured_component_only_if_same_source": [
                Fraction(included, DAY) / (cores / sample - live_rate) if cores / sample > live_rate else None
                for sample in samples
            ],
        }
    return {
        "live_included_payments_per_second": live_rate,
        "historical_payments_per_second_needed": historic_rate,
        "total_payments_per_second_while_catching_up": combined_rate,
        "budgets_by_available_core_seconds_per_second": budgets,
        "measured_component_core_seconds_per_second_while_catching_up_if_same_source": [
            sample * combined_rate for sample in samples
        ],
        "scope": "Ideal CPU scheduling for complete public verification and state handling. This counts no independent mempool pass. Using measured component time assumes equivalent implementation, machine and work per statement; it gives no qualification of the complete verifier and assigns no benefit to unimplemented optimizations.",
    }


def project_route(route, rate, profile, sizes, costs, matrix):
    home = profile["home"]
    relay = profile["relay"]
    archive = profile["archive"]
    seconds = profile["year_days"] * DAY
    offers = profile["annual_offers"]
    resubmissions = relay["reorg_wallet_resubmissions_per_year"]
    mempool_deliveries = offers + resubmissions
    included = offers * rate // 100
    batch = profile["payments_per_block"]
    blocks = divide_up(included, batch)
    fork_blocks = relay["extra_fork_blocks_per_year"]
    fork_payments = fork_blocks * batch
    mempool_body = sizes["mempool"]
    block_body = sizes["included"]
    aggregate = sizes["aggregate"]
    canonical = wire_bytes(included, blocks, block_body, aggregate)
    fork_wire = wire_bytes(fork_payments, fork_blocks, block_body, aggregate)
    max_batch_wire = wire_bytes(batch, 1, sizes.get("included_max", block_body), aggregate)
    relayed_objects = blocks + fork_blocks
    relayed_wire = canonical + fork_wire
    relayed_included_payload = (included + fork_payments) * block_body
    down = home["line_download_bps"] * home["useful_application_percent"] // 100
    up = home["line_upload_bps"] * home["useful_application_percent"] // 100
    mean_offer_rate = Fraction(offers, seconds)
    wallet_bytes_per_submission = mempool_body + PEER_BODY_FRAME
    wallet_staged_offers = math.ceil(mean_offer_rate * home["mempool_seconds"] * profile["burst"]["mean_multiplier"]) + batch
    mempool_disk = wallet_staged_offers * (sizes.get("mempool_max", mempool_body) + PEER_BODY_FRAME)

    def relay_variant(payload_peers=None, reuse=None):
        pending, block = relay_traffic(mempool_deliveries, relayed_objects, mempool_body, relayed_wire,
                                       relayed_included_payload, relay, payload_peers, reuse)
        return {
            "mempool": traffic(pending["ingress"], pending["egress"], seconds),
            "block": traffic(block["ingress"], block["egress"], seconds),
            "total": traffic(pending["ingress"] + block["ingress"], pending["egress"] + block["egress"], seconds),
        }

    normal = relay_variant()
    intake = down - normal["total"]["mean_ingress_bps"]
    outtake = up - normal["total"]["mean_egress_bps"]
    network_service = mean_offer_rate * min(
        Fraction(down, normal["total"]["mean_ingress_bps"]), Fraction(up, normal["total"]["mean_egress_bps"])
    )
    mempool_cpu_us = costs["mempool_payment_us"]
    block_cpu_us = costs["block_payment_us"]
    aggregate_cpu_us = costs["block_aggregate_us"]
    block_cost = ((included + fork_payments) * block_cpu_us if block_cpu_us is not None else None)
    if route == "aggregate_cp03" and block_cost is not None:
        block_cost = None if aggregate_cpu_us is None else block_cost + relayed_objects * aggregate_cpu_us
    annual_total_cpu_us = mempool_deliveries * mempool_cpu_us + block_cost if None not in (mempool_cpu_us, block_cost) else None
    live_cores = Fraction(annual_total_cpu_us, 1_000_000 * seconds) if annual_total_cpu_us is not None else None
    cpu_service = (None if live_cores is None else
                   mean_offer_rate * Fraction(home["validation_core_seconds_per_second"], live_cores))
    cpu_ceiling = Fraction(home["validation_core_seconds_per_second"], mean_offer_rate)
    pure_blocks = relay_variant(reuse=0)["block"]
    block_only_intake = down - pure_blocks["mean_ingress_bps"]
    block_only_outtake = up - pure_blocks["mean_egress_bps"]
    block_only_cores = Fraction(block_cost, 1_000_000 * seconds) if block_cost is not None else None
    block_only_service = mean_offer_rate * min(Fraction(down, pure_blocks["mean_ingress_bps"]),
                                                Fraction(up, pure_blocks["mean_egress_bps"]))

    ranges = divide_up(blocks, relay["wallet_blocks_per_range"])
    deep_replays = relay["wallet_deep_replays_at_first_year_end"]
    wallet_live = common_wallet(included + fork_payments + deep_replays * included,
                                blocks + fork_blocks + deep_replays * blocks,
                                ranges + fork_blocks + deep_replays)
    cold = {}
    block_only_cold = {}
    disk = {}
    block_only_disk = {}
    for years in profile["years"]:
        historic_payments = included * years
        historic_blocks = blocks * years
        scan = common_wallet(historic_payments, historic_blocks, 1)
        genesis_transfer = archive["cold_genesis_context_bytes"]
        wallet_cold_download = scan["ingress"] + genesis_transfer + ARCHIVE_RPC
        ideal_wallet_time = time_to_transfer(wallet_cold_download, down)
        deadline = home["wallet_cold_one_year_hours"] * 3600
        # This is a generous upper bound on elapsed CPU budget for overlapped I/O.
        # Retained-key scanning benchmarks may be entered in a later measured gate.
        check_counts = {str(keys): 2 * historic_payments * keys for keys in (1, 4, 32)}
        validator_cold_cost = (historic_payments * block_cpu_us if block_cpu_us is not None else None)
        if route == "aggregate_cp03" and validator_cold_cost is not None:
            validator_cold_cost = None if aggregate_cpu_us is None else validator_cold_cost + historic_blocks * aggregate_cpu_us
        recovery_deadline = home["cold_one_year_days"] * DAY
        work = {
            "required_payment_verifications": historic_payments if route == "masked_whir" else 0,
            "required_outer_block_verifications": historic_blocks if route == "aggregate_cp03" else 0,
            "required_payment_state_applications": historic_payments,
        }
        cold[str(years)] = {
            "wallet_delegating_validity": {
                **scan,
                "genesis_bytes_with_one_archive_reply": genesis_transfer + ARCHIVE_RPC,
                "additional_genesis_get_request_bytes": ARCHIVE_RPC,
                "cold_total_ingress_bytes": wallet_cold_download,
                "cold_total_egress_bytes": scan["egress"] + ARCHIVE_RPC,
                "ideal_downlink_only_seconds": ideal_wallet_time,
                "trial_decapsulation_upper_counts_by_retained_keys": check_counts,
                "trial_rate_needed_if_overlapped_at_48h_target_by_retained_keys": {
                    key: Fraction(count, deadline) for key, count in check_counts.items()
                },
                "trial_rate_needed_if_scanning_after_transfer_at_48h_target_by_retained_keys": {
                    key: Fraction(count, deadline - ideal_wallet_time) if deadline > ideal_wallet_time else None
                    for key, count in check_counts.items()
                },
            },
            "validator_replaying_from_genesis": recovery(
                canonical * years, historic_blocks, intake, outtake, validator_cold_cost, live_cores,
                home, archive, {
                    "required_application_ingress_bps_plus_live_for_research_deadline": (
                        normal["total"]["mean_ingress_bps"]
                        + Fraction((canonical * years + genesis_transfer + (1 + historic_blocks) * ARCHIVE_RPC) * 8, recovery_deadline)),
                    **work,
                }),
            "full_verifying_wallet": {
                "raw_block_download_bytes": canonical * years,
                "genesis_bytes": genesis_transfer,
                "archive_reply_bytes": (historic_blocks + 1) * ARCHIVE_RPC,
                "archive_request_bytes": (historic_blocks + 1) * ARCHIVE_RPC,
                "ideal_downlink_only_seconds_before_wallet_scanning": time_to_transfer(
                    (canonical + blocks * ARCHIVE_RPC) * years + genesis_transfer + ARCHIVE_RPC, down),
                "replay_cpu_seconds_if_supplied": None if validator_cold_cost is None else Fraction(validator_cold_cost, 1_000_000),
                "shared_requirements": "Runs public validity/state replay and additionally scans all receipts to recover wallet-specific keys and witnesses.",
            },
        }
        disk[str(years)] = state_disk(included, blocks, batch, years, home, canonical,
                                      max_batch_wire, mempool_disk)
        block_only_disk[str(years)] = state_disk(included, blocks, batch, years, home, canonical,
                                                 max_batch_wire, 0)
        block_only_cold[str(years)] = recovery(
            canonical * years, historic_blocks, block_only_intake, block_only_outtake, validator_cold_cost,
            block_only_cores, home, archive, {
                "required_application_ingress_bps_plus_live_for_research_deadline": (
                    pure_blocks["mean_ingress_bps"]
                    + Fraction((canonical * years + genesis_transfer + (1 + historic_blocks) * ARCHIVE_RPC) * 8, recovery_deadline)),
                **work,
            })
    bootstrap = cold["1"]["validator_replaying_from_genesis"]["link_only_ideal_seconds_at_residual_after_live"]
    archive_sizes = {"canonical": canonical + fork_wire}
    builder = None
    if route == "aggregate_cp03":
        cp03_proof = mempool_body - BODY_PREFIX
        pending_seconds = archive["offered_proofs_retention_seconds"]
        pending_cap = math.ceil(mean_offer_rate * pending_seconds * profile["burst"]["mean_multiplier"]) + batch
        builder = {
            "full_cp03_bytes_presented_per_year_before_inclusion_including_resubmits": (
                mempool_deliveries * (mempool_body + PEER_BODY_FRAME)),
            "cp03_checks_at_ingress_if_open_builder_validates_all_offers": mempool_deliveries,
            "cp03_program_executions_in_outer_relation_at_minimum": included + fork_payments,
            "inner_complete_input_bytes_read_at_minimum": (included + fork_payments) * mempool_body,
            "spool_bytes_at_cp03_2x2_body_cap_for_10x_window_and_one_batch_reserve": (
                pending_cap * (sizes["mempool_max"] + PEER_BODY_FRAME)),
            "held_reference_proofs_default_window_seconds": pending_seconds,
            "outer_prover_cpu_rss_and_additional_trace_disk": None,
            "scope": "One builder taking all offers, or aggregate ingress distributed among builders. Co-location avoids a second network copy between ingress and the outer prover. Independent remote builder intake or retries add copies. A local retained public body can cover re-inclusion only while available, otherwise charge a wallet or peer resubmission.",
        }
        audit_size = canonical + fork_wire + (included + fork_payments) * (cp03_proof + 4) + relayed_objects * 12
        archive_sizes["canonical_plus_inner_proofs_for_included_and_fork_records"] = audit_size
        archive_sizes["canonical_plus_all_offered_full_cp03_and_fork_only_inner_proofs"] = (
            canonical + fork_wire + offers * (mempool_body + 4) + fork_payments * (cp03_proof + 4) + relayed_objects * 12
        )

    return {
        "annual_offers": offers,
        "annual_included": included,
        "annual_not_included": offers - included,
        "extra_wallet_resubmissions_for_reorg": resubmissions,
        "included_blocks": blocks,
        "last_canonical_block_payments": included - (blocks - 1) * batch,
        "extra_transmitted_fork_blocks": fork_blocks,
        "canonical_block_bytes_per_one_retaining_copy_per_year": canonical,
        "canonical_ordinary_proof_bytes_per_year": (included * (block_body - BODY_PREFIX)
                                                    if route == "masked_whir" else blocks * aggregate),
        "masked_whir_network_body_ceiling_if_applicable": (masked_link_body_limits(
            offers, mempool_deliveries, included + fork_payments, relayed_objects, seconds, relay,
            profile["burst"], down, up) if route == "masked_whir" else None),
        "block_body_or_capsule_bytes_each": block_body,
        "mempool_body_bytes_each_or_cp03_mean": mempool_body,
        "block_proof_serialized_bytes_if_aggregate": aggregate or None,
        "relay_default": normal,
        "relay_all_inventory_peers_fetch_payloads_sensitivity": relay_variant(payload_peers=relay["inventory_peers"]),
        "relay_perfect_cross_phase_cache_sensitivity": relay_variant(reuse=100),
        "wallet": {
            "one_submission_application_upload_bytes_including_12_byte_frame": wallet_bytes_per_submission,
            "one_submission_pure_transfer_seconds_on_useful_home_uplink": time_to_transfer(wallet_bytes_per_submission, up),
            "annual_network_wide_originator_upload_bytes_including_nonincluded": (
                mempool_deliveries * wallet_bytes_per_submission * relay["wallet_upload_copies"]),
            "ordinary_synchronized_wallet_common_history": wallet_live,
            "ordinary_receipt_trials_upper_count_per_retained_key": 2 * (included + fork_payments + deep_replays * included),
            "deep_replays_priced_at_first_year_end": deep_replays,
            "per_wallet_submission_count_is_user_specific": True,
        },
        "validation": {
            "mempool_checks_per_year": mempool_deliveries,
            "standalone_block_proof_checks_per_year": included + fork_payments if route == "masked_whir" else 0,
            "ordered_aggregate_block_proof_checks_per_year": relayed_objects if route == "aggregate_cp03" else 0,
            "block_state_checks_per_payment": included + fork_payments,
            "aggregate_prover_inner_cp03_checks_per_year_minimum": included + fork_payments if route == "aggregate_cp03" else 0,
            "aggregate_prover_inner_public_body_bytes_read_per_year_minimum": (included + fork_payments) * mempool_body if route == "aggregate_cp03" else 0,
            "annual_cpu_microseconds_if_explicitly_supplied": annual_total_cpu_us,
            "mean_cpu_cores_required_if_explicitly_supplied": live_cores,
            "theoretical_cpu_seconds_per_offer_across_mempool_and_block_to_match_mean": cpu_ceiling,
            "serialized_durable_block_commit_and_memory_not_projected_from_cpu_sum": True,
        },
        "home_service": {
            "useful_application_ingress_bps": down,
            "useful_application_egress_bps": up,
            "steady_link_can_service_mean_default": intake > 0 and outtake > 0,
            "one_year_genesis_replay_link_floor_within_research_deadline": (
                bootstrap is not None and bootstrap <= home["cold_one_year_days"] * DAY),
            "maximum_network_only_offers_per_second": network_service,
            "maximum_cpu_only_offers_per_second_if_supplied": cpu_service,
            "network_only_burst": burst_case(mean_offer_rate, mean_offer_rate * profile["burst"]["mean_multiplier"],
                                             seconds, profile["burst"], network_service, batch, mempool_body),
            "network_only_100_per_second_stress": burst_case(mean_offer_rate, Fraction(profile["burst"]["stress_offers_per_second"]),
                                             seconds, profile["burst"], network_service, batch, mempool_body),
            "network_and_cpu_burst_if_supplied": None if cpu_service is None else burst_case(
                mean_offer_rate, mean_offer_rate * profile["burst"]["mean_multiplier"], seconds,
                profile["burst"], min(network_service, cpu_service), batch, mempool_body),
            "sizing_only": "Capacity ceilings presume ideal scheduling, sized copies without retry churn, and availability of the whole declared link. Durable serial state service, disk IO, RAM, worst invalid input and tail latency need measurement.",
        },
        "independent_block_only_validator": {
            "relay": pure_blocks,
            "mempool_checks": 0,
            "wallet_uploads_received": 0,
            "steady_link_can_service_mean": block_only_intake > 0 and block_only_outtake > 0,
            "network_only_offers_per_second_equivalent": block_only_service,
            "network_only_burst": burst_case(mean_offer_rate, mean_offer_rate * profile["burst"]["mean_multiplier"],
                                             seconds, profile["burst"], block_only_service, batch, block_body),
            "annual_block_validation_cpu_microseconds_if_supplied": block_cost,
            "masked_standalone_block_cpu_budget_if_applicable": (standalone_block_cpu_budget(
                included, included + fork_payments, seconds, home, matrix) if route == "masked_whir" else None),
            "block_only_cold_recovery_by_years": block_only_cold,
            "pruned_disk_by_years": block_only_disk,
            "scope": "Downloads complete uncached block data and checks it against current branch state. Upstream wallet intake, proof data availability, block production and submitter censorship remain separate roles.",
        },
        "aggregate_builder_if_applicable": builder,
        "archive": archive_plan(archive_sizes, relayed_objects, seconds, archive, wallet_live, profile["years"]),
        "pruned_node_disk_by_years": disk,
        "cold_recovery_by_years": cold,
    }


def formatted_fraction(value):
    if not isinstance(value, Fraction):
        raise TypeError(f"unsupported JSON value {type(value).__name__}")
    if value.denominator == 1:
        return value.numerator
    return {"numerator": value.numerator, "denominator": value.denominator}


def integer_argument(minimum, maximum=None):
    def convert(raw):
        value = int(raw)
        if value < minimum or (maximum is not None and value > maximum):
            raise argparse.ArgumentTypeError(f"required range: {minimum} to {maximum or 'unbounded'}")
        return value

    return convert


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--masked-body-bytes", type=integer_argument(BODY_PREFIX + 1, 2_106_575), required=True,
                        help="full candidate body, including 4,876 B of assumed CP03-equivalent public prefix")
    parser.add_argument("--masked-max-body-bytes", type=integer_argument(BODY_PREFIX + 1, 2_106_575),
                        help="separate cap used for retained block/mempool staging; defaults to stated body size")
    parser.add_argument("--matrix-evidence", type=Path,
                        help="optional public component receipt; defaults to dimensions/MATRIX.json if present")
    parser.add_argument("--cold-genesis-bytes", type=integer_argument(0),
                        help="cold public genesis context; default is measured Gate2 genesis size")
    parser.add_argument("--aggregate-proof-bytes", type=integer_argument(1, 2_106_575),
                        help="enable the sole fallback sensitivity with a hypothetical transparent proof size per block")
    parser.add_argument("--mempool-payload-peers", type=integer_argument(0, 6), help="number of actual outbound payload copies")
    parser.add_argument("--block-payload-peers", type=integer_argument(0, 6), help="number of actual outbound block copies")
    parser.add_argument("--block-reuse-percent", type=integer_argument(0, 100))
    parser.add_argument("--wallet-blocks-per-range", type=integer_argument(1))
    parser.add_argument("--wallet-upload-copies", type=integer_argument(1))
    parser.add_argument("--extra-fork-blocks-per-year", type=integer_argument(0))
    parser.add_argument("--reorg-wallet-resubmissions-per-year", type=integer_argument(0))
    parser.add_argument("--wallet-deep-replays-at-first-year-end", type=integer_argument(0))
    parser.add_argument("--masked-mempool-us", type=integer_argument(1), help="supplied all-in CPU microseconds per standalone check")
    parser.add_argument("--masked-block-payment-us", type=integer_argument(1), help="supplied all-in CPU microseconds per included payment")
    parser.add_argument("--cp03-mempool-us", type=integer_argument(1), help="supplied all-in CPU microseconds per pre-inclusion check")
    parser.add_argument("--capsule-block-payment-us", type=integer_argument(1), help="supplied included CP03 state-check CPU microseconds per capsule")
    parser.add_argument("--aggregate-block-us", type=integer_argument(1), help="supplied outer verification CPU microseconds per block")
    args = parser.parse_args()
    if args.masked_max_body_bytes and args.masked_max_body_bytes < args.masked_body_bytes:
        parser.error("--masked-max-body-bytes must cover --masked-body-bytes")
    cp03 = actual_evidence()
    published_matrix = HERE.parent / "dimensions" / "MATRIX.json"
    matrix_path = args.matrix_evidence or (published_matrix if published_matrix.is_file() else None)
    matrix = None if matrix_path is None else measured_matrix_component(matrix_path.resolve(strict=True))
    profile = json.loads((HERE / "PROFILE.json").read_text())
    for key in profile["relay"]:
        supplied = getattr(args, key, None)
        if supplied is not None:
            profile["relay"][key] = supplied
    profile["archive"]["cold_genesis_context_bytes"] = (
        cp03["cp03"]["genesis_context_bytes"] if args.cold_genesis_bytes is None else args.cold_genesis_bytes
    )
    routes = {
        "masked_whir": ({
            "mempool": args.masked_body_bytes,
            "mempool_max": args.masked_max_body_bytes or args.masked_body_bytes,
            "included": args.masked_body_bytes,
            "included_max": args.masked_max_body_bytes or args.masked_body_bytes,
            "aggregate": 0,
        }, {
            "mempool_payment_us": args.masked_mempool_us,
            "block_payment_us": args.masked_block_payment_us,
            "block_aggregate_us": None,
        }),
    }
    if args.aggregate_proof_bytes is not None:
        routes["aggregate_cp03"] = ({
            "mempool": cp03["cp03"]["mean_body_bytes"],
            "mempool_max": CP03_2X2_MAX_BODY,
            "included": REDUCED_RECORD,
            "aggregate": args.aggregate_proof_bytes,
        }, {
            "mempool_payment_us": args.cp03_mempool_us,
            "block_payment_us": args.capsule_block_payment_us,
            "block_aggregate_us": args.aggregate_block_us,
        })
    output = {
        "format": "NODE-ROLE-PROJECTIONS01",
        "scope": "Exact protocol-byte and explicit-assumption arithmetic. Unmeasured timings are null. No annual load, WAN, pruned ledger, masked WHIR or transparent aggregation execution is implied.",
        "profile": profile,
        "excluded_from_scenario": [
            "Funding/issuance, chain-specific setup and empty-block cadence require separate accounting. Cold recovery includes one sized public genesis fetch. Candidate changes to public record sizes require fresh layout accounting.",
            "Consensus framing, peer setup, noise, transport loss beyond researcher link allowance, valid-spam budget, real dissemination latency, miner work, and measured operating cost.",
            "A remote pruning protocol, independent archive failure rates, open network broadcast, and cold-bootstrap source integrity were not implemented or measured by this calculator.",
        ],
        "actual_public_cp03_evidence": cp03,
        "actual_public_masked_matrix_component_evidence_if_present": matrix,
        "candidate_size_and_optional_cpu_parameters": routes,
        "projections": {
            name: {str(rate): project_route(name, rate, profile, sizes, costs, matrix)
                   for rate in profile["include_percentages"]}
            for name, (sizes, costs) in routes.items()
        },
    }
    print(json.dumps(output, default=formatted_fraction, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
