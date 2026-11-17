#!/usr/bin/env python3
"""Read a closed public Gate1 database; separate measured bytes from projections.

This performs no admission, pruning, cryptographic verification or capacity test.
The annual scenario is the owner's sizing input, not a traffic/storage budget.
"""
import argparse
import hashlib
import json
import sqlite3
import struct
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workload", required=True, type=Path)
    parser.add_argument("--approve-workload", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    manifest = args.workload.resolve(strict=True)
    raw = manifest.read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.approve_workload:
        raise ValueError("Workload identity differs from the reviewed Gate1 source")
    workload = json.loads(raw)
    if workload["format"] != "CP04-NETWORK-BLOCK-WORKLOAD01" or workload["ordinary_count"] != 96:
        raise ValueError("This calculation is scoped to the reviewed Gate1 96-payment sample")
    db_path = manifest.parent / "producer.sqlite"
    before = db_path.stat()
    connection = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)
    connection.execute("BEGIN")
    ordinary = connection.execute(
        "SELECT count(*),sum(full_length),sum(length(reduced)),min(length(reduced)),"
        "max(length(reduced)) FROM bodies WHERE height=2"
    ).fetchone()
    if ordinary[0] != 96 or ordinary[3:] != (4952, 4952):
        raise ValueError("Unexpected ordinary body sample")
    counts = {table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
              for table in ("leaves", "nodes", "node_undo", "nullifiers", "cores")}
    pages = connection.execute(
        "SELECT name,count(*),sum(pgsize),sum(payload),sum(unused) FROM dbstat GROUP BY name ORDER BY name"
    ).fetchall()
    connection.close()
    after = db_path.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise ValueError("Database changed during the read-only measurement")
    scan = (manifest.parent / "final.checked.scan").read_bytes()
    offset, frame_sizes = 0, []
    while offset < len(scan):
        length, = struct.unpack_from("<I", scan, offset)
        frame_sizes.append(length + 4)
        offset += length + 4
    if offset != len(scan) or len(frame_sizes) != 2:
        raise ValueError("Unexpected checked public history framing")

    payments, seconds = 100_000_000, 365 * 86400
    body_bytes = ordinary[1] / 96 * payments
    scan_bytes = frame_sizes[1] / 96 * payments
    # Source tree::append creates one row for every occupied node, including leaves.
    # This is a payload count under the present schema, not a storage benchmark.
    tree_nodes = sum((2 * payments + (1 << level) - 1) // (1 << level) for level in range(41))
    state_fields = {
        "two_nullifier_ids": payments * 2 * 64,
        "one_core_id": payments * 64,
        "two_leaves_origin_commitment_body_id": payments * 2 * (64 + 64 + 64),
        "tree_node_values": tree_nodes * 64,
    }
    result = {
        "format": "CP04-RESOURCE-MODEL01",
        "workload_sha256": args.approve_workload,
        "measured": {
            "ordinary_bodies": ordinary[0], "ordinary_full_bytes": ordinary[1],
            "ordinary_reduced_bytes": ordinary[2], "reduced_bytes_each": 4952,
            "public_scan_frame_bytes_funding_ordinary": frame_sizes,
            "public_sql_counts": counts,
            "dbstat_columns": ["name", "pages", "allocated_page_bytes", "payload_bytes", "unused_bytes"],
            "dbstat_rows": pages,
            "scope": "Read-only closed producer database, already compared with receiving ledger; no new verification or pruned database result",
        },
        "analytically_derived": {
            "annual_offered_payments": payments, "seconds_per_year": seconds,
            "payments_per_second": payments / seconds,
            "full_bodies_bytes_per_year_one_copy": body_bytes,
            "full_body_ingress_average_bits_per_second": body_bytes * 8 / seconds,
            "six_outgoing_full_copies_average_bits_per_second": body_bytes * 8 * 6 / seconds,
            "reduced_records_bytes_per_year": 4952 * payments,
            "common_scan_bytes_per_year_at_measured_96_batch_mean": scan_bytes,
            "current_schema_selected_state_fields_bytes": state_fields,
            "current_schema_selected_state_fields_sum_bytes": sum(state_fields.values()),
            "state_scope": "Two-input/two-output ordinary scenario. Field payload only: excludes reduced history, headers, row keys/overhead, indexes, undo, archive catalogs, funding, journals and replicas. Not total disk or a minimal protocol lower bound.",
            "bootstrap_transfer_only_days_at_100_mbit_per_second": body_bytes * 8 / 100_000_000 / 86400,
            "bootstrap_transfer_only_days_at_1_gbit_per_second": body_bytes * 8 / 1_000_000_000 / 86400,
            "wallet_common_scan_transfer_only_hours_at_100_mbit_per_second": scan_bytes * 8 / 100_000_000 / 3600,
        },
        "unmeasured": ["Year-scale indexed state and disk latency", "Long-history proof replay and bootstrap service", "Integrated streaming wallet decryption/witness cost", "Pruned ordinary-node remote archive publication/retrieval", "PoW work and consensus", "WAN availability, TCP loss and fan-out"],
        "decision": "Full-body pruning could move the dominant storage duty to explicit archives, but cannot erase retained state/common-history costs. Current TCP frame ACK is not an implemented LocalArchive eviction acknowledgement. No resource/participation PASS follows.",
    }
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"output": str(args.output), "full_body_tb": body_bytes / 1e12,
                      "common_scan_gb": scan_bytes / 1e9,
                      "selected_state_field_gb": sum(state_fields.values()) / 1e9}))


if __name__ == "__main__":
    main()
