"""Summarize four successful wallet operations and their first public replay from recorded role meters."""
import argparse
import json
from pathlib import Path
import statistics

HERE = Path(__file__).resolve().parent


def summarize(records):
    if not records:
        raise ValueError("no successful measurements")
    return dict(count=len(records), cpu_s_mean=statistics.mean(r["cpu_s"] for r in records),
                wall_s_mean=statistics.mean(r["elapsed_s"] for r in records),
                peak_rss_KiB=max(r["peak_rss_kib"] for r in records))


def calculate(evidence):
    data = json.loads((evidence / "RESULT.json").read_bytes())
    meters = [r for who in "ABCD" for r in data["role_meters"][who]]
    replay = data["public_replay"]["public_verifier_meters"]
    if replay[0]["operation"] != "verifier_setup" or [r["operation"] for r in replay[1:5]] != ["public_verify"] * 4:
        raise ValueError("replay order differs")
    transfers = data["transfers"]
    if len(transfers) != 4:
        raise ValueError("expected two sends, restored two-input successor and one-input successor")
    packets = [r["block"]["packet_bytes"] for r in transfers]
    blocks = [(evidence / "blocks" / f"{i+1}.bin").stat().st_size for i in range(4)]
    return dict(payment_B=packets, block_B=blocks, public_genesis_B=(evidence / "genesis.bin").stat().st_size,
                proof_B=[r["block"]["proof_bytes"] for r in transfers],
                receipt_pair_B=[r["block"]["receipts_bytes"] for r in transfers],
                wallet_setup=summarize([r for r in meters if r["operation"] == "wallet_setup"]),
                wallet_prove=summarize([r for r in meters if r["operation"] == "prove"]),
                public_verifier_setup=summarize(replay[:1]), public_verify=summarize(replay[1:5]),
                one_packet_copy_at_100M_TB=statistics.mean(packets) * 1e8 / 1e12,
                full_one_payment_block_copy_at_100M_TB=statistics.mean(blocks) * 1e8 / 1e12)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("evidence", type=Path, nargs="?", default=HERE / "candidate/evidence")
    args = ap.parse_args()
    print(json.dumps(calculate(args.evidence), indent=2, sort_keys=True))
