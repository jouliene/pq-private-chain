"""Price two released packet encodings using the pinned public funded-wallet capture."""
import argparse
from decimal import Decimal, localcontext
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "experiments/funded-whir/review"))
from public import split
sys.path.insert(0, str(ROOT / "devnet"))
from transport import frame


def read_capture(path):
    archive = path.read_bytes()
    digest = hashlib.sha256(archive).hexdigest()
    pins = (ROOT / "experiments/funded-whir/RELEASE.sha256").read_text().splitlines()
    if [row.split()[0] for row in pins if row.split()[1] == "independent-public.tar.gz"] != [digest]:
        raise ValueError("expected the pinned independent funded-wallet release")
    names = ("ordinary.released", "restored-onward.transfer", "released.swap", "released-swap.block",
             "ordinary.candidate", "candidate.swap")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as capture:
        return {name: capture.extractfile("public/" + name).read() for name in names}


def project(transfer_bytes, swap_frames, basis):
    swap_bytes = sum(swap_frames) + 13
    # The last three counterfactual formats exceed real RPC or block limits.
    # Price the same envelopes by length, without submitting invalid data.
    rpc_overhead = len(frame({"op": "submit"}))
    slots = {"ordinary": transfer_bytes + 4, "swap": sum(swap_frames) + 8}
    scenarios = []
    for percent in (0, 10, 100):
        for count in (10_000_000, 30_000_000, 100_000_000):
            pairs = count * percent // 100
            singles = count - pairs
            min_blocks = (singles + 2 * pairs + 3) // 4
            slot_data = singles * slots["ordinary"] + pairs * slots["swap"]
            pending = singles * transfer_bytes + pairs * swap_bytes
            rpc = pending + count * rpc_overhead
            archive = slot_data + 222 * min_blocks
            one_peer = pending + archive
            seconds = 365 * 24 * 3600
            scenarios.append(dict(operations=count, swap_percent=percent, minimum_blocks=min_blocks,
                packed_mean_block_interval_ceiling_s=round(seconds / min_blocks, 5),
                one_final_submission_each_RPC_B=rpc, pending_bodies_B=pending,
                packed_archive_B=archive, one_operation_per_block_archive_B=slot_data + 222 * count,
                one_pending_and_one_packed_chain_copy_ingress_B=one_peer,
                two_downstream_pending_and_chain_egress_B=2 * one_peer,
                mean_egress_Mbit_s_two_downstream=round(16 * one_peer / (seconds * 1_000_000), 5)))
    return dict(basis=basis, transfer_B=transfer_bytes, swap_submission_B=swap_bytes,
                swap_frame_B=swap_frames, RPC_submit_overhead_B=rpc_overhead,
                occupied_slot_bytes=slots, scenarios=scenarios)


def expected_proof(profile):
    # Per-level probability that the node is empty while its sibling is occupied.
    # The two terminal trees share their indices. Linearity of expectation still applies.
    with localcontext() as ctx:
        ctx.prec = 64
        expected = Decimal(profile["outer_direct_B"])
        for stage in profile["stages"]:
            height, q = stage["log_n"], stage["queries"]
            n = 1 << height
            copies = 2 if stage["width"] == 1 else 1
            distinct = n * (1 - (1 - Decimal(1) / n)**q)
            frontier = Decimal(0)
            for level in range(1, height + 1):
                nodes = 1 << level
                frontier += nodes * ((1 - Decimal(1) / nodes)**q - (1 - Decimal(2) / nodes)**q)
            expected += stage["bytes"]["roots"] + stage["bytes"]["direct"]
            expected += copies * (distinct * (stage["width"] * stage["d"] * 40 + 64) + 64 * frontier)
        return int(expected)


def costs(path):
    data = read_capture(path)
    transfer = b"MSP1\x01\x00" + data["ordinary.released"]
    assert len(transfer) == len(data["restored-onward.transfer"])
    released, _, _ = split(data["released.swap"], False)
    experimental, _, _ = split(data["candidate.swap"], True)
    block = data["released-swap.block"]
    slots = b"".join(len(f).to_bytes(4, "little") + f for f in released)
    assert block[:8] == b"ASTPOW01" and block[213] == 2 and block[214:-8] == slots
    here = Path(__file__).resolve().parent
    profile = json.loads((here/"primary/MODEL.json").read_bytes())["primary"]
    gates = json.loads((here/"kkw/GATES.json").read_bytes())
    base = project(len(transfer), list(map(len, released)), "captured packet sizes; annual counts projected")
    previous = project(len(data["ordinary.candidate"]), list(map(len, experimental)),
                       "captured prior WHIR packets; hypothetical chain archive")
    assert base["swap_submission_B"] == len(data["released.swap"])
    assert previous["swap_submission_B"] == len(data["candidate.swap"])
    transfer_fixed = 9 + 31*8 + 2*1792
    signed_fixed = 9 + 34*8 + 2*1792 + 107 + 17088
    def price(ordinary, leg, basis):
        return project(transfer_fixed + ordinary, [signed_fixed + leg] * 2, basis)
    mean = expected_proof(profile)
    maximum = profile["maximum_proof_B"]
    return {"funded_capture": "funded-whir-2026-11-20/independent-public.tar.gz",
            "observed_mined_swap_block_B": len(block), "block_fixed_B": len(block) - len(slots),
            "live_MNG1_SLG1": base, "previous_WHIR_research_encoding": previous,
            "CFW_projected_mean": price(mean, mean, "ideal independent uniform queries; mean rounded down by <1 B per proof; over-cap"),
            "CFW_geometry_maximum": price(maximum, maximum, "geometry worst case for every proof simultaneously; over-cap"),
            "KKW_compiler_floor": price(gates["suites"]["MNG1"]["online_B_floor"],
                gates["suites"]["SLG1"]["online_B_floor"],
                "lower bound for the selected Boolean lowering; online AND partials only plus same public and receipt framing; over-cap")}


if __name__ == "__main__":
    if not __debug__:
        sys.exit("enable assertions")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("public_capture", type=Path)
    print(json.dumps(costs(parser.parse_args().public_capture), indent=2))
