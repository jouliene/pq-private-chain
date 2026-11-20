"""Measure the deployed public SWP1 pair verifier on a complete public bundle."""
import argparse
from hashlib import sha256
import importlib
import json
import os
from pathlib import Path
import platform
import resource
import statistics
import sys
import time


def load_public(deployment):
    dev = deployment.resolve(strict=True) / "devnet"
    sys.path.insert(0, str(dev))
    # chain installs the exact staged advancing-payments wire and state paths.
    chain = importlib.import_module("chain")
    ledger = importlib.import_module("swap_ledger")
    wire = importlib.import_module("swap_wire")
    if any(Path(module.__file__).resolve().parent != dev for module in (chain,ledger,wire)):
        raise ValueError("public review requires the staged code")
    return chain, ledger, wire


def read_bundle(wire, path):
    with path.open("rb") as f:
        data = f.read(wire.MAX_BUNDLE + 1)
    return data, wire.split(data)


def children_cpu():
    r = resource.getrusage(resource.RUSAGE_CHILDREN)
    return r.ru_utime + r.ru_stime


def live_cpu(pid):
    # The PID-namespace supervisor does not forward native wait4 CPU to the Python parent.
    # Sample the actual process and both launchers while they are still alive.
    todo = [pid]
    roles = []
    hz = os.sysconf("SC_CLK_TCK")
    while todo:
        pid = todo.pop()
        root = Path("/proc")/str(pid)
        fields = (root/"stat").read_text().rsplit(")",1)[1].split()
        roles.append({"process": (root/"comm").read_text().strip(),
                      "cpu_s": (int(fields[11])+int(fields[12]))/hz})
        todo.extend(map(int,(root/"task"/str(pid)/"children").read_text().split()))
    if sum(row["process"]=="native" for row in roles) != 1:
        raise RuntimeError("could not measure the unique sandboxed native verifier")
    return roles, hz


def run_samples(ledger, wire, data, expected_network, count):
    # Each trial starts a fresh, read-only verifier. This code creates no node or wallet.
    parent_start = time.process_time()
    child_start = children_cpu()
    start = time.perf_counter()
    role = ledger.public_role()
    completed_helpers_cpu = children_cpu()-child_start
    trials = []
    try:
        for _ in range(count):
            before = list(role.sizes)
            wall = time.perf_counter()
            cpu = time.process_time()
            frames = wire.split(data)
            tip_height = wire.read_frame(frames[0]).expiry
            slots = ledger.verify_pair(frames, role, expected_network, tip_height)
            if len(slots) != 2 or sum(s.fee for s in slots) != 3:
                raise ValueError("incomplete verified effects")
            trials.append({"pair_wall_s":time.perf_counter()-wall, "parent_pair_cpu_s":time.process_time()-cpu,
                           "approval_wall_from_process_launch_s":time.perf_counter()-start,
                           "ipc_to_verifier_B":role.sizes[0]-before[0],
                           "ipc_from_verifier_B":role.sizes[1]-before[1]})
        parent_at_verdict = time.process_time()-parent_start
        live, hz = live_cpu(role.proc.pid)
        meters = role.close()
    finally:
        role.abort()
    elapsed = time.perf_counter()-start
    child_cpu = children_cpu()-child_start
    parent_cpu = time.process_time()-parent_start
    operations = [m["operation"] for m in meters]
    if operations != ["verifier_setup"] + ["public_verify"]*(4*count):
        raise ValueError("incomplete native proof and signature meters")
    labels = ("leg0_proof","leg0_signature","leg1_proof","leg1_signature")
    for i,t in enumerate(trials):
        items = meters[1+4*i:5+4*i]
        t["stage"] = dict(zip(labels,items))
        t["native_verification_cpu_s"] = sum(x["cpu_s"] for x in items)
        t["parent_plus_native_pair_cpu_s"] = t["native_verification_cpu_s"]+t["parent_pair_cpu_s"]
        t["native_process_peak_rss_KiB"] = max(x["peak_rss_kib"] for x in items)
    return {"native_setup":meters[0], "calls":trials, "launch_through_shutdown_wall_s":elapsed,
            "parent_cpu_through_shutdown_s":parent_cpu, "children_cpu_through_shutdown_s":child_cpu,
            "live_sandbox_process_cpu_at_last_verdict":live, "clock_ticks_per_s":hz,
            "completed_setup_helpers_cpu_s":completed_helpers_cpu,
            "parent_and_all_observed_process_cpu_to_last_verdict_s": (
                parent_at_verdict+completed_helpers_cpu+sum(row["cpu_s"] for row in live)),
            "native_high_resolution_metered_cpu_s":sum(x["cpu_s"] for x in meters),
            "parent_process_peak_rss_KiB":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}


def sizes(chain, wire, data, frames):
    from transport import frame as rpc_frame
    from swap_terms import SIZE as private_terms_size
    parts = wire.pair(frames)
    proofs = [int.from_bytes(p.leg[5:9],"little") for p in parts]
    legs = [len(p.leg) for p in parts]
    total_proofs = sum(proofs)
    total_receipts = 2*wire.CT_PAIR
    sizes = {"proofs_B":proofs, "proofs_total_B":total_proofs, "four_ciphertexts_B":total_receipts,
             "inner_magic_width_length_B":18, "complete_legs_B":legs,
             "final_signatures_B":2*wire.SIG, "two_frame_headers_B":2*wire.HEADER,
             "two_frame_headers_by_field_B":{"magic_version":10,"side":2,"payer":2,"expiry":8,
                                              "network":64,"terms_commitment":64,"companion_leg_digest":64},
             "individual_block_frames_B":[len(f) for f in frames],
             "submission_magic_version_lengths_B":13, "submission_bundle_B":len(data)}
    if len(data) != total_proofs + total_receipts + 18 + 2*wire.SIG + 2*wire.HEADER + 13:
        raise ValueError("incomplete byte decomposition")
    block_vector = chain.packet_vector(frames)
    empty_vector = chain.packet_vector(())
    sizes.update(block_vector_including_count_B=len(block_vector),
                 block_incremental_over_empty_B=len(block_vector)-len(empty_vector),
                 whole_two_frame_block_B=213+len(block_vector)+8,
                 rpc_submit_request_B=len(rpc_frame({"op":"submit"},data)),
                 aggregate_fee_native_units=3, physical_payment_slots=2,
                 negotiation_files_B={"private_terms_schema_only":private_terms_size,
                                      "two_preoffers":sum(legs), "two_authorizations":2*wire.SIG},
                 one_copy_each_negotiation_file_B=private_terms_size+sum(legs)+2*wire.SIG)
    return sizes


def measure(deployment, blob):
    chain,ledger,wire = load_public(deployment)
    data,frames = read_bundle(wire,blob)
    cold = run_samples(ledger,wire,data,chain.NETWORK,1)
    warm = run_samples(ledger,wire,data,chain.NETWORK,6)
    def median(field):
        return statistics.median(x[field] for x in warm["calls"][1:])
    return {"bundle_sha256":sha256(data).hexdigest(), "machine":platform.machine(),
            "system":platform.platform(), "native_threads":2, "wire":sizes(chain,wire,data,frames),
            "swap_verifier_key_sha256":sha256((deployment/"swap-keys/swap.vk").read_bytes()).hexdigest(),
            "approved_binary_sha256":(deployment/"devnet/approved-swap-native.sha256").read_text().strip(),
            "cold":cold, "warm_process_including_one_warmup":warm,
            "warm_measured_pairs":5, "warm_median_pair_wall_s":median("pair_wall_s"),
            "warm_median_parent_plus_native_pair_cpu_s":median("parent_plus_native_pair_cpu_s"),
            "warm_peak_native_process_KiB":max(t["native_process_peak_rss_KiB"] for t in warm["calls"][1:])}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("deployment",type=Path)
    parser.add_argument("public_bundle",type=Path)
    args=parser.parse_args()
    print(json.dumps(measure(args.deployment.resolve(),args.public_bundle),indent=2,sort_keys=True))
