"""Measure the complete experimental pair cryptographic check with the released signature service."""
import argparse
import json
from pathlib import Path
import resource
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
sys.path.insert(0,str(HERE.parent/"atomic-swap"))
import measure


def run(deployment, binary, matrices, bundle):
    chain, ledger, _ = measure.load_public(deployment)
    import packet
    raw = bundle.read_bytes()
    first, _ = packet.split(raw)
    started = time.monotonic()
    role = ledger.public_role()
    try:
        # Finish cold service startup and validate IPC format. The actual signatures
        # are checked by validate(), once for each wallet, inside the measured interval.
        if role.call(b"V" + bytes(64+packet.SIG)) != b"0":
            raise ValueError("invalid signature service verdict")
        startup = time.monotonic()-started
        prev, hz = measure.live_cpu(role.proc.pid)
        start = time.monotonic()
        own = time.process_time()
        child = measure.children_cpu()
        packet.validate(raw,chain.NETWORK,first.expiry,binary,matrices/"SLG1.r1cs",role)
        wall = time.monotonic()-start
        cpu_parent = time.process_time()-own
        cpu_proofs = measure.children_cpu()-child
        end, _ = measure.live_cpu(role.proc.pid)
        cpu_signature = sum(x["cpu_s"] for x in end)-sum(x["cpu_s"] for x in prev)
        # Linux reports largest terminated child's RSS, covering the two
        # sequential fresh proof checks. The signature service is still alive.
        max_child = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        own_peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        role.close()
    finally:
        role.abort()
    return dict(bytes=len(raw),signature_service_startup_and_negative_control_s=startup,
                pair_wall_s=wall,parent_cpu_s=cpu_parent,proof_processes_cpu_s=cpu_proofs,
                live_signature_service_cpu_s=cpu_signature,signature_cpu_tick_s=1/hz,
                total_pair_cpu_s=cpu_parent+cpu_proofs+cpu_signature,
                parent_peak_KiB=own_peak,largest_exited_child_peak_KiB=max_child,
                scope="pair layout, two fresh full WHIR checks with registered matrix reads, two SLH-DSA verifications, fee and uniqueness checks; excludes selected-chain database and PoW")


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for k in ("deployment","binary","matrices","bundle"):
        p.add_argument(k,type=Path)
    a=p.parse_args()
    print(json.dumps(run(*(v.resolve(strict=True) for v in vars(a).values())),indent=2))
