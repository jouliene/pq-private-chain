"""Measure complete confirmed packets with only the public verifier and the two registered profiles."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import sys
import time


def measure(deployment, public):
    sys.path.insert(0,str(deployment/"devnet"))
    import chain
    import runtime
    from run import Resources
    from managed_ops import parse
    trial=json.loads((public/"RUN.json").read_bytes())
    if trial["network"]!=chain.NETWORK.hex() or trial["vk"]!=chain.PROFILE.hex():
        raise ValueError("public evidence network or key")
    result={}
    for name in ("fixed","fixed-pay","register","mint","deliver","return","branch-burn","burn"):
        row=trial["payments"][name]
        raw=(public/"packets"/(row["tx"]+".bin")).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=row["tx"] or len(raw)!=row["packet_B"]:
            raise ValueError("transaction size or identity")
        inner=raw if raw.startswith(b"AST1\x01") else parse(raw).inner
        resources=Resources(runtime.config(deployment/"runtime"))
        times=[]
        try:
            # Warm up once, charge setup separately. Each following call verifies
            # the full proof, receipt digest and applicable issuer signature.
            for _ in range(4):
                started=time.monotonic()
                slot,=resources.backend.verify(raw)
                times.append(time.monotonic()-started)
                if slot.fee!=3:
                    raise ValueError("unexpected native fee")
            meters=resources.finish("verifier")["meters"]
            resources.finish("hash")
        finally:
            resources.close()
        result[name]=dict(full_packet_B=len(raw),inner_proof_B=int.from_bytes(inner[5:9],"little"),
                          ciphertext_pair_B=3584,envelope_B=len(raw)-len(inner),block_length_prefix_B=4,
                          wallet_wall_s=row["proving_wall_s"],wallet_cpu_s=row["prover_cpu_s"],
                          wallet_role_peak_KiB=row["prover_role_peak_rss_KiB"],
                          wallet_native_meters=row.get("wallet_native_meters",[]),
                          public_verify_wall_s_median=statistics.median(times[1:]),verifier_meters=meters)
    return result


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("deployment","public"):
        p.add_argument(name,type=lambda s:Path(s).resolve())
    a=p.parse_args()
    print(json.dumps(measure(a.deployment,a.public),indent=2,sort_keys=True))
