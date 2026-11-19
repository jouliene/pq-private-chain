"""Measured role meters and explicit format/retention projections at 100M selected payments/year."""
import argparse
import json
from pathlib import Path
from statistics import mean
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from budget import PAYMENTS, projection

def costs(w,r):
    selected=[w["lone"],*w["concurrent"],w["recipient_spend"]]
    proof=next(iter({p["packet_B"] for p in selected}))
    if any(p["packet_B"]!=proof or p["real_inputs"]!=2 for p in selected) or proof!=143187:
        raise ValueError("expected four complete positive-input payments")
    measured={}
    for role in ("wallet_prover_setup","compact_prove"):
        records=[m for p in selected for m in p["wallet_metrics"] if m["operation"]==role]
        assert len(records)==len(selected)
        measured[role]=dict(mean_cpu_s=mean(i["cpu_s"] for i in records),mean_wall_s=mean(i["elapsed_s"] for i in records),
                            peak_rss_KiB=max(i["peak_rss_kib"] for i in records))
    req=w["lone"]["submission_frame"]["request_B"]
    ack=w["lone"]["submission_frame"]["reply_B"]
    qps=PAYMENTS/(365*86400)
    cpu=mean(m["cpu_s"] for m in r["standalone_native_verify"])
    scenarios=projection(proof)
    for v in scenarios.values():
        blocks=v['blocks_per_inclusion']*PAYMENTS
        v.update(sender_submit_TB=req*PAYMENTS/1e12,ack_TB=ack*PAYMENTS/1e12,
            cold_range_framing_GB=9*((int(blocks)+15)//16)/1e9,
            eight_block_mean_interval_s=8*365*86400/blocks,
            live_verify_cpu_s_per_s_one_validation_pass=qps*cpu,
            annual_live_wallet_proving_cpu_core_years=qps*sum(m['mean_cpu_s'] for m in measured.values()),
            pruned_payload_floor_GB=v['node_effects_min_GB']+v['headers_ids_GB'],
            serving_projection_storage_GB=v['cold_wallet_projection_GB'],
            max_two_full_occupied_bodies_B=2*(222+4*(4+proof)),
            next_eight_proof_budget_5TB_B=int(8*(50000-32-3584-226*v["blocks_per_inclusion"])-13),
            next_eight_proof_budget_1TB_B=int(8*(10000-32-3584-226*v["blocks_per_inclusion"])-13))
    return dict(complete_proof_B=proof-9-2*1792,packet_B=proof,
        baseline_packet_B=230206,reduction_fraction=1-proof/230206,real_wallets=measured,
        node_warm_verify_cpu_s_mean=cpu,measured_capture_relay=w['block_relay'],
        installed_vk_B=r['external_vk_B'],pruned_storage_only_sample_B=r['storage_only_pruned_two_heights_B'],
        full_db_sample_B=r["sqlite_full_B"],scenarios=scenarios)

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("run",type=Path);p.add_argument("replay",type=Path)
    a=p.parse_args()
    print(json.dumps(costs(json.loads(a.run.read_bytes()),json.loads(a.replay.read_bytes())),indent=2,sort_keys=True))
