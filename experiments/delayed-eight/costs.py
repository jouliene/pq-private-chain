"""Retained byte accounting, measured roles and explicit 365-day occupancy scenarios."""
import argparse
import json
from pathlib import Path

YEAR=365*86400
N=100_000_000
MIX={"sparse":([.85,.10,.04,.01],1),"busy":([.05,.10,.15,.70],1/9)}


def analyze(live,certs,accept):
    manifest=json.loads((live/"CAPTURE.json").read_bytes())
    branch=json.loads((live/"BRANCH.json").read_bytes())
    transfer=manifest["payments"]+[branch["outside"]]
    groups=certs["certificate"]
    proof=groups["8"]["proof_B"]
    assert proof==groups["2"]["proof_B"]
    source_B=certs["source_bytes"]["0"]
    real=accept["compacted"]["store"]
    core_set=manifest["original_selected"]
    original_sid={p["sid"] for p in manifest["payments"]}
    union=set(branch["winner"])|set(core_set)
    def by_branch(order):
        cores=sum(222+32*len(raw_payments.get(b,())) for b in order)
        active={sid for b in order for sid in raw_payments.get(b,())}
        used=len(active&original_sid);direct=len(active-original_sid)
        return dict(core_B=cores,blocks=len(order),certified_placements=used,uncertified=direct,
                    retained_B=16+cores+4*len(order)+(groups["8"]["certificate_B"]+4 if used else 0)+direct*(source_B+4))
    raw_payments={}
    for p in transfer:raw_payments.setdefault(p["block"],[]).append(p["sid"])
    original=by_branch(core_set);replacement=by_branch(branch["winner"]);both=by_branch(union)
    assert both["retained_B"]==real["interchange_B"]
    costs=certs["builder_meters"]
    cpu=sum(m["cpu_s"] for m in costs if m["operation"] in ("source_verify_assign","certificate_prove"))
    first_prove=next(m for m in costs if m["operation"]=="certificate_prove")
    first_prep=next(m for m in costs if m["operation"]=="source_verify_assign")
    per=first_prove["cpu_s"]+first_prep["cpu_s"]
    projections={}
    for name,(widths,blank) in MIX.items():
        blocks=(1+blank)/sum(i*p for i,p in enumerate(widths,1))
        def retained(used,real_count,ex=0):
            cert=proof+9+3584*real_count+4
            return 16+N*(226*blocks+32+(1-ex)*cert/used+ex*(source_B+4))
        projections[name]=dict(blocks_per_inclusion=blocks,raw_full_wallet_source_TB=N*source_B/1e12,
            wallet_submit_TB=N*143210/1e12,ack_TB=N*120/1e12,
            one_raw_block_relay_body_TB=N*(222*blocks+4+source_B)/1e12,
            raw_block_plus_one_extra_packet_edge_TB=N*(222*blocks+4+2*source_B)/1e12,
            compact_TB_by_actual_count={str(k):retained(k,k)/1e12 for k in range(1,9)},
            four_selected_in_full_eight_TB=retained(4,8)/1e12,
            fraction_direct_allowed_at_5TB=(5e12-retained(8,8))/(retained(8,8,1)-retained(8,8)),
            cold_wallet_GB_before_paging=N*(305*blocks+3744)/1e9,
            mean_interval_needed_for_100M_s=YEAR/(N*blocks),capacity_at_two_s_mean=N/(2*N*blocks/YEAR))
    relay=live/"RELAY.json"
    return dict(format="D8-COSTS-1",measured=dict(original_branch=original,replacement_branch=replacement,all_retained=both,
        before_all_B=accept["initial"]["full"]["interchange_B"],direct_original_bodies_all_B=accept["initial"]["full_bodies_B"],
        after_partial_all_B=accept["partial_compacted"]["store"]["interchange_B"],disk=real["sqlite_B"],
        cold_runtime_B=accept["cold_disk_before_spend"],recovery=accept["restore"]["cold_sync"],
        upload_B=sum(f["request_B"] for p in transfer for f in p["frames"]),
        acknowledgments_B=sum(f["reply_B"] for p in transfer for f in p["frames"]),
        lone_command_to_confirmed_s=transfer[0]["online_to_observed_s"],
        min_max_command_to_confirmed_s=[min(p["online_to_observed_s"] for p in transfer),max(p["online_to_observed_s"] for p in transfer)],
        verified_full_slots=8,proof_attempts=sum(p["attempts"] for p in transfer),direct_offers=len(transfer),
        backlog_direct_original_branch=8,backlog_after_first_install_original_branch=0,
        backlog_after_reorganization_winner=1,backlog_after_partial=0),
        observed_peer_relay=json.loads(relay.read_bytes()) if relay.exists() else None,
        scenarios=projections,builder=dict(full_preparation_and_proving_CPU_s=per,
            cores_at_100M=per*N/YEAR/8,workers_at_100M=groups["8"]["proving_call_wall_s"]*N/YEAR/8,
            original_backlog_payload_B_per_24h=N/YEAR*86400*source_B,
            one_warm_builder_payments_per_s=8/groups["8"]["proving_call_wall_s"],
            measured_full_plus_partial_CPU_s=cpu),independent_capacity=dict(slots=4,research_block_interval_s=2,
            fully_occupied_payments_per_year=YEAR/2*4,required_payments_per_s=N/YEAR))


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for k in ("live","certificates","accept","out"):p.add_argument(k,type=Path)
    a=p.parse_args()
    result=analyze(a.live,json.loads(a.certificates.read_bytes()),json.loads(a.accept.read_bytes()))
    a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
