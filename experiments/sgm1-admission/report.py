"""Separate measured mixed service from linearly projected calendar costs."""
import json
import sys
from pathlib import Path
from statistics import median

YEAR = 365.25 * 86400
def summarize(runs):
    catch, = (r for r in runs if r["mode"]=="catchup")
    n=catch["operations"]
    replay=n/(catch["funding_s"]+catch["wall_including_close_s"])
    rate=n/catch["wall_including_close_s"]
    cpu_per_op=catch["cpu_including_close_s"]/n
    frames=catch["bytes_read"]/n
    def service_metrics(r):
        commit=r["commit_s"]
        a=r["arrival_s"]
        q=[sum(t<=offer for t in a)-sum(t<=offer for t in commit) for offer in a]
        return dict(operations=r["operations"],offered_op_s=r["offered_op_s"],
                    achieved_first_offer_to_final_commit_op_s=r["op_per_s"],
                    actual_ingress_op_s=(n-1)/(a[-1]-a[0]),
                    peak_outstanding=r["peak_outstanding"],outstanding_at_half=q[n//2-1],
                    outstanding_at_each_tenth_offer=q[9::10],
                    outstanding_at_last_offer=r["outstanding_at_last_offer"],drain_s=r["drain_s"],
                    p50_arrival_to_commit_s=median(y-x for x,y in zip(a,commit)),
                    max_arrival_to_commit_s=r["max_arrival_to_commit_s"],cpu_core_mean=r["cpu_cores"],
                    cpu_per_leg_s=r["cpu_per_leg_s"],sampled_tree_peak_KiB=r["sampled_process_tree_peak_KiB"])
    annual={}
    for num in (10_000_000,30_000_000,100_000_000):
        live=num/YEAR
        paced=next((r for r in runs if r["mode"]==f"{num//1_000_000}M"),None)
        annual[str(num)]=dict(measured_live_core_mean=paced["cpu_cores"] if paced else None,
                arrivals_per_s=live,average_legs_per_s=live*1.1,
                two_core_cpu_allowance_per_leg_s=2/(live*1.1),
                projected_core_demand=live*cpu_per_op,
                payment_and_swap_payload_TB_per_copy=num*frames/1e12,
                historical_replay_days_no_new_work=num/rate/86400,
                historical_replay_days_with_same_live_flow=(
                    num/(rate-live)/86400 if rate>live else None))
    return dict(measured={r["mode"]:service_metrics(r) for r in runs},
                catchup_from_empty_including_funding_and_close_op_s=replay,
                catchup_after_funding_including_close_op_s=rate,
                charged_cpu_s_per_leg=catch["cpu_including_close_s"]/catch["distinct_legs"],
                mean_wire_bytes=frames,closed_db_bytes=catch["db_closed_bytes"],
                scenarios=annual)
if __name__=="__main__":
    print(json.dumps(summarize(json.loads(Path(sys.argv[1]).read_text())),indent=2))
