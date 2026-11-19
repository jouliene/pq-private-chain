"""From the selected branch and paid-width scenarios, size a proof-independent block core and detachable archive."""
import json
from pathlib import Path
import sys
from statistics import mean

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from build import ROOT,CAPTURE
from transport import frame

AP=ROOT/"experiments/advancing-payments"
YEAR=365*86400
PAY=100_000_000
MIX={"sparse":([.85,.10,.04,.01],1),"busy":([.05,.10,.15,.70],1/9)}
WIRE=230206
CORE=222
SID=32


def read(path):
    return json.loads(path.read_bytes())


def schedule(stamps,width,delay):
    """FIFO assignment to one warm detached builder. Singles remain direct until their pack verifies."""
    end=0.
    events=[]
    released=[]
    for i in range(0,len(stamps)-width+1,width):
        items=stamps[i:i+width]
        begin=max(end,items[-1])
        end=begin+delay
        released.extend(end-s for s in items)
        events.extend((s,1) for s in items)
        events.append((end,-width))
    seen=peak=0
    for _,delta in sorted(events):
        seen+=delta
        peak=max(peak,seen)
    return dict(input_count=len(stamps),packs=len(released)//width,uncompacted_tail=len(stamps)-len(released),
                max_wallet_admission_delay_from_background_build_s=0,
                first_to_last_inclusion_span_s=stamps[-1]-stamps[0],
                first_to_last_certificate_ready_s=end-stamps[0],mean_temporary_retention_s=mean(released),
                peak_temporary_singletons=peak,maximum_temporary_retention_s=max(released))


def run():
    measured=read(AP/"costs/COSTS.json")
    widths=[measured["widths"][str(k+1)]["packet"] for k in range(4)]
    assert widths[0]==WIRE
    gate=read(HERE/"evidence/BUILD.json")
    work=gate["builder"]["meters"][-1]
    assert work["operation"]=="builder_aggregate" and widths[2]==gate["certificate_B"]
    widths_cpu=[0.]+[measured["widths"][str(k)]["outer_builder"]["cpu_s"]["mean"] for k in range(2,5)]
    widths_wall=[0.]+[measured["widths"][str(k)]["outer_builder"]["wall_s"]["mean"] for k in range(2,5)]
    widths_cpu[2],widths_wall[2]=work["cpu_s"],work["elapsed_s"]
    cert_cpu=read(AP/"costs/VERIFY_COST.json")["measurements"]
    verify=[mean(row["cpu_s"] for row in cert_cpu if row["k"]==k) for k in range(1,5)]
    fixture=read(CAPTURE/"RESULT.json")
    history={r["tip"]:r for events in fixture["observed_blocks"].values() for r in events}
    captured=[history[bid] for bid in fixture["winning"]]
    stamps=[r["found_unix"] for r in captured for _ in range(r["payments"])]
    paced=read(AP/"evidence/paced/DIRECT.json")
    periodic=[p["included_s"] for p in paced["payments"]]
    request=len(frame(dict(op="submit"),bytes(WIRE)))
    ack=len(frame(dict(ok=True,result=dict(id="0"*64,duplicate=False))))
    block_request=len(frame(dict(op="block",id="0"*64)))
    block_response=len(frame(dict(ok=True,result={})))
    results=[]
    def model(name,mix,empty,share):
        count=PAY*share
        width=sum(k*w for k,w in enumerate(mix,1))
        paid=count/width
        blocks=paid*(1+empty)
        common=16+(CORE+4)*blocks+SID*count
        complete=common+count*(WIRE+4)
        # One known block fetch per selected block, each replying with a self-contained direct archive.
        live=count*(WIRE+4)+blocks*(16+4+CORE+block_request+block_response)+SID*count
        cases={}
        for strategy,freq in (("per_paid_block",[paid*w for w in mix]),("cross_block_3",[0.,0.,count/3,0.]),
                              ("cross_block_4",[0.,0.,0.,count/4]),("no_builder",[count,0.,0.,0.])):
            annual=common+sum((n+4)*f for n,f in zip(widths,freq))
            detached=sum(freq[i]*(4+widths[i]) for i in range(1,4))
            cases[strategy]=dict(archive_TB=annual/1e12,archive_B_per_included=annual/count,
                archive_days_per_TB=365e12/annual,archive_days_per_5TB=5*365e12/annual,
                background_builder_wall_s_per_s=sum(f*w for f,w in zip(freq,widths_wall))/YEAR,
                background_builder_cpu_s_per_s=sum(f*c for f,c in zip(freq,widths_cpu))/YEAR,
                cold_certificate_verify_cpu_s_per_s=sum(f*c for f,c in zip(freq,verify))/YEAR,
                optional_new_certificate_distribution_one_copy_TB=detached/1e12)
        return dict(mix=name,included=count,offered=PAY,mean_paid_width=width,selected_blocks=blocks,
                    full_initial_selected_archive_TB=complete/1e12,one_initial_direct_block_fetch_edge_TB=live/1e12,
                    preinclusion_optional_extra_submit_edge_TB=PAY*(request+ack)/1e12,
                    direct_ingress_verify_cpu_s_per_s=PAY*verify[0]/YEAR,
                    direct_block_admission_verify_cpu_s_per_s=count*verify[0]/YEAR,
                    full_wallet_proving_cpu_s_per_s=PAY*measured["wallet_warm"]["cpu_s"]["mean"]/YEAR,
                    wallet_submit_requests_TB=PAY*request/1e12,wallet_ACKs_TB=PAY*ack/1e12,
                    new_cert_archive=cases)
    for name,(mix,empty) in MIX.items():
        for rate in (1,.95):
            results.append(model(name,mix,empty,rate))
    side=[history[h] for h in fixture["reorg"]["detached"]]
    def stored(rows,k):
        n=sum(x["payments"] for x in rows)
        return 16+len(rows)*(4+CORE)+n*SID+sum(widths[v-1]+4 for v in k)
    return dict(encoded_packet_B=widths,actual_3_distinct_wallets_elapsed_s=work["elapsed_s"],
                serialized_submit_B=request,serialized_ack_B=ack,selected_block_request_B=block_request,
                selected_block_response_frame_overhead_B=block_response,
                observed_selected_work=dict(blocks=len(captured),payments=len(stamps),empty_blocks=sum(not r["payments"] for r in captured),
                    captured_original_archive_B=fixture["archive_B"],hypothetical_direct_archive_B=stored(captured,[1]*len(stamps)),
                    hypothetical_detached_archive_B=stored(captured,[3]),
                    simulated_schedule_from_observed_inclusions=schedule(stamps,3,widths_wall[2])),
                observed_retained_side_branch=dict(blocks=len(side),payments=sum(r["payments"] for r in side),
                    direct_fork_package_B=stored(side,[1]*sum(r["payments"] for r in side))),
                paced_12_actual_admission_times=dict(interval_s=paced["offered_period_s"],observed_empty_blocks=paced["empty_blocks"],
                    delayed_three_projection=schedule(periodic,3,widths_wall[2]),delayed_four_projection=schedule(periodic,4,widths_wall[3])),
                model_year_s=YEAR,scenarios=results)


if __name__=="__main__":
    print(json.dumps(run(),indent=2,sort_keys=True))
