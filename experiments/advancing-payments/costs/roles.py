"""Derive application byte counts, work and scenario costs from a public APV2 campaign."""
import argparse
import hashlib
import json
from pathlib import Path
from statistics import mean, median

YEAR = 365 * 86400
OFFERED = 100_000_000
CT = 1792
BLOCK_PREFIX = 152
PAGE = 192 * 1024  # run.pages; complete records, smaller than the wallet's 256 KiB ceiling
MIXES = {"low": ((.85, .10, .04, .01), 1), "busy": ((.05, .10, .15, .70), 1/9)}


def need(condition, label):
    if not condition:
        raise ValueError(label)


def read(path):
    return json.loads(path.read_bytes())


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pages(size, stride):
    need(size % stride == 0, "record-aligned wallet pages")
    page_payload = (PAGE // stride) * stride
    return size + 4 * ((size + page_payload - 1) // page_payload + 1)


def pay_io(leaves, singleton):
    # P+selector:u16+132B header, public leaves, binary PQ address, result.
    return dict(to_wallet=4+135+pages(leaves,32)+4+1601, from_wallet=4+singleton)


def measurement(items):
    def collect(field):
        x=[r[field] for r in items]
        return dict(min=min(x), mean=mean(x), median=median(x), max=max(x))
    need(items, "at least one timing")
    return dict(n=len(items), wall_s=collect("elapsed_s"), cpu_s=collect("cpu_s"),
                peak_rss_kib=max(r["peak_rss_kib"] for r in items))


def op_meters(roles, name, operation):
    return [m for role,data in roles.items() if name(role)
            for m in data["meters"] if m["operation"]==operation]


def sizes_and_trace(directory, trace):
    size={}
    def packet(pid):
        raw=(directory/"packets"/(pid+".bin")).read_bytes()
        need(sha(raw)==pid and raw.startswith(b"APV2"), "registered packet identity")
        n=raw[4]
        proof=int.from_bytes(raw[5:9], "little")
        need(n in range(1,5) and len(raw)==9+proof+2*n*CT, "complete packet envelope")
        if n in size:
            need(size[n]==len(raw), "variable packet length within occupancy")
        size[n]=len(raw)
        return raw
    for pid in set(trace["submissions"].values()):
        need(packet(pid)[4]==1, "wallet exports a singleton")
    block_width={}
    for ident,b in trace["blocks"].items():
        p=packet(b["packet"]) if b["packet"] else b""
        prefix=bytes.fromhex(b["prefix"])
        need(len(prefix)==BLOCK_PREFIX and prefix[:8]==b"APBLOCK1" and
             int.from_bytes(prefix[-4:], "little")==len(p), "block prefix")
        raw=prefix+p
        need(sha(raw)==ident and len(raw)==b["size"], "complete serialized block")
        block_width[ident]=p[4] if p else 0
    need(set(size)==set(range(1,5)), "all measured widths")
    peer_order=[]
    for e in trace["events"]:
        keys=[e["block"]] if e["op"]=="extend" else e.get("blocks",[]) if e["op"]=="switch" else []
        peer_order.extend(block_width[k] for k in keys if block_width[k])
    return size, peer_order


def model(name, share, sizes, wallet, verify, builders):
    mix, empty_ratio=MIXES[name]
    included=OFFERED*share
    width=sum(k*mix[k-1] for k in range(1,5))
    paid=included/width
    empties=paid*empty_ratio
    total_blocks=paid+empties
    packet_bytes=sum(sizes[k]*mix[k-1] for k in range(1,5))*paid
    body=packet_bytes+BLOCK_PREFIX*total_blocks
    relay=body+4*total_blocks
    verification=paid*sum(mix[k-1]*verify[k]["cpu_s"]["mean"] for k in range(1,5))
    builder_cpu=paid*sum(mix[k-1]*builders[k]["cpu_s"]["mean"] for k in range(2,5))
    builder_wall=paid*sum(mix[k-1]*builders[k]["wall_s"]["mean"] for k in range(2,5))
    # Hypothetical serial builder, fixed empirical means. Even singleton slots must reach the producer.
    equivalent_rate = included / builder_wall
    base_rate = included / YEAR
    backlog = max(0.0, 600 * (10 * base_rate - equivalent_rate))
    drain = backlog / (equivalent_rate-base_rate) if equivalent_rate > base_rate else None
    # Each selected offer is verified by queue inspection; final block proof is reverified at admission.
    intake=included*verify[1]["cpu_s"]["mean"]
    upload=OFFERED*(4+sizes[1])
    scan_rows=int(2*included)*(32+CT)
    scan_nfs=int(2*included)*32
    leaf_B=(96+int(2*included))*32
    return dict(mix=name,inclusion=share,offered=OFFERED,included=int(included),mean_width=width,
        expected_paid_blocks=paid,expected_empty_blocks=empties,expected_blocks=total_blocks,
        mean_seconds_per_block=YEAR/total_blocks,uniform_eight_block_seconds=8*YEAR/total_blocks,
        wallet_to_ingress_bytes=upload,ingress_ack_bytes=32*OFFERED,
        submission_bytes_one_egress_per_extra_preinclusion_forward=upload,
        wallet_one_ack_per_offer_Mbps=32*OFFERED*8/YEAR/1e6,
        wallet_submission_application_Mbps=8*upload/YEAR/1e6,peer_one_edge_Mbps=8*relay/YEAR/1e6,
        one_full_upload_retry_per_missing_offer_extra_B=(OFFERED-included)*(4+sizes[1]),
        one_full_upload_retry_per_offer_extra_B=upload,
        complete_canonical_block_bytes=body,proof_and_receipt_packet_bytes=packet_bytes,genesis_once_B=3084,
        peer_one_copy_stream_bytes=relay,per_extra_peer_egress_bytes=relay,
        one_archive_max_offers_per_year={str(tb):tb*1e12/(body/OFFERED) for tb in [1,5]},
        days_to_archive_TB={str(tb):365*tb*1e12/body for tb in [1,5]},
        average_archive_B_per_included=body/included,
        verifier_cpu_s_per_s=verification/YEAR,selected_queue_verifier_cpu_s_per_s=intake/YEAR,
        builder_cpu_s_per_s=builder_cpu/YEAR,serial_builder_service_s_per_s=builder_wall/YEAR,
        extra_verifier_cpu_s_per_s_if_excluded_offers_checked_once=(OFFERED-included)*verify[1]["cpu_s"]["mean"]/YEAR,
        single_serial_builder_equivalent_payments_per_s=equivalent_rate,
        ten_x_600s_builder_only_burst=dict(base_included_per_s=base_rate,backlog_payment_equivalents=backlog,
                                         post_burst_drain_s_if_capacity_exceeds_base=drain),
        dedicated_builder_wall_s_per_s={k:paid*mix[k-1]*builders[k]["wall_s"]["mean"]/YEAR for k in range(2,5)},
        wallet_prover_cpu_s_per_s=OFFERED*wallet["cpu_s"]["mean"]/YEAR,
        warm_wallet_equivalent_serial_workers=OFFERED*wallet["wall_s"]["mean"]/YEAR,
        wallet_preparation_to_anchor_window_ratio=wallet["wall_s"]["median"]/(8*YEAR/total_blocks),
        real_indexes_minimum_new_payload_B=128*included,
        raw_header_and_id_minimum_new_payload_B=164*total_blocks,
        approximate_9_selected_bodies_B=9*body/total_blocks,
        fresh_wallet_end_year_framed_scan_input_B=5+pages(scan_rows,32+CT)+pages(scan_nfs,32),
        fresh_wallet_end_year_framed_pay_input_B=pay_io(leaf_B,sizes[1])["to_wallet"],
        fresh_wallet_end_year_all_commitments_B=leaf_B,one_year_common_receipt_rows_B=scan_rows,
        one_year_common_nfs_B=scan_nfs,complete_genesis_and_archive_recovery_B=3084+body)


def storage_summary(path):
    if path is None:
        return None
    report=read(path)
    result={}
    for name in ("archive","pruned"):
        a,b=report[name]["before"],report[name]["after"]
        need(a["material_sha256"]==b["material_sha256"] and a["rows"]==b["rows"],"compaction identity")
        result[name]=dict(file_B=a["file_B"],allocated_B=a["allocated_filesystem_B"],active_page_B=a["live_page_B"],
            freelist_B=a["freelist_B"],compacted_file_B=b["file_B"],compacted_allocated_B=b["allocated_filesystem_B"],
            copy_wall_s=report[name]["copy_compaction_wall_s"],rows=b["rows"],body_B=b["body_B"])
    return result


def direct_summary(path, singleton):
    if path is None:
        return None
    d=read(path)
    rows=d["payments"]
    need(len(rows)==4,"independent direct intents")
    ages=[x["height"]-x["anchor_height"] for x in rows]
    size=4*(BLOCK_PREFIX+4+singleton)+d["empty_blocks"]*(BLOCK_PREFIX+4)
    need(size==d["full_block_stream_B"] and all(2<=age<=8 for age in ages),"direct block clock")
    return dict(period_s=d["offered_period_s"],block_period_s=d["block_period_s"],anchor_age_blocks=ages,
        creation_s=[x["creation_s"] for x in rows],offer_to_commit_s=[x["inclusion_from_offer_s"] for x in rows],
        ready_to_commit_s=[x["inclusion_from_ready_s"] for x in rows],bound_s=d["full_intent_bound_s"],
        empty_blocks=d["empty_blocks"],full_block_stream_B=size,offered_payments_s=d["nominal_offered_payments_s"],
        extra_intake_B=sum(t["out_bytes"] for x in rows for t in x["attempts"])-(4+singleton)*len(rows),
        acknowledgements_B=sum(t["ack_bytes"] for x in rows for t in x["attempts"]))


def clock_summary(path, singleton, four):
    if path is None:
        return None
    c=read(path)
    need(c["packet_B"]==four and c["pool_input_B"]==4*(4+singleton),"clocked aggregate bytes")
    return dict(result=c["result"],ready_s=c["ready_s"],prospective_height=c["prospective_height"],
        block_period_s=c["block_period_s"],ticks=len(c["ticks"]),ticks_peak_lateness_s=c["peak_tick_lateness_s"],
        four_wallet_upload_B=c["pool_input_B"],packet_B=c["packet_B"],builder=c["builder"]["meters"])


def calculate(directory, replay=None, storage=None, direct=None, clock=None):
    result=read(directory/"RESULT.json")
    trace=read(directory/"TRACE.json")
    size,peer_order=sizes_and_trace(directory,trace)
    roles=result["roles"]
    wallets=lambda s:s.startswith("wallet") or s.startswith("restore")
    wallet=measurement(op_meters(roles,wallets,"wallet_prove"))
    meters=op_meters(roles,lambda s:s=="peer_verify","public_verify")
    need(len(meters)==len(peer_order), "one independent peer verification per selected nonempty event")
    verify={k:measurement([m for width,m in zip(peer_order,meters) if width==k]) for k in range(1,5)}
    builders={k:measurement(op_meters(roles,lambda s:s.startswith("builder"+str(k)),"builder_aggregate")) for k in range(2,5)}
    setup={}
    for key,role,op in [
        ("wallet",wallets,"wallet_setup"),("restored_wallet",lambda s:s.startswith("restore"),"wallet_setup"),
        ("public_verifier",lambda s:s in ("verifier","peer_verify"),"verifier_setup"),
        *((f"builder{k}",lambda s,k=k:s.startswith(f"builder{k}"),"builder_setup") for k in range(2,5))]:
        setup[key]=measurement(op_meters(roles,role,op))
    scan=measurement(op_meters(roles,wallets,"wallet_scan"))
    ops={x["label"]:x for x in result["opportunities"]}
    widths={}
    for k in range(1,5):
        selected=[x for x in ops.values() if x["count"]==k]
        for x in selected:
            need(x["wallet_packet_B"]==[size[1]]*k and
                 x["block_B"]==BLOCK_PREFIX+size[k] and x["packet_B"]==size[k],"opportunity bytes")
        widths[k]=dict(packet=size[k],proof=size[k]-9-2*k*CT,ciphertexts=2*k*CT,
                       preinclusion=k*(size[1]+4),acks=32*k,block=BLOCK_PREFIX+size[k],relay=156+size[k],
                       builder_input_pipe_B=k*(size[1]+4) if k>1 else 0,
                       builder_output_pipe_B=4+size[k] if k>1 else 0,
                       receiver_verifier=verify[k],outer_builder=builders.get(k),
                       producer_state_apply_wall_s_mean=mean(x["state_admission_s"] for x in selected),
                       verifier_input_pipe_B=4+size[k],verifier_output_pipe_B=5+k*(172+2*CT),
                       producer_queue_to_commit_wall_s=[x["oldest_accepted_to_commit_s"] for x in selected])
    for r in result["relay"]:
        need(r["block_B"] in [BLOCK_PREFIX]+[w["block"] for w in widths.values()] and
             r["full_stream_B"]==r["block_B"]+4,"actual block relay encoding")
    rec=result["recovery"]
    recovery=dict(**rec,genesis_plus_full_archive_B=rec["genesis_B"]+rec["complete_archived_blocks_B"],
        s_to_wallet=5+pages(rec["common_receipt_rows_B"],32+CT)+pages(rec["common_nfs_B"],32),
        s_from_wallet=8,scan=scan,
        successor_P=pay_io(rec["local_membership_leaf_payload_B"],size[1]))
    restore=roles["restore0"]
    need(recovery["s_to_wallet"]+recovery["successor_P"]["to_wallet"]+4==restore["to_role_B"],
         "scan, spend and exit exactly account for private receiving process input")
    need(4+1601+4+8+recovery["successor_P"]["from_wallet"]==restore["from_role_B"],
         "address, empty endowment, scan and spend account for receiving process output")
    all_upload=sum(t["out_bytes"] for x in result["uploads"] for t in x["attempts"])
    all_ack=sum(t["ack_bytes"] for x in result["uploads"] for t in x["attempts"])
    retry={x["label"]:x["attempts"] for x in result["uploads"] if x["label"] in ("builder-offline","duplicate-delivery")}
    need(len(retry)==2,"captured outage and duplicate retransmission")
    relay_wall={k:mean(r["receive_validate_wall_s"] for r in result["relay"] if r["block_B"]==BLOCK_PREFIX+size.get(k,0)) for k in range(5)}
    need(trace["events"][-1]["state"]==result["final"], "selected terminal state")
    # The first successful replacement relays two real frames in campaign.py; the later
    # suffix reselection reuses locally retained blocks without another socket call.
    switches=[e for e in trace["events"] if e["op"]=="switch"]
    need(len(switches)==3 and len(switches[0]["blocks"])==2, "branch relay samples")
    branch_relay=sum(4+trace["blocks"][key]["size"] for key in switches[0]["blocks"])
    extension_relay=sum(x["full_stream_B"] for x in result["relay"])
    upload_fallback=retry["builder-offline"]
    upload_duplicate=retry["duplicate-delivery"]
    expected_attempts=[(0,0,False),(size[1]+4,32,True)]
    for attempts in (upload_fallback,upload_duplicate):
        need([(a["out_bytes"],a["ack_bytes"],a["accepted"]) for a in attempts]==expected_attempts,
             "outage and complete direct retry bytes")
    return dict(input_sha256={k:sha((directory/k).read_bytes()) for k in ["RESULT.json","TRACE.json"]},
        widths=widths,wallet_warm=wallet,setup=setup,recovery=recovery,receiver_stream_plus_admission_wall_s_mean=relay_wall,
        producer_opportunities=ops,busy=result["busy"],concurrent=result["concurrent"],
        observed_upload_total_B=all_upload,observed_ack_total_B=all_ack,observed_retry=retry,
        wallet_create_public_startup_pipe_B=4+1601+4+24*32,wallet_restore_public_startup_pipe_B=4+1601+4,
        observed_extension_relay_application_B=extension_relay,observed_branch_switch_relay_application_B=branch_relay,
        observed_total_peer_relay_application_B=branch_relay+extension_relay,
        finite_busy=dict(reported_rounds=len(result["busy"]["rounds"]),last_completion_s=result["busy"]["rounds"][-1]["completed_s"],
                         required_offered_s=OFFERED/YEAR,prepared_origin_rate_s=result["busy"]["offered_per_second"],
                         offered_fraction_of_target=result["busy"]["offered_per_second"]/(OFFERED/YEAR),
                         observed_completion_rate=result["busy"]["synchronized_prepared_payments"]/result["busy"]["rounds"][-1]["completed_s"]),
        common_historical_P_stage_B=[dict(label=q["label"],**pay_io(q["downloaded_leaf_payload_B"],q["packet_B"])) for q in result["wallet_preparation"]],
        branch_disk={k:result[k] for k in ["archive","pruned","final"]},
        public_replay=read(replay) if replay else None,
        direct_clock=direct_summary(direct,size[1]),batch_clock=clock_summary(clock,size[1],size[4]),
        physical_storage=storage_summary(storage),
        scenarios=[model(name,share,size,wallet,verify,builders) for name in MIXES for share in [.95,1]],
        direct_singleton_batch_four=dict(blocks_B=4*(152+size[1]),relayed_B=4*(156+size[1]),
                                       one_full_block_B=152+size[4],one_full_relay_B=156+size[4]))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory",type=Path,help="public author or independent campaign directory")
    parser.add_argument("--replay",type=Path,help="archival/pruned public replay output (optional)")
    parser.add_argument("--storage",type=Path,help="physical and compacted database evidence")
    parser.add_argument("--direct",type=Path,help="separate live direct-clock sample")
    parser.add_argument("--clock",type=Path,help="separate live width-four clock outcome")
    a=parser.parse_args()
    print(json.dumps(calculate(a.directory,a.replay,a.storage,a.direct,a.clock),sort_keys=True,indent=2,allow_nan=False))


if __name__=="__main__":
    main()
