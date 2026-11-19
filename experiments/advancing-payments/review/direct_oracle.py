"""Replay the separately clocked direct-service public capture and verify its latency arithmetic."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
sys.path.insert(0,str(HERE.parent))
from public_chain import check, proof_public
from run import Resources
from state import Ledger


def verify(args):
    capture = json.loads((args.campaign/"TRACE.json").read_bytes())
    bill = json.loads((args.campaign/"DIRECT.json").read_bytes())
    genesis = (args.campaign/"genesis.bin").read_bytes()
    assert capture["genesis_sha256"] == bill["genesis_sha256"] == args.genesis_sha
    assert capture["profile_sha256"] == bill["profile_sha256"] == args.profile_sha
    blocks,indices = [],[]
    for height,ref in enumerate(capture["order"],1):
        item = capture["blocks"][ref]
        pid = item["packet"]
        payload = b"" if pid is None else (args.campaign/"packets"/(pid+".bin")).read_bytes()
        assert pid is None or hashlib.sha256(payload).hexdigest()==pid
        raw = bytes.fromhex(item["prefix"])+payload
        assert len(raw)==item["size"] and hashlib.sha256(raw).hexdigest()==ref
        if payload:
            (slot,) = proof_public(payload)
            indices.append((height,slot[1],len(raw),len(payload)))
        blocks.append(raw)
    assert len(indices)==len(bill["payments"])==args.expected
    measurements = []
    for i,(actual,rec) in enumerate(zip(indices,bill["payments"],strict=True)):
        h,anchor,size,packet_size = actual
        assert (rec["height"],rec["anchor_height"],rec["block_B"],rec["packet_B"])==actual
        assert 2 <= h-anchor <=8
        assert rec["offered_s"]==i*bill["offered_period_s"]
        assert abs(rec["included_s"]-rec["offered_s"]-rec["inclusion_from_offer_s"])<1e-8
        assert abs(rec["included_s"]-rec["uploaded_s"]-rec["inclusion_from_ready_s"])<1e-8
        assert rec["inclusion_from_offer_s"]<=bill["full_intent_bound_s"]
        assert [r["accepted"] for r in rec["attempts"]]==[False,True]
        assert rec["attempts"][1]["out_bytes"]==packet_size+4 and rec["attempts"][1]["ack_bytes"]==32
        measurements.append(dict(height=h,anchor=anchor,age=h-anchor,elapsed_s=rec["inclusion_from_offer_s"]))
    assert bill["empty_blocks"]==len(blocks)-args.expected
    assert bill["full_block_stream_B"]==sum(4+len(b) for b in blocks)
    late = bill["block_finish_lateness_s"]
    assert len(late)==len(blocks)
    res = Resources(args)
    try:
        node = Ledger(args.database,res.backend,genesis,args.genesis_sha,True,True)
        try:
            for raw in blocks:
                node.accept(raw)
        finally:
            node.close()
        for name in list(res.roles):
            res.finish(name)
    finally:
        res.close()
    state = check(genesis,args.genesis_sha,args.profile_sha,blocks,args.reference,args.database)
    assert state["head_id"]==capture["final"]["id"]==bill["final"]["id"] and state["payments"]==args.expected
    paced = {}
    if args.expected == 12:
        service = bill["paced_service"]
        assert service["offered"] == service["included"] == 12 and service["last_commit_deadline_s"] == 122
        lags = [s["started_s"]-s["offered_s"] for s in bill["payments"]]
        assert all(x>=0 and abs(x-s["scheduling_lag_s"])<1e-8 for s,x in zip(bill["payments"],lags,strict=True))
        assert bill["arrival_horizon_s"]==120 and bill["block_period_s"]==2 and bill["offered_period_s"]==10
        assert abs(max(lags)-service["max_creation_dispatch_lag_s"])<1e-8
        last = bill["payments"][-1]["included_s"]
        assert abs(last-bill["last_confirmation_s"])<1e-8 and service["final_pending"]==0
        passed = max(lags)<2 and last <= 122
        assert service["finite_service_pass"] == passed
        paced = dict(max_dispatch_lag_s=max(lags),last_commit_s=last,final_pending=0,finite_service_pass=passed)
    return dict(measurements=measurements,finite_twelve=paced,late_max_s=max(late),capture_empty_blocks=bill["empty_blocks"],
                capture_complete_one_edge_B=bill["full_block_stream_B"],branch=state,
                binary_sha256=args.binary_sha,genesis_sha256=args.genesis_sha,profile_sha256=args.profile_sha)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for f in ["campaign","database","reference","binary","keys"]:
        p.add_argument("--"+f,type=lambda x:Path(x).resolve(),required=True)
    p.add_argument("--expected",type=int,choices=[4,12],default=4)
    for f in ["genesis-sha","profile-sha","binary-sha"]:
        p.add_argument("--"+f,required=True)
    print(json.dumps(verify(p.parse_args()),indent=2,sort_keys=True))
