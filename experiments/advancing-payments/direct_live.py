"""Timed single-origin, direct-to-producer service with independently clocked advancing local blocks."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import resource
import signal
import tempfile
import time
import sqlite3
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from wire import need, sha, split_block, u32
from run import Resources, Records, payment, put, save, snapshot
from state import Ledger
from ingress import Endpoint, admit_queue, create_pool, upload

# Hardware scenario declared before these runs. One fee-paying user, four real online intents.
ARRIVALS=(0.,12.,24.,36.)
BLOCK_PERIOD=2.
WALL_BOUND=22.


def live(a,res):
    a.work.mkdir(parents=True,exist_ok=False)
    a.evidence.mkdir(parents=True,exist_ok=False)
    records=Records(a.evidence)
    history=[]
    metrics=[]
    with tempfile.TemporaryDirectory(dir="/dev/shm") as private,tempfile.TemporaryDirectory() as local:
        def wallet(name):
            p=Path(private)/name;p.mkdir(mode=0o700)
            w=res.role(name,["wallet","/keys","/private/seed","create"],p)
            return w,w.get(),w.get()
        sender,_,notes=wallet("direct_sender")
        receiver,dest,unused=wallet("direct_recipient")
        # Recipient's 24 separately created notes are not endowed in this test.
        genesis=b"APGEN001"+u32(24)+notes
        origin=sha(genesis)
        put(a.evidence/"genesis.bin",genesis)
        node=Ledger(a.work/"direct.sqlite",res.backend,genesis,origin,True)
        pool=a.work/"pool.sqlite"; create_pool(pool)
        path=Path(local)/"direct"; preferred=Path(local)/"offline"
        unavailable=Endpoint(preferred,pool,False);unavailable.stop()
        serving=Endpoint(path,pool,True)
        tap=sqlite3.connect(pool)
        try:
            # Creator and validating node run simultaneously. The local block opportunity clock is open-loop.
            start=time.monotonic()
            submitted = {}
            included = {}
            with ThreadPoolExecutor(max_workers=1) as worker:
                job = None
                next_send = 0
                tick = 0
                while len(included) < len(ARRIVALS) or job is not None:
                    now = time.monotonic() - start
                    need(now < ARRIVALS[-1] + WALL_BOUND + 8, "direct live completion")
                    if job is not None and job.done():
                        k, raw, start_h, create_s, sent_at, attempts = job.result()
                        records.submission("live"+str(k), raw)
                        submitted[sha(raw)] = dict(payer=0, k=k, anchor_height=start_h, creation_s=create_s,
                                                   offered_s=ARRIVALS[k], uploaded_s=sent_at, attempts=attempts)
                        job = None
                    if job is None and next_send < len(ARRIVALS) and now >= ARRIVALS[next_send]:
                        k = next_send
                        selected = node.head()
                        leaves = node.leaves()
                        def make(k=k, h=selected["h"], header=selected["header"], leaves=leaves):
                            begin = time.monotonic()
                            raw = payment(sender, k, header, leaves, dest)
                            built = time.monotonic() - begin
                            attempts = upload([preferred, path], raw)
                            return k, raw, h, built, time.monotonic()-start, attempts
                        job = worker.submit(make)
                        next_send += 1
                    if now < (tick+1)*BLOCK_PERIOD:
                        time.sleep(.004)
                        continue
                    tick += 1
                    if tap.execute("SELECT count(*) FROM pool").fetchone()[0]:
                        block, cost = admit_queue(pool, node, {}, tick)
                        need(cost["count"] == 1, "direct singleton")
                        packet_id = sha(split_block(block)[2])
                        need(packet_id not in included, "duplicate inclusion")
                        included[packet_id] = dict(included_s=time.monotonic()-start, height=node.head()["h"],
                                                   block_B=len(block), packet_B=cost["packet_B"])
                    else:
                        block = node.produce(b"",tick)
                    history.append(records.block(block))
                    metrics.append((time.monotonic()-start)-tick*BLOCK_PERIOD)
            need(submitted.keys() == included.keys() and len(submitted) == len(ARRIVALS), "offered and admitted identities")
            need(tap.execute("SELECT count(*) FROM pool").fetchone()[0] == 0, "direct queue drained")
            reports = []
            for packet_id, sample in sorted(submitted.items(), key=lambda item:item[1]["k"]):
                sample.update(included[packet_id])
                sample["inclusion_from_offer_s"] = sample["included_s"] - sample["offered_s"]
                sample["inclusion_from_ready_s"] = sample["included_s"] - sample["uploaded_s"]
                need([r["accepted"] for r in sample["attempts"]] == [False,True], "direct independent endpoint")
                need(2 <= sample["height"]-sample["anchor_height"] <= 8, "chain advanced during each direct transfer")
                need(sample["inclusion_from_offer_s"] <= WALL_BOUND, "observed full-intent latency")
                reports.append(sample)
            final=snapshot(node)
            for name in list(res.roles):res.finish(name)
            result=dict(profile_sha256=a.profile_sha,genesis_sha256=origin,offered_period_s=12,block_period_s=BLOCK_PERIOD,
                        nominal_offered_payments_s=1/12,arrival_horizon_s=48,payments=reports,full_intent_bound_s=WALL_BOUND,
                        total_elapsed_s=time.monotonic()-start,last_confirmation_s=reports[-1]["included_s"],
                        empty_blocks=len(history)-4,full_block_stream_B=sum(records.blocks[h]["size"]+4 for h in history),
                        block_finish_lateness_s=metrics,max_block_finish_lateness_s=max(metrics),final=final,roles=res.finished)
            save(a.evidence/"DIRECT.json",result)
            save(a.evidence/"TRACE.json",dict(genesis_sha256=origin,profile_sha256=a.profile_sha,blocks=records.blocks,order=history,final=final))
            return result
        finally:
            serving.stop();node.close();tap.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for flag in ["binary","keys","work","evidence"]:parser.add_argument("--"+flag,type=Path,required=True)
    for flag in ["binary-sha","profile-sha"]:parser.add_argument("--"+flag,required=True)
    a=parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    signal.alarm(240)
    res=Resources(a)
    try: print(json.dumps(live(a,res),indent=2))
    finally:res.close()


if __name__=="__main__":
    main()
