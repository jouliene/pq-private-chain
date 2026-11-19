"""Run one warm four-wallet aggregate while an independent two-second block clock advances."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys
import signal
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from run import Resources, reject, save, snapshot
from state import Ledger, WINDOW
from wire import need, packet_width, sha

PERIOD = 2
NAMES = tuple("waiting"+str(n) for n in range(4))


def inputs(args):
    trace = json.loads((args.main/"TRACE.json").read_bytes())
    genesis = (args.main/"genesis.bin").read_bytes()
    need(sha(genesis) == trace["genesis_sha256"] == args.genesis_sha, "authorized clock genesis")
    need(trace["profile_sha256"] == args.profile_sha, "registered profile")
    def fetch(name):
        digest = trace["submissions"][name]
        raw = (args.main/"packets"/(digest+".bin")).read_bytes()
        need(sha(raw) == digest and packet_width(raw) == 1, "public wallet submission")
        return raw
    return genesis, [fetch(n) for n in NAMES], fetch("unrelated")


def check_group(node, group, packet):
    slots = node.backend.verify(packet)
    need(len(slots) == len(group) == 4, "four verified slots")
    need(slots == [node.backend.verify(p)[0] for p in group], "complete wallet effects in order")
    need(all(s.height == 0 for s in slots), "preparation height")
    return slots


def admit(node, packet, nonce):
    next_height = node.head()["h"] + 1
    if next_height > WINDOW:
        reject(node, "clocked expired aggregate", lambda:node.produce(packet,nonce), "anchor expired or future")
        return "expired", node.produce(b"",nonce)
    return "included", node.produce(packet,nonce)


def trial(a, res, node, group, unrelated):
    a.evidence.mkdir(parents=True,exist_ok=False)
    builder = res.role("builder4",["builder","/keys","4"])
    need(builder.get() == b"READY", "registered warm builder")
    for p in group:
        need(node.inspect(p)[0].height == 0, "freshly eligible public inputs")
    ticks = []
    status = None
    with ThreadPoolExecutor(max_workers=1) as pool:
        epoch = time.monotonic()
        job = pool.submit(builder.call,*group)
        raw = None
        ready = None
        while status is None:
            elapsed = time.monotonic()-epoch
            need(elapsed < 180, "bounded clock runtime")
            if raw is None and job.done():
                raw = job.result()
                ready = elapsed
                need(packet_width(raw) == 4, "wallet-only aggregation")
            height = len(ticks)+1
            if elapsed < PERIOD*height:
                time.sleep(.003)
                continue
            if height == 1:
                block = node.produce(unrelated,height)
                kind = "unrelated"
            elif raw is None:
                block = node.produce(b"",height)
                kind = "empty"
            else:
                status, block = admit(node, raw, height)
                kind = "aggregate" if status == "included" else "empty"
            ticks.append(dict(h=height,kind=kind,block_sha256=sha(block),end_s=time.monotonic()-epoch))
    check_group(node,group,raw)
    (a.evidence/"aggregate.bin").write_bytes(raw)
    data = dict(genesis_sha256=a.genesis_sha,profile_sha256=a.profile_sha,block_period_s=PERIOD,
                pool_input_B=sum(4+len(p) for p in group),aggregate_sha256=sha(raw),packet_B=len(raw),
                ready_s=ready,result=status,prospective_height=len(ticks),ticks=ticks,final=snapshot(node),
                peak_tick_lateness_s=max(t["end_s"]-t["h"]*PERIOD for t in ticks),
                builder=res.finish("builder4"))
    save(a.evidence/"CLOCK.json",data)
    return data


def replay(a, node, group, unrelated):
    data = json.loads((a.evidence/"CLOCK.json").read_bytes())
    raw = (a.evidence/"aggregate.bin").read_bytes()
    need(data["genesis_sha256"]==a.genesis_sha and data["profile_sha256"]==a.profile_sha and
         sha(raw)==data["aggregate_sha256"],"clock artifacts")
    check_group(node, group, raw)
    ticks = data["ticks"]
    need(len(ticks)>=2 and len(ticks)==data["prospective_height"],"clock trace length")
    for h,tick in enumerate(ticks,1):
        if h==len(ticks):
            status,block=admit(node,raw,h)
            need(status==data["result"],"clock outcome")
        else:
            block=node.produce(unrelated if h==1 else b"",h)
        need(h==tick["h"] and sha(block)==tick["block_sha256"],"clock block identity")
    need(snapshot(node)==data["final"],"clock end state")
    return dict(result=data["result"],height=len(ticks),aggregate_sha256=sha(raw),final=snapshot(node))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode",choices=["trial","replay"])
    for f in ["main","evidence","binary","keys","work"]:
        p.add_argument("--"+f,required=True,type=Path)
    for f in ["binary-sha","profile-sha","genesis-sha"]:
        p.add_argument("--"+f,required=True)
    a=p.parse_args()
    signal.alarm(300)
    genesis,group,unrelated=inputs(a)
    a.work.mkdir(parents=True,exist_ok=False)
    res=Resources(a)
    try:
        node=Ledger(a.work/"clock.sqlite",res.backend,genesis,a.genesis_sha,True)
        try:
            output=trial(a,res,node,group,unrelated) if a.mode=="trial" else replay(a,node,group,unrelated)
            print(json.dumps(output,sort_keys=True,indent=2))
        finally:node.close()
    finally:res.close()


if __name__=="__main__":
    main()
