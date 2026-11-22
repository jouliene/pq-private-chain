"""Two-core admission trace. Independent checker and fixture construction run elsewhere."""
import argparse
import bisect
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import resource
import sqlite3
import subprocess
import sys
from threading import Condition, Thread
import time
from packets import need
from ledger import Ledger

YEAR = 365.25 * 86400
MODES = {"10M":1e7/YEAR,"30M":3e7/YEAR,"100M":1e8/YEAR,"8ops":8.0,"12ops":12.0,"16ops":16.0,"overload":20.0,"catchup":None}

def two_cores():
    found={}
    for cpu in sorted(os.sched_getaffinity(0)):
        topo=Path(f"/sys/devices/system/cpu/cpu{cpu}/topology")
        key=tuple((topo/f).read_text().strip() for f in ("physical_package_id","core_id"))
        found.setdefault(key,cpu)
    need(len(found)>=2,"need two distinct physical cores")
    return list(found.values())[:2]

def cpu():
    t=os.times()
    return t.user+t.system+t.children_user+t.children_system

def worker(public,path,mode):
    cpus=two_cores()
    os.sched_setaffinity(0,cpus)
    need(not path.exists(),"each load requires a new ledger")
    pin=bytes.fromhex((public/"genesis.sha256").read_text().strip())
    n=len(list(public.glob("op-*.bin")))
    rate=MODES[mode]
    init_start,init_cpu=time.monotonic(),cpu()
    db=Ledger(path,public,pin)
    init_wall=time.monotonic()-init_start
    genesis_cpu=cpu()-init_cpu
    start,c0=time.monotonic(),cpu()
    # Frames are read and decoded in the measured role. Requests arrive on a fixed
    # open-loop schedule even when both workers are busy. No verification verdict cache.
    due=[i/rate if rate else 0.0 for i in range(n)]
    arrivals, sizes, done, service = [], [], [], []
    incoming, checking = deque(), deque()
    condition = Condition()
    failures=[]
    stopping=False
    def receive():
        try:
            for i,t in enumerate(due,1):
                delay=t-(time.monotonic()-start)
                if delay>0:
                    time.sleep(delay)
                with (public/f"op-{i:02}.bin").open("rb") as src:
                    payload=src.read(524309)
                with condition:
                    if not rate:
                        condition.wait_for(lambda: len(incoming)<8 or stopping)
                    if stopping:
                        return
                    arrivals.append(time.monotonic()-start)
                    sizes.append(len(payload))
                    incoming.append(payload)
                    condition.notify_all()
        except BaseException as ex:
            with condition:
                failures.append(ex)
                condition.notify_all()
    def notify(_):
        with condition:
            condition.notify_all()
    def timed_verify(verify):
        begin=time.monotonic()
        apply=verify()
        return apply,time.monotonic()-begin
    def commit_first():
        future,count=checking.popleft()
        apply,proof_wall=future.result()
        t=time.monotonic()
        with db.transaction():
            apply()
        service.append([count,round(proof_wall,6),round(time.monotonic()-t,6)])
        done.append(time.monotonic()-start)
    ingress=Thread(target=receive,daemon=True)
    ingress.start()
    legs_checked=swap_count=0
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            while len(done)<n:
                with condition:
                    condition.wait_for(lambda: failures or (incoming and len(checking)<2)
                                       or (checking and checking[0][0].done()))
                    if failures:
                        raise failures[0]
                    wire=incoming[0] if incoming and len(checking)<2 else None
                if wire is not None:
                    try:
                        count,verify=db.prepare(wire)
                    except ValueError as ex:
                        if checking and str(ex)=="ineligible branch anchor":
                            commit_first()
                            continue
                        raise
                    job=pool.submit(timed_verify,verify)
                    checking.append((job,count))
                    job.add_done_callback(notify)
                    legs_checked+=count
                    swap_count+=count==2
                    with condition:
                        incoming.popleft()
                        condition.notify_all()
                else:
                    commit_first()
    finally:
        with condition:
            stopping=True
            condition.notify_all()
    ingress.join()
    bytes_in=sum(sizes)
    wall=done[-1]
    elapsed_cpu=cpu()-c0
    tip=db.tip()
    need(tip[0]==n and tip[4]==n and swap_count*10==n,"admission accounting")
    # Every earlier transaction has already synchronously committed to WAL. Closing
    # also accounts for checkpointing the final WAL back into the main database.
    db.close()
    closed=time.monotonic()-start
    total_cpu=cpu()-c0
    backlog=[i+1-bisect.bisect_right(done,t) for i,t in enumerate(arrivals)]
    model=next((v.split(":",1)[1].strip() for v in Path("/proc/cpuinfo").read_text().splitlines()
                if v.startswith("model name")),"unknown")
    return dict(mode=mode,physical_cpu_ids=cpus,cpu_model=model,sqlite=sqlite3.sqlite_version,
        operations=n,distinct_legs=legs_checked,swaps=swap_count,
        bytes_read=bytes_in,final_height=tip[0],final_root=tip[2].hex(),fees=tip[4],
        funding_s=init_wall,funding_cpu_s=genesis_cpu,commit_wall_s=wall,
        wall_including_close_s=closed,cpu_s=elapsed_cpu,cpu_including_close_s=total_cpu,
        cpu_per_leg_s=elapsed_cpu/legs_checked,cpu_per_op_s=elapsed_cpu/n,
        cpu_cores=elapsed_cpu/wall,op_per_s=n/wall,offered_op_s=rate,
        peak_outstanding=max(backlog),outstanding_at_last_offer=backlog[-1],
        drain_s=wall-arrivals[-1],max_arrival_to_commit_s=max(t-a for t,a in zip(done,arrivals)),
        max_offer_lateness_s=max(t-a for t,a in zip(arrivals,due)) if rate else None,
        arrival_s=[round(t,6) for t in arrivals],
        db_closed_bytes=path.stat().st_size,peak_self_KiB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        commit_s=[round(v,6) for v in done],leg_count_verify_wall_commit_wall=service)

def tree_rss(pid):
    # Sample parent and its currently live Node signature helpers. Summed RSS may
    # count shared pages twice. psutil/sampler is not in the admission process.
    try:
        import psutil
        p=psutil.Process(pid)
        children=p.children(recursive=True)
        val=p.memory_info().rss
        for c in children:
            try:
                val+=c.memory_info().rss
            except psutil.NoSuchProcess:
                pass
        return val//1024
    except psutil.NoSuchProcess:
        return 0

def main():
    a=argparse.ArgumentParser()
    a.add_argument("public",type=Path);a.add_argument("work",type=Path)
    a.add_argument("--worker",choices=MODES)
    a.add_argument("--catchup-passes",type=int,default=1,choices=range(1,17))
    a.add_argument("--modes",nargs="+",choices=MODES,default=list(MODES))
    opt=a.parse_args()
    if opt.worker:
        print(json.dumps(worker(opt.public,opt.work,opt.worker)))
        return
    opt.work.mkdir()
    results=[]
    replays=[]
    modes=list(opt.modes)
    if "catchup" in modes:
        modes.extend(["catchup"]*(opt.catchup_passes-1))
    for mode in modes:
        label=mode if mode!="catchup" or not replays else f"catchup-{len(replays)+1:02}"
        cmd=[sys.executable,"-B",__file__,opt.public,opt.work/(label+".sqlite"),"--worker",mode]
        receipt=opt.work/(label+".json")
        with receipt.open("wb") as dst:
            p=subprocess.Popen(cmd,stdout=dst)
            peak=0
            while p.poll() is None:
                peak=max(peak,tree_rss(p.pid))
                time.sleep(.02)
        need(p.returncode==0,"admission worker failed")
        r=json.loads(receipt.read_text());r["sampled_process_tree_peak_KiB"]=peak
        if mode != "catchup" or not replays:
            results.append(r)
        if mode == "catchup":
            replays.append({k:r[k] for k in ("operations","funding_s","wall_including_close_s",
                "funding_cpu_s","cpu_including_close_s","bytes_read","final_root","sampled_process_tree_peak_KiB")})
        print(f"{label}: {r['op_per_s']:.3f} operations/s, {r['cpu_per_leg_s']:.3f} CPU-s/leg, peak outstanding {r['peak_outstanding']}",flush=True)
    if replays:
        need(len({r["final_root"] for r in replays})==1,"historical replay disagreement")
        (opt.work/"catchup_series.json").write_text(json.dumps(replays,indent=2)+"\n")
    (opt.work/"traces.json").write_text(json.dumps(results,indent=2)+"\n")
if __name__=="__main__":
    main()
