"""Exercise outage with acknowledged preferred traffic ahead of a newly direct payer."""
import argparse
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import time
import signal

HERE=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(HERE))
from ingress import Endpoint, admit_queue, create_pool, upload
from run import Resources, snapshot
from state import Ledger
from wire import need, sha, split_block


def run(a):
    trace=json.loads((a.main/"TRACE.json").read_bytes())
    genesis=(a.main/"genesis.bin").read_bytes()
    need(trace["profile_sha256"]==a.profile_sha and trace["genesis_sha256"]==sha(genesis)==a.genesis_sha,
         "approved failover capture")
    packets=[]
    for i in range(3):
        pid=trace["submissions"]["waiting"+str(i)]
        packet=(a.main/"packets"/(pid+".bin")).read_bytes()
        need(sha(packet)==pid,"wallet submission identity")
        packets.append(packet)
    res=Resources(a)
    try:
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            pool=root/"pool.sqlite"
            create_pool(pool)
            ordinary=Endpoint(root/"preferred",pool,False)
            direct=Endpoint(root/"direct",pool,True)
            node=Ledger(root/"node.sqlite",res.backend,genesis,a.genesis_sha,True)
            try:
                deliveries=[upload([root/"preferred"],p) for p in packets[:2]]
                ordinary.stop()
                deliveries.append(upload([root/"preferred",root/"direct"],packets[2]))
                db=sqlite3.connect(pool)
                try:
                    need([r[0] for r in db.execute("SELECT direct FROM pool ORDER BY seq")]==[0,0,1],
                         "mixed waiting queue on outage")
                    builders = {}
                    interrupted = None
                    if a.worker != "absent":
                        worker = res.role("queue_builder",["builder","/keys","2"])
                        need(worker.get()==b"READY", "healthy registered builder startup")
                        builders[2] = worker
                        if a.worker == "exited":
                            worker.proc.kill()
                            worker.proc.wait(10)
                        elif a.worker == "disconnect":
                            sent_B = sum(4+len(p) for p in packets[:2])
                            def interrupt_after_input():
                                deadline = time.monotonic()+5
                                while worker.sizes[0] < sent_B and time.monotonic() < deadline:
                                    time.sleep(.002)
                                if worker.sizes[0] >= sent_B:
                                    worker.proc.kill()
                            interrupted = threading.Thread(target=interrupt_after_input)
                            interrupted.start()
                    events=[]
                    consumed=0
                    while consumed < len(packets):
                        block,stats=admit_queue(pool,node,builders,len(events)+1)
                        included = split_block(block)[2]
                        width = 2 if a.worker=="healthy" and consumed==0 else 1
                        offered = packets[consumed:consumed+width]
                        need(stats["count"]==width, "actual service width")
                        need(res.backend.verify(included)==[res.backend.verify(p)[0] for p in offered],
                             "complete eligible wallet effects in FIFO order")
                        if consumed==0 and a.worker!="healthy":
                            need(stats.get("fallback")=={"absent":"registered builder unavailable",
                                 "exited":"builder exited","disconnect":"builder transport disconnected"}[a.worker],
                                 "expected worker failure")
                        consumed+=width
                        remaining=db.execute("SELECT count(*) FROM pool").fetchone()[0]
                        need(remaining==3-consumed,"pending offers preserved")
                        events.append(dict(block_sha256=sha(block),packet_sha256=sha(included),remaining=remaining,
                                           width=width,fallback=stats.get("fallback"),height=node.head()["h"]))
                    if interrupted is not None:
                        interrupted.join(5)
                        need(not interrupted.is_alive(),"completed fault injector")
                    end=snapshot(node)
                    need(end["fees"]==9 and end["spent"]==6,"three economic effects")
                    return dict(profile_sha256=a.profile_sha,genesis_sha256=a.genesis_sha,deliveries=deliveries,
                                queued_before_outage=2,worker_scenario=a.worker,events=events,final=end)
                finally:db.close()
            finally:ordinary.stop();direct.stop();node.close()
    finally:res.close()


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ["main","binary","keys"]:
        p.add_argument("--"+name,type=Path,required=True)
    for name in ["profile-sha","binary-sha","genesis-sha"]:
        p.add_argument("--"+name,required=True)
    p.add_argument("--worker",default="absent",choices=["absent","exited","disconnect","healthy"])
    signal.alarm(150)
    print(json.dumps(run(p.parse_args()),indent=2,sort_keys=True))
