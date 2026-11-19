"""Measure a real, accepted singleton separately from ordinary wallet history requests."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
import time


def process_io():
    return {k:int(v) for k,v in (line.split(":") for line in Path("/proc/self/io").read_text().splitlines())
            if k in ("read_bytes","write_bytes")}


def worker(a):
    from chain import Chain
    from runtime import config
    from run import Resources
    resources=Resources(config(a.runtime))
    ledger=Chain(a.db,resources.backend)
    packet=a.packet.read_bytes()
    try:
        resources.backend.verify(a.warmup.read_bytes())
        assert a.packet.read_bytes()!=a.warmup.read_bytes()
        steps=0
        def tick():
            nonlocal steps
            steps+=1
            return 0
        ledger.db.set_progress_handler(tick,1)
        before_io=process_io()
        before_sizes=tuple(resources.v.sizes)
        print("OFFER START",file=sys.stderr,flush=True)
        start=time.monotonic()
        cpu=time.process_time()
        admission=ledger.offer(packet)
        controller_cpu=time.process_time()-cpu
        elapsed=time.monotonic()-start
        print("OFFER END",file=sys.stderr,flush=True)
        elapsed_io=process_io()
        after_sizes=resources.v.sizes
        ledger.db.set_progress_handler(None,0)
        report=ledger.status()
        assert admission==dict(id=hashlib.sha256(packet).hexdigest(),duplicate=False) and report["mempool"]==1
        resources.finish("verifier")
        meters=resources.finished["verifier"]["meters"]
        verify=[m for m in meters if m["operation"]=="public_verify"]
        assert len(verify)==2
        return dict(accepted=True,appended_to_pool=1,block_height=report["height"],packet_B=len(packet),
                    controller_cpu_s=controller_cpu,wall_s=elapsed,sqlite_vm_instructions=steps,
                    native_verification=verify[-1],verifier_pipe_request_B=after_sizes[0]-before_sizes[0],
                    verifier_pipe_reply_B=after_sizes[1]-before_sizes[1],
                    process_physical_read_B=elapsed_io["read_bytes"]-before_io["read_bytes"],
                    process_charged_write_B=elapsed_io["write_bytes"]-before_io["write_bytes"])
    finally:
        ledger.close()
        resources.close()


def campaign(a):
    from chain import Chain,decode_block
    from runtime import config
    from run import Resources
    r=json.loads((a.capture/"WALLET.json").read_bytes())
    pub=a.capture/"blocks"
    state=Resources(config(a.runtime))
    results={}
    try:
        with tempfile.TemporaryDirectory(prefix="pqwallet-real-offers-") as t:
            d=Path(t)
            prior=a.product/"devnet/review/evidence/main"
            h3=json.loads((prior/"RESULT.json").read_bytes())["winning"][2]
            unrelated,=decode_block((prior/"blocks"/(h3+".bin")).read_bytes()).packets
            warm=d/"warmup.bin"
            warm.write_bytes(unrelated)
            for arm in ("small","large"):
                record=r["scale"][arm]
                ids=record["archive"]["order"]
                n=record["base_height"]+2
                db=d/(arm+".sqlite")
                packet=d/(arm+".bin")
                p,=decode_block((pub/(ids[n]+".bin")).read_bytes()).packets
                assert hashlib.sha256(p).hexdigest()==record["tx"]
                packet.write_bytes(p)
                prep=Chain(db,state.backend)
                try:
                    for bid in ids[:n]:
                        prep.accept((pub/(bid+".bin")).read_bytes())
                    ss=prep.status()
                    assert ss["height"]==n and ss["tip"]==ids[n-1] and ss["mempool"]==0
                finally:
                    prep.close()
                cmd=["strace","-qq","-P",str(db),"-e","trace=pread64","-e","raw=pread64",
                     sys.executable,"-IB",str(Path(__file__).resolve()),str(a.capture),str(a.runtime),
                     "--product",str(a.product),"--db",str(db),"--packet",str(packet),"--warmup",str(warm)]
                child=subprocess.run(cmd,capture_output=True,text=True,timeout=30)
                if child.returncode:
                    raise RuntimeError("registered admission probe failed: "+child.stderr[-1200:])
                single,=re.findall(r"OFFER START\n(.*?)OFFER END",child.stderr,flags=re.S)
                calls=[int(s,0) for s in re.findall(r"pread64\([^\n]*?\)\s+=\s+(0x[0-9a-f]+|\d+)",single)]
                result=json.loads(child.stdout)
                result.update(main_db_pread_calls=len(calls),main_db_pread_B=sum(calls))
                results[arm]=result
    finally:
        state.close()
    return dict(method="real Chain.offer on freshly reopened genuine H6/H42 prefix; registered verifier warmed with a different packet; SQL progress callback and strace only in this measurement",samples=results)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("capture",type=lambda x:Path(x).resolve())
    p.add_argument("runtime",type=lambda x:Path(x).resolve())
    p.add_argument("--product",type=lambda x:Path(x).resolve(),default=Path(__file__).resolve().parents[2])
    for k in ("db","packet","warmup"):
        p.add_argument("--"+k,type=Path,help=argparse.SUPPRESS)
    a=p.parse_args()
    sys.path.insert(0,str(a.product/"devnet"))
    print(json.dumps(worker(a) if a.db else campaign(a),indent=2))
