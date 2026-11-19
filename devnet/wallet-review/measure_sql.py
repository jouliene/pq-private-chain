"""Measure real SQLite reads of the production history endpoints on a public selected archive.

The subprocess tracer records only positional read lengths. It never decodes the read buffer.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent))
from history import PublicHistory


def physical_read_bytes():
    for line in Path("/proc/self/io").read_text().splitlines():
        if line.startswith("read_bytes:"):
            return int(line.split()[1])
    raise RuntimeError("Linux process I/O accounting unavailable")


def worker(path,params):
    p=json.loads(params)
    db=sqlite3.connect(path.resolve().as_uri()+"?mode=ro",uri=True)
    try:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA mmap_size=0")
        gh=bytes.fromhex(p["genesis_header"])
        service=PublicHistory(db,*[bytes.fromhex(p[k]) for k in ("network","profile","genesis")],gh)
        results=[]
        for repetition in range(2):
            steps=0
            def tick():
                nonlocal steps
                steps+=1
                return 0
            db.set_progress_handler(tick,1)
            start_io=physical_read_bytes()
            print("WINDOW START",file=sys.stderr,flush=True)
            db.execute("BEGIN")
            try:
                if p["name"]=="unchanged":
                    head=service.head([[p["height"],p["tip"]],[0,p["genesis"]]])
                    assert head["height"]==p["height"] and head["tip"]==p["tip"]
                    calls=[(head,b"")]
                elif p["name"]=="suffix1":
                    calls=[service.page(p["tip"],p["height"],p["previous"],1)]
                else:
                    calls=[]
                    for start in range(1,p["height"]+1,16):
                        calls.append(service.page(p["tip"],start,p["ids"][start-1],min(16,p["height"]-start+1)))
                result=Counter()
                for meta,body in calls:
                    result.update(meta["reads"])
                    result["reply_history_B"]+=len(body)
            finally:
                db.execute("ROLLBACK")
            print("WINDOW END",file=sys.stderr,flush=True)
            end_io=physical_read_bytes()
            db.set_progress_handler(None,0)
            results.append(dict(repetition=repetition,sqlite_vm_instructions=steps,
                                process_physical_read_B=end_io-start_io,endpoint=dict(result)))
        print(json.dumps(results))
    finally:
        db.close()


def measure(path):
    import chain
    db=sqlite3.connect(path.resolve().as_uri()+"?mode=ro",uri=True)
    try:
        records=db.execute("SELECT s.h,s.id,b.header FROM sel s JOIN blocks b ON s.id=b.id ORDER BY s.h").fetchall()
        assert records[0][1]==chain.GENESIS and records[-1][0]>0
        assert db.execute("SELECT count(*) FROM sqlite_schema WHERE name='wallet_history_v2'").fetchone()[0]==1
    finally:
        db.close()
    ids=[r[1].hex() for r in records]
    results={}
    for name in ("unchanged","suffix1","cold"):
        p=dict(name=name,height=records[-1][0],tip=ids[-1],previous=ids[-2],ids=ids,
               network=chain.NETWORK.hex(),profile=chain.PROFILE.hex(),genesis=ids[0],genesis_header=records[0][2].hex())
        # -e raw ensures no SQLite content reaches the trace. -P selects only the main database FD.
        cmd=["strace","-qq","-P",str(path.resolve()),"-e","trace=pread64","-e","raw=pread64",
             sys.executable,"-IB",str(Path(__file__).resolve()),str(path),"--run",json.dumps(p)]
        child=subprocess.run(cmd,capture_output=True,text=True,timeout=60)
        if child.returncode:
            raise RuntimeError("SQLite read tracing failed: "+child.stderr[-1000:])
        rows=json.loads(child.stdout)
        matches=re.findall(r"WINDOW START\n(.*?)WINDOW END",child.stderr,flags=re.S)
        assert len(matches)==len(rows)==2
        for window,row in zip(matches,rows):
            calls=[int(n,0) for n in re.findall(r"pread64\([^\n]*?\)\s+=\s+(0x[0-9a-f]+|\d+)",window)]
            row.update(main_db_pread_calls=len(calls),main_db_pread_B=sum(calls))
        results[name]=rows
    return dict(height=records[-1][0],tip=records[-1][1].hex(),measurements=results)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("database",type=Path)
    p.add_argument("--run",help=argparse.SUPPRESS)
    o=p.parse_args()
    if o.run:
        worker(o.database,o.run)
    else:
        print(json.dumps(measure(o.database),indent=2,sort_keys=True))
