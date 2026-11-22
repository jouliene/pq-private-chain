"""Measure a genuine linked proof and detached-hash control in isolated role processes."""
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parents[2]/"fresh-spend"/"binding"))
from relation import parent


def call(action,statement,proof,w=None,negative=False):
    start = time.perf_counter()
    p = subprocess.run([sys.executable,str(HERE/"role.py"),action,str(statement),str(proof)],
                       input=w or b"",capture_output=True,cwd=statement.parent)
    if negative:
        if p.returncode!=1 or b"rejected" not in p.stderr:
            raise RuntimeError(f"unexpected negative result: {p.returncode} {p.stderr[-256:]}")
        return p.stderr.decode().strip()
    if p.returncode:
        raise RuntimeError(p.stderr.decode())
    return {**json.loads(p.stdout),"process_wall_s":time.perf_counter()-start}


def main():
    directory = Path(sys.argv[1]).resolve()
    directory.mkdir(parents=True,exist_ok=False)
    a,b,c,z = (secrets.token_bytes(64) for _ in range(4))
    d0,d1 = secrets.randbits(1),secrets.randbits(1)
    level = 12
    first = parent(level,b,a) if d0 else parent(level,a,b)
    root = parent(level+1,c,first) if d1 else parent(level+1,first,c)
    detached = parent(level+1,c,z) if d1 else parent(level+1,z,c)
    if first == z:
        raise RuntimeError("independent digest repeated")
    st,pr = directory/"mixed.statement",directory/"mixed.proof"
    st.write_bytes(bytes([level])+root)
    private = a+b+c+bytes((d0,d1))
    stats = {"profile":"mixed16x256","prove":call("prove",st,pr,private),
             "verify":call("verify",st,pr)}
    data = pr.read_bytes()
    stats.update(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        other,mod = tmp/"other.statement",tmp/"modified.proof"
        for name,raw in (("wrong_root",bytes([level])+bytes([root[0]^1])+root[1:]),
                         ("wrong_level",bytes([level+1])+root)):
            other.write_bytes(raw)
            stats[name] = call("verify",other,pr,negative=True)
        other.write_bytes(bytes([level])+detached)
        call("detached",other,mod,private+z)
        stats["detached_link"] = call("verify",other,mod,negative=True)
        for name,offset in (("trace_mutation",137),("column_mutation",len(data)//2),
                            ("degree_response_mutation",len(data)-7)):
            mod.write_bytes(data[:offset]+bytes([data[offset]^1])+data[offset+1:])
            stats[name] = call("verify",st,mod,negative=True)
        for name,raw in (("truncated",data[:-1]),("trailing",data+b"\0")):
            mod.write_bytes(raw)
            stats[name] = call("verify",st,mod,negative=True)
    (directory/"metrics.json").write_text(json.dumps(stats,indent=2)+"\n")
    print(json.dumps(stats))


if __name__ == "__main__":
    main()
