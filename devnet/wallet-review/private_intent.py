"""Check selected effect cardinality and independently verify the actual real input overlap. Output counts only."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE.parent),str(HERE.parents[1]/"experiments/advancing-payments")]
from private_compare import decode
from runtime import config
from run import Resources


def ro(path):
    return sqlite3.connect(path.resolve().as_uri()+"?mode=ro",uri=True)


def audit(private,ident,capture,node,runtime):
    with ro(private/"intents.sqlite") as out:
        row=out.execute("SELECT pinned,disposition FROM intents WHERE id=?",(ident,)).fetchone()
        assert row is not None and row[0]
        cms=json.loads(row[0])
        txs=[r[0] for r in out.execute("SELECT tx FROM attempts WHERE intent=? ORDER BY rowid",(ident,))]
    assert 1<=len(cms)<=2 and len(txs)>=2
    with ro(private/"wallet-state.sqlite") as wallet:
        # Current genuinely spent real note(s) retained by the sender. No identity leaves this process.
        nfs={wallet.execute("SELECT nf FROM owned WHERE cm=?",(bytes.fromhex(cm),)).fetchone()[0] for cm in cms}
    assert len(nfs)==len(cms)
    public=Resources(config(runtime))
    try:
        registered=[]
        for tx in txs:
            raw=(capture/"attempts"/(tx+".bin")).read_bytes()
            assert hashlib.sha256(raw).hexdigest()==tx
            slot,=public.backend.verify(raw)
            assert nfs<=set(slot.nfs)
            registered.append((tx,slot))
        common=set.intersection(*[set(slot.nfs) for _,slot in registered])
        assert nfs<=common
    finally:
        public.close()
    effects=[]
    with ro(node) as db:
        for height,raw in db.execute("SELECT s.h,b.raw FROM sel s JOIN blocks b ON b.id=s.id WHERE s.h>0 ORDER BY s.h"):
            block=decode(raw)
            for packet in block["packets"]:
                tx=hashlib.sha256(packet).hexdigest()
                if tx in txs:
                    effects.append((height,tx))
    report=json.loads((capture/"WALLET.json").read_bytes())["live_intent"]
    assert len(effects)==1 and effects[0][1]==report["confirmed"] and row[1]=="confirmed"
    return dict(registered_verified_attempts=len(registered),real_inputs_shared_by_all=len(nfs),
                all_shared_nullifiers=len(common),selected_effects=len(effects),selected_height=effects[0][0],
                selected_fee=next(slot.fee for tx,slot in registered if tx==effects[0][1]))


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for key in ("private","capture","node","runtime"):
        p.add_argument(key,type=Path)
    p.add_argument("intent")
    a=p.parse_args()
    print(json.dumps(audit(a.private,a.intent,a.capture,a.node,a.runtime),indent=2))
