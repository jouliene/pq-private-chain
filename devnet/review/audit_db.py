"""Compare an atomic, read-only devnet database snapshot to independently decoded full public branches."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from network_oracle import GENESIS, NETWORK, ZERO, best, counted_hash, decode, examine, proof_public, u32


def audit_db(path, roots_exe, reward_exe):
    con = sqlite3.connect(path.resolve().as_uri()+"?mode=ro",uri=True)
    con.row_factory=sqlite3.Row
    try:
        con.execute("BEGIN")
        assert con.execute("PRAGMA integrity_check").fetchone()[0]=="ok"
        assert not list(con.execute("PRAGMA foreign_key_check"))
        assert con.execute("SELECT network FROM config").fetchall()[0][0]==NETWORK
        stored={r["id"]:r for r in con.execute("SELECT id,parent,h,work,ap,header,fees,n,front,raw FROM blocks")}
        chain=[r[0] for r in con.execute("SELECT id FROM sel ORDER BY h")]
        genesis=stored[GENESIS]
        assert chain[0]==GENESIS and genesis["parent"] is None and genesis["raw"]==b""
        assert genesis["h"]==genesis["work"]==genesis["fees"]==genesis["n"]==0 and genesis["front"]==b""
        assert genesis["header"]==ZERO+u32(0)+counted_hash(b"dev-genesis-state",NETWORK)+counted_hash(b"dev-genesis-body",NETWORK)+ZERO
        assert genesis["ap"].hex()==examine([],roots_exe,reward_exe)["anchor"]
        assert all(i==h for h,(i,) in enumerate(con.execute("SELECT h FROM sel ORDER BY h")))
        results={}
        parents={r["parent"] for r in stored.values()}
        for tip in {chain[-1],*(b for b in stored if b not in parents)}:
            path_to_tip=[]
            ancestry=set()
            at=tip
            while at!=GENESIS:
                assert at in stored and at not in ancestry
                ancestry.add(at)
                row=stored[at]
                path_to_tip.append(row["raw"])
                at=row["parent"]
            path_to_tip.reverse()
            result=examine(path_to_tip,roots_exe,reward_exe)
            assert bytes.fromhex(result["tip"])==tip and result["height"]==stored[tip]["h"]
            for info in result["headers"]:
                row=stored[bytes.fromhex(info["id"])]
                assert row["work"]==info["work"] and row["fees"]==info["fees"] and row["ap"].hex()==info["anchor"]
                assert row["header"][100:132].hex()==info["funded_root"]
            results[tip]=result
        assert best(results.values())["tip"]==chain[-1].hex()
        selected=results[chain[-1]]
        assert [h["id"] for h in selected["headers"]]==[h.hex() for h in chain[1:]]
        outs=[]
        spent=[]
        selected_txids=set()
        for b in chain[1:]:
            raw=decode(stored[b]["raw"])
            for packet in raw["packets"]:
                selected_txids.add(hashlib.sha256(packet).digest())
                slot,=proof_public(packet)
                for nf in slot[2]:
                    spent.append((nf,raw["h"]))
                for i,cm in enumerate(slot[3]):
                    outs.append((len(outs),cm,raw["h"],slot[-1][1792*i:1792*(i+1)],None))
            outs.append((len(outs),raw["cm"],raw["h"],None,raw["reward_body"]+raw["cm"]))
        actual=[tuple(r) for r in con.execute("SELECT pos,cm,h,ct,reward FROM outs ORDER BY pos")]
        assert actual==outs
        assert sorted(spent)==[tuple(r) for r in con.execute("SELECT nf,h FROM spent ORDER BY nf")]
        assert stored[chain[-1]]["n"]==len(outs)
        txloc=set()
        for bid,row in stored.items():
            if bid!=GENESIS:
                b=decode(row["raw"])
                txloc.update((hashlib.sha256(p).digest(),bid,i) for i,p in enumerate(b["packets"]))
        assert txloc=={tuple(r) for r in con.execute("SELECT tx,bid,idx FROM txloc")}
        pool=list(con.execute("SELECT tx,packet,nf0,nf1,cm0,cm1 FROM pool"))
        assert len(pool)<=64
        nullifiers={p[0] for p in spent}
        commitments={p[1] for p in outs}
        for row in pool:
            slot,=proof_public(row["packet"])
            assert hashlib.sha256(row["packet"]).digest()==row["tx"] and row["tx"] not in selected_txids
            assert slot[2]==(row["nf0"],row["nf1"]) and slot[3]==(row["cm0"],row["cm1"])
            assert nullifiers.isdisjoint(slot[2]) and commitments.isdisjoint(slot[3])
            nullifiers.update(slot[2])
            commitments.update(slot[3])
        return dict(selected={k:v for k,v in selected.items() if k!="headers"},
                    heights_by_occupancy=dict(Counter(h["width"] for h in selected["headers"])),
                    branch_tips=[dict(tip=r["tip"],height=r["height"],work=r["work"]) for _,r in sorted(results.items())],
                    selected_headers=selected["headers"],raw_block_objects=len(stored)-1,txloc_rows=len(txloc),
                    pending=len(pool),commitment_and_reward_receipt_rows=len(outs),spent_rows=len(spent))
    finally:
        con.close()


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("database",type=Path)
    p.add_argument("reference",type=Path)
    p.add_argument("reward",type=Path)
    a=p.parse_args()
    print(json.dumps(audit_db(a.database,a.reference.resolve(),a.reward.resolve()),indent=2,sort_keys=True))
