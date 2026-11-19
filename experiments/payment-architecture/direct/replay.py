"""Verify complete PoW histories and payment effects from public artifacts in a new process."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import time

def verify(deploy, evidence):
    sys.path.insert(0,str(deploy/"devnet"))
    from chain import Chain, block_id, decode_block
    from runtime import config
    from run import Resources
    v=json.loads((evidence/"RUN.json").read_bytes())
    bank={}
    for f in (evidence/"blocks").glob("*.bin"):
        raw=f.read_bytes()
        if block_id(raw).hex()!=f.stem:
            raise ValueError("block digest")
        bank[f.stem]=raw
    if set(bank)!=set(v["selected"])|set(v["orphan"]):
        raise ValueError("incomplete public branch inventory")
    t=time.monotonic()
    roles=Resources(config(deploy/"runtime"))
    try:
        with tempfile.TemporaryDirectory() as temp:
            file=Path(temp)/"full.sqlite"
            ledger=Chain(file,roles.backend)
            try:
                # Admit the competing branch first; the validated work rule chooses the other.
                for bid in dict.fromkeys([*v["orphan"],*v["selected"]]):
                    ledger.accept(bank[bid])
                status=ledger.status()
                if (status["tip"]!=v["final_tip"] or status["height"]!=11 or status["issued"]!=1100
                        or status["fees"]!=12 or status["spent"]!=8 or ledger.selected(1,128)!=v["selected"]):
                    raise ValueError("public final state")
            finally:
                ledger.close()
            with sqlite3.connect(file.as_uri()+"?mode=ro",uri=True) as db:
                stored={name:pages for name,pages in db.execute("SELECT name,SUM(pgsize) FROM dbstat GROUP BY name")}
                projection=db.execute("SELECT sum(length(record)) FROM wallet_history_v2").fetchone()[0]
                # Demonstrate conceptual pruned body retention as a separate storage-only materialization.
                # This is neither a pruned devnet implementation nor a new validating checkpoint.
                keep=2
                pruned=Path(temp)/"pruned.sqlite"
                with sqlite3.connect(pruned) as lean:
                    db.backup(lean)
                    with lean:
                        lean.execute("UPDATE blocks SET raw=x'' WHERE h<=?",(status["height"]-keep,))
                    lean.execute("VACUUM")
            raw_by_tx={}
            for raw in bank.values():
                for p in decode_block(raw).packets:
                    raw_by_tx[hashlib.sha256(p).hexdigest()]=p
            canonical={hashlib.sha256(p).hexdigest() for bid in v["selected"] for p in decode_block(bank[bid]).packets}
            if canonical!={p["tx"] for p in [v["lone"],*v["concurrent"],v["recipient_spend"]]}:
                raise ValueError("missing direct/parallel/new spend")
            slots={}
            for tx,raw in raw_by_tx.items():
                [s]=roles.backend.verify(raw)
                slots[tx]=s
                if s.fee!=3 or len(s.cms)!=2 or len(s.nfs)!=2 or len(raw)!=143187:
                    raise ValueError("payment shape")
            other=slots[v["orphan_payment"]["tx"]]
            winner=slots[v["concurrent"][0]["tx"]]
            if len(set(other.nfs)&set(winner.nfs))!=2 or v["orphan_payment"]["tx"] in canonical:
                raise ValueError("real conflicting branch inputs")
            final_pay_heights={hashlib.sha256(p).hexdigest():decode_block(bank[i]).height
                for i in v["selected"] for p in decode_block(bank[i]).packets}
            ages={tx:h-slots[tx].height for tx,h in final_pay_heights.items()}
            if ages[v["lone"]["tx"]]<2:
                raise ValueError("lone proof did not span unrelated advance")
            result=dict(verified_from_zero_premine=True,height=status["height"],tip=status["tip"],
                bank_blocks=len(bank),issued=status["issued"],fees=status["fees"],spent=status["spent"],
                competing_spend_shared_nullifiers=2,canonical_payments=len(canonical),
                canonical_archive_B=sum(len(bank[i]) for i in v["selected"]),archived_forks_included_B=sum(map(len,bank.values())),
                occupancy=dict(Counter(len(decode_block(bank[i]).packets) for i in v["selected"])),
                standalone_verified_packets=len(slots),payment_ages=ages,external_vk_B=(deploy/"keys/direct.vk").stat().st_size,
                sqlite_full_B=file.stat().st_size,sqlite_pages_by_object_B=stored,projection_payload_all_branches_B=projection,
                storage_only_pruned_two_heights_B=pruned.stat().st_size,wall_with_setup_and_reverification_s=time.monotonic()-t)
        meter=roles.finish("verifier")
        result["verifier_setup"]=[m for m in meter["meters"] if m["operation"]=="verifier_setup"]
        result["standalone_native_verify"]=meter["meters"][-len(slots):]
        return result
    finally:
        roles.close()

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("deploy",type=Path);p.add_argument("public_capture",type=Path)
    a=p.parse_args()
    print(json.dumps(verify(a.deploy.resolve(),a.public_capture.resolve()),indent=2,sort_keys=True))
