"""Interrupt a real wallet after SQL ownership writes and before its prefix cursor commits."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile

HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE.parent)]
from private_compare import decode,proof_public,check_private
from runtime import config
from wallet import Wallet
from wallet_sync import WalletSync
import chain


def material(node):
    with sqlite3.connect(node.resolve().as_uri()+"?mode=ro",uri=True) as db:
        gh,=db.execute("SELECT b.header FROM sel s JOIN blocks b ON b.id=s.id WHERE s.h=0").fetchone()
        raw,header=db.execute("SELECT b.raw,b.header FROM sel s JOIN blocks b ON b.id=s.id WHERE s.h=1").fetchone()
    b=decode(raw)
    slots=[]
    for packet in b["packets"]:
        row,=proof_public(packet)
        slots.append(dict(txid=hashlib.sha256(packet).digest(),nfs=row[2],cms=row[3],cts=(row[-1][:1792],row[-1][1792:])))
    return gh,dict(height=1,id=b["id"],parent=b["parent"],header=header,reward=b["reward_body"]+b["cm"],slots=slots)


def run_stage(a):
    cfg=config(a.runtime)
    private=a.scratch
    gh,block=material(a.node_database)
    with Wallet(cfg.binary,cfg.binary_sha,cfg.keys,private) as wallet:
        state=WalletSync(wallet,private,chain.NETWORK,chain.GENESIS,gh)
        try:
            assert state.tip==chain.GENESIS and state.height==0 and not state.history
            if a.stage=="init":
                return
            if a.stage=="terminate":
                state.db.execute("PRAGMA cache_size=1")
                state.db.execute("PRAGMA cache_spill=ON")
                w={"owned":False}
                def event(op,table,column,database,trigger):
                    # The SQLite authorizer supplies table/column names and never exposes bound values.
                    if op==sqlite3.SQLITE_INSERT and table=="owned":
                        w["owned"]=True
                    if op==sqlite3.SQLITE_INSERT and table=="heads" and w["owned"]:
                        os._exit(73)
                    return sqlite3.SQLITE_OK
                state.db.set_authorizer(event)
                state.apply(block)
                raise AssertionError("process did not reach the targeted post-ownership write boundary")
            bad=dict(block,header=block["header"][:100]+bytes(32))
            try:
                state.apply(bad)
            except ValueError as err:
                assert str(err)=="wallet funded root or transition mismatch"
            else:
                raise AssertionError("invalid funded root accepted")
            assert state.height==0 and not state.history and state.inventory()["balance"]==0
            with state.transaction(False):
                for table in ("owned","payments","undo"):
                    assert state.db.execute("SELECT count(*) FROM "+table).fetchone()[0]==0
            state.apply(block)
            assert state.height==1 and state.inventory()["reward_notes"]==1 and state.inventory()["balance"]==100
            result=check_private(state,private,a.node_database,a.legacy_product,a.legacy_runtime,a.oracle)
            print(json.dumps(result))
        finally:
            state.close()


def campaign(a):
    with tempfile.TemporaryDirectory(prefix="pqdev-recovery-control-") as tmp:
        private=Path(tmp)
        with (a.miner_private/"seed").open("rb") as src:
            with os.fdopen(os.open(private/"seed",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"wb") as dst:
                shutil.copyfileobj(src,dst)
        base=[sys.executable,"-IB",str(Path(__file__).resolve()),*sys.argv[1:],"--scratch",str(private)]
        subprocess.run(base+["--stage","init"],check=True)
        proc=subprocess.run(base+["--stage","terminate"],capture_output=True)
        assert proc.returncode==73,"abrupt stop not exercised"
        journal=private/"wallet-state.sqlite-journal"
        journal_B=journal.stat().st_size if journal.exists() else 0
        finished=subprocess.run(base+["--stage","recover"],capture_output=True,check=True)
        return dict(real_valid_reward_funded=True,post_ownership_abrupt_exit_code=73,observed_hot_journal_B=journal_B,
                    after_restart_cursor_height=0,invalid_root_rolled_back=True,
                    resumed=json.loads(finished.stdout))


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for key in ("miner-private","node-database","runtime","legacy-product","legacy-runtime","oracle"):
        p.add_argument("--"+key,type=Path,required=True)
    p.add_argument("--scratch",type=Path,help=argparse.SUPPRESS)
    p.add_argument("--stage",choices=("init","terminate","recover"),help=argparse.SUPPRESS)
    a=p.parse_args()
    if a.stage:run_stage(a)
    else:print(json.dumps(campaign(a),indent=2))
