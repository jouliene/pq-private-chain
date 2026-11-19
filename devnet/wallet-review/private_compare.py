"""Local full-history differential. Output counts only; never export either inventory or any path."""
import importlib.util
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile

HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE.parent/"review")]
from check_membership import compare
from network_oracle import decode,proof_public


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    obj=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


def reference_inventory(legacy_product,legacy_runtime,private_dir,view):
    old=module("previous_full_wallet",legacy_product/"devnet/wallet.py")
    verify=module("previous_wallet_build",legacy_product/"devnet/crypto/check_build.py")
    exe=legacy_runtime/"native"
    binary_sha=verify.validate(exe,legacy_runtime/"BUILD.json")
    keys=legacy_product/"experiments/advancing-payments/evidence/public-registry"
    with tempfile.TemporaryDirectory(prefix="pqdev-wallet-private-oracle-") as scratch:
        private=Path(scratch)
        with (private_dir/"seed").open("rb") as src:
            with os.fdopen(os.open(private/"seed",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"wb") as dst:
                shutil.copyfileobj(src,dst)
        with old.Wallet(exe,binary_sha,keys,private,"restore") as cold:
            totals=cold.scan(*view)
            return list(cold.history),totals


def public_snapshot(database,height,wanted_tip):
    leaves=[]
    rewards=[]
    receipts=[]
    spent=[]
    with sqlite3.connect(database.resolve().as_uri()+"?mode=ro",uri=True) as db:
        db.execute("BEGIN")
        tip,header=db.execute("SELECT b.id,b.header FROM sel s JOIN blocks b ON b.id=s.id WHERE s.h=?",(height,)).fetchone()
        assert tip==wanted_tip,"wallet prefix is no longer selected"
        rows=db.execute("SELECT b.id,b.raw FROM sel s JOIN blocks b ON b.id=s.id WHERE s.h BETWEEN 1 AND ? ORDER BY s.h",(height,))
        count=0
        for expected,raw in rows:
            count+=1
            b=decode(raw)
            assert b["id"]==expected and b["h"]==count
            for packet in b["packets"]:
                slot,=proof_public(packet)
                for i,cm in enumerate(slot[3]):
                    leaves.append(cm)
                    receipts.append(cm+slot[-1][i*1792:(i+1)*1792])
                spent.extend(slot[2])
            rewards.append(b["reward_body"]+b["cm"])
            leaves.append(b["cm"])
        assert count==height
    return leaves,(header,b"".join(leaves),b"".join(rewards),b"".join(receipts),b"".join(sorted(spent)))


def normalize(rows):
    return sorted((row["commitment"],row["amount"],row["source"],bool(row["spent"])) for row in rows)


def check_private(state,private_dir,node_database,legacy_product,legacy_runtime,oracle):
    """Compare the current durable state of a dedicated test wallet at its committed selected prefix."""
    leaves,view=public_snapshot(Path(node_database),state.height,state.tip)
    cold,totals=reference_inventory(Path(legacy_product),Path(legacy_runtime),Path(private_dir),view)
    assert normalize(cold)==normalize(state.history),"ownership, values, classification or spentness diverged"
    assert state.inventory()==totals,"wallet totals differ from full scan"
    statuses=state.input_status(tuple(row["commitment"] for row in cold))
    assert all(statuses[row["commitment"]]==("spent" if row["spent"] else "unspent") for row in cold)
    samples=[]
    for row in cold:
        if row["spent"] or not row["amount"]:
            continue
        pos,siblings=state.witness(row["commitment"])
        assert leaves[pos]==bytes.fromhex(row["commitment"])
        samples.append((pos,siblings))
    if leaves:
        paths=compare(oracle,leaves,view[0][100:132],samples)
    else:
        assert not cold and view[0][100:132]==bytes(32)
        paths=dict(public_leaves=0,depth=0,owned_paths=0,positional_siblings_checked=0)
    return dict(height=state.height,public_full_replay_B=sum(len(x) for x in view),
                owned_records=len(cold),spent_records=sum(r["spent"] for r in cold),
                balance_matches=True,all_statuses_match=True,membership=paths)


if __name__=="__main__":
    import argparse
    import json
    sys.path.insert(0,str(HERE.parent))
    import chain
    from cli import Lab
    from wallet_sync import WalletSync
    parser=argparse.ArgumentParser(description=__doc__)
    for option in ("home","runtime","legacy-product","legacy-runtime","oracle"):
        parser.add_argument("--"+option,required=True,type=lambda s:Path(s).resolve())
    parser.add_argument("--wallet",required=True)
    parser.add_argument("--node-database",type=Path,help="public chain.sqlite if the wallet lives in a separate home")
    parser.add_argument("--node",choices=tuple("abcd"),default="c")
    a=parser.parse_args()
    lab=Lab(a.home,a.runtime)
    directory=lab.walletdir(a.wallet)
    assert (directory/"wallet-state.sqlite").is_file(),"run the actual wallet synchronization first"
    gh=bytes(32)+chain.u32(0)+chain.digest(b"dev-genesis-state",chain.NETWORK)+chain.digest(b"dev-genesis-body",chain.NETWORK)+bytes(32)
    with lab.wallet(a.wallet) as wallet:
        state=WalletSync(wallet,directory,chain.NETWORK,chain.GENESIS,gh)
        try:
            database=a.node_database or a.home/"nodes"/a.node/"chain.sqlite"
            info=check_private(state,directory,database,a.legacy_product,a.legacy_runtime,a.oracle)
        finally:
            state.close()
    print(json.dumps(info,indent=2))
