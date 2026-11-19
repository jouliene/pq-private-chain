"""Compare private checkpoints with the full wallet on a completed genuine walkthrough's two archived branches.

Only aggregate results leave the disposable fixture. Run with --home pointing to the local walkthrough.
"""
import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import shutil
import sys
import time
import hashlib
import tempfile

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
import chain
import runtime
from history import decode_range
from run import Resources
from wallet import Wallet
from wallet_sync import synced_wallet


class LocalFeed:
    """The local Chain implementation, called directly without network or transport bytes."""
    def __init__(self,node):
        self.node=node
        self.damage=None

    def request(self,_,op,meter,**kw):
        result=getattr(self.node,op)(**kw)
        meta,body=result if op=="history_range" else (result,b"")
        if self.damage=="continuation" and op=="history_range":
            meta["next"]=999
        if self.damage=="later-block" and op=="history_range":
            from history import BLOCK_BYTES,SLOT_BYTES
            offset=9
            while offset+BLOCK_BYTES+body[offset+BLOCK_BYTES-1]*SLOT_BYTES<len(body):
                offset+=BLOCK_BYTES+body[offset+BLOCK_BYTES-1]*SLOT_BYTES
            # Last block's funded root, covered by wallet validation.
            root=offset+68+100
            body=body[:root]+bytes(32)+body[root+32:]
        if self.damage=="frozen-count" and op=="history_head":
            meta["notes"]+=1
        return meta,body


def check(home,native,name,prove=False):
    report=json.loads((home/"evidence/RESULT.json").read_bytes())
    win=report["winning"]
    split=win.index(report["reorg"]["common"])+1
    lose=win[:split]+report["reorg"]["detached"]
    assert len(lose)-split>chain.UNDO and len(win)>len(lose)
    res=Resources(native)
    genesis=bytes.fromhex(report["genesis"])
    def add(node,ls):
        for bid in ls:
            raw=(home/"evidence/blocks"/(bid+".bin")).read_bytes()
            assert chain.block_id(raw).hex()==bid
            node.accept(raw)
    with ExitStack() as stack:
        stack.callback(res.close)
        root=Path(stack.enter_context(tempfile.TemporaryDirectory(dir="/dev/shm")))
        priv=root/"wallet"
        priv.mkdir(mode=0o700)
        shutil.copy2(home/"wallets"/name/"seed",priv/"seed")
        node=chain.Chain(root/"chain.sqlite",res.backend)
        stack.callback(node.close)
        feed=LocalFeed(node)
        wallet=stack.enter_context(Wallet(native.binary,native.binary_sha,native.keys,priv))
        oracle=stack.enter_context(Wallet(native.binary,native.binary_sha,native.keys,priv))
        results={}
        def matches(s):
            tip=node.history_head([])
            assert tip["tip"]==s.tip.hex()
            args=[]
            for kind in ("leaves","rewards","receipts","nfs"):
                items=bytearray()
                cursor=0
                while cursor is not None:
                    body,cursor=node.page(kind,cursor,96,tip["tip"])
                    items+=body
                args.append(bytes(items))
            full=oracle.scan(s.header,*args)
            ordered=lambda rows: sorted((r["commitment"],r["amount"],r["source"],r["spent"]) for r in rows)
            assert ordered(s.history)==ordered(oracle.history) and full==s.inventory()
            for r in oracle.history:
                if r["spent"] or not r["amount"]:
                    continue
                cm=bytes.fromhex(r["commitment"])
                pos,path=s.witness(r["commitment"])
                assert args[0][32*pos:32*pos+32]==cm
                value=cm
                idx=pos
                for siblings in path:
                    children=list(siblings)
                    children.insert(idx%4,value)
                    idx//=4
                    value=res.h.call(b"N"+b"".join(children))
                assert value==s.header[-32:]
            return dict(height=s.height,owned_records=len(s.history),positive_unspent=full["notes"])
        add(node,win[:split])
        for error in ("continuation","later-block","frozen-count"):
            # Independent private recovery targets. No logged data or changing the main wallet.
            case=root/error
            case.mkdir(mode=0o700)
            feed.damage=error
            start=0
            if error=="frozen-count":
                with synced_wallet(feed,"local",wallet,case,max_blocks=1) as (s,stats):
                    assert s.height==1 and not stats["complete"]
                start=1
                feed.damage=None
            try:
                with synced_wallet(feed,"local",wallet,case):
                    raise AssertionError("invalid history accepted")
            except ValueError as exc:
                assert str(exc) in ("invalid selected range","wallet funded root or transition mismatch","selected target header mismatch")
            import sqlite3
            with sqlite3.connect(case/"wallet-state.sqlite") as q:
                assert q.execute("SELECT max(h) FROM heads").fetchone()[0]==start
            feed.damage=None
            with synced_wallet(feed,"local",wallet,case) as (s,stats):
                assert stats["complete"] and s.height==split
            results["rejected_"+error]=True
        with synced_wallet(feed,"local",wallet,priv,max_blocks=1) as (s,stats):
            assert not stats["complete"] and s.height==1 and stats["target_tip"]==win[split-1]
        high,low=sorted((win[split],lose[split]),reverse=True)
        add(node,[high])
        with synced_wallet(feed,"local",wallet,priv) as (s,stats):
            assert stats["complete"] and stats["completed_prefixes"]==[split,split+1] and stats["catchup_heads"]==1
            assert s.tip.hex()==high and stats["blocks"]==split
            results["resumed_frozen_target"]=matches(s)
            add(node,[low])
            shallow=s.synchronize(feed,"local")
            assert s.tip.hex()==low and shallow["rewound_blocks"]==1 and shallow["deep_resets"]==0
            results["shallow"]=matches(s)
            add(node,lose[split:])
            s.synchronize(feed,"local")
            results["losing"]=matches(s)
            add(node,win[split:])
            deep=s.synchronize(feed,"local")
            assert deep["deep_resets"]==1 and deep["rewound_blocks"]==len(lose) and s.tip.hex()==win[-1]
            results["deep"]=matches(s)
            warm=s.synchronize(feed,"local")
            assert warm["public_requests"]==1 and warm["public_body_B"]==warm["node_reads"]["payload_rows"]==warm["tree_hashes"]==0
            if prove:
                receiver=stack.enter_context(Wallet(native.binary,native.binary_sha,native.keys,root/"receiver","create"))
                amount=max(row["amount"] for row in s.history if not row["spent"])
                pinned=s.select(amount)
                assert len(pinned)==2
                start=time.perf_counter()
                packet=s.pay(amount,receiver.address,pinned)
                proving_wall=time.perf_counter()-start
                effect,=res.backend.verify(packet)
                assert effect.anchor==res.h.call(b"H"+s.header) and effect.height==s.height and effect.fee==3
                assert set(s.last_payment["real_nullifiers"])=={x.hex() for x in effect.nfs}
                hit=[receiver.open_row(cm+ct) for cm,ct in zip(effect.cms,effect.cts,strict=True)]
                assert [r[1:] for r in hit if r is not None]==[(amount,"incoming")]
                assert node.offer(packet)==dict(id=hashlib.sha256(packet).hexdigest(),duplicate=False)
                results["compact_payment"]=dict(packet_B=len(packet),packet_sha256=hashlib.sha256(packet).hexdigest(),
                    real_inputs=len(pinned),verified_and_accepted_at_height=s.height,recipient_receipt_matches=True,
                    proving_wall_s=proving_wall)
            results["unchanged"]=dict(requests=warm["public_requests"],payload_B=warm["public_body_B"],
                                      metadata_queries=warm["node_reads"]["metadata_queries"])
            data=s.history
            ids=[row[0] for row in s.db.execute("SELECT tx FROM payments")]
            assert all(s.has_payment(i) for i in ids)
            results["owned_related_payment_associations"]=len(ids)
            prev=s.height
            floor=prev-s.keep
            floor_tip=s.db.execute("SELECT id FROM heads WHERE h=?",(floor,)).fetchone()[0]
            s.rewind(floor,floor_tip)
            s.rewind(0,genesis)
            assert not s.history and not any(s.has_payment(i) for i in ids) and s.inventory()["balance"]==0
            # A valid first transition with its root changed must leave all wallet rows at genesis.
            _,body=node.history_range(win[-1],1,genesis.hex(),1)
            bad=decode_range(body)[0]
            bad["header"]=bad["header"][:-32]+bytes(32)
            try:
                s.apply(bad)
            except ValueError as e:
                assert "funded root" in str(e)
            else:
                raise AssertionError("damaged root accepted")
            assert s.height==0 and not s.history and not s.db.execute("SELECT 1 FROM undo").fetchone()
            s.synchronize(feed,"local")
            assert data==s.history and all(s.has_payment(i) for i in ids)
            results.update(atomic_invalid_transition=True,pruned_undo_then_genesis=True,
                           rewound_blocks=deep["rewound_blocks"],replayed_blocks=deep["blocks"],
                           shallow_blocks=shallow["blocks"])
    if prove:
        results["compact_payment"]["native_meters"]=wallet.metrics
    return results


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home",type=Path,required=True)
    parser.add_argument("--runtime",type=Path,required=True)
    parser.add_argument("--wallet",default="miner-a")
    parser.add_argument("--prove",action="store_true")
    a=parser.parse_args()
    print(json.dumps(check(a.home,runtime.config(a.runtime),a.wallet,a.prove),indent=2,sort_keys=True))
