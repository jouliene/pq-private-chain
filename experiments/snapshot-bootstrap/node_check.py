"""Check import, restart, independent corroboration and quarantine on three existing reward blocks."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory


def rejects(call,reason):
    try:
        call()
    except ValueError as exc:
        assert reason in str(exc),(str(exc),reason)
        return
    raise AssertionError("operation unexpectedly accepted: "+reason)


def check(deployment,archive,wanted):
    sys.path.insert(0,str(deployment/"devnet"))
    import chain as c
    from node_snapshot import (STATE,attach_history,expected_pin,export_snapshot,finish_replay,import_snapshot,
                               new_replay,state_digest)
    import runtime
    from run import Resources
    raws=[]
    while wanted!=c.GENESIS:
        raw=(archive/(wanted.hex()+".bin")).read_bytes()
        block=c.decode_block(raw)
        assert c.block_id(raw)==wanted
        if block.height<=3:
            raws.append(raw)
        wanted=block.parent
    raws.reverse()
    assert len(raws)==3
    resources=Resources(runtime.config(deployment/"runtime"))
    try:
        with TemporaryDirectory() as tmp:
            tmp=Path(tmp)
            handles=[]
            def opened(path,replay=False):
                ledger=(new_replay if replay else c.Chain)(tmp/path,resources.backend)
                handles.append(ledger)
                return ledger
            try:
                reference=opened("source",True)
                for raw in raws[:2]:
                    reference.accept(raw)
                state,work,pin=export_snapshot(reference)
                assert pin==expected_pin(reference)
                active=opened("import")
                rejects(lambda:import_snapshot(active,state,work[:-1],pin),"truncated")
                assert active.status()["height"]==0
                import_snapshot(active,state,work,pin)
                bid=c.block_id(raws[0])
                rejects(lambda:active.block(bid),"snapshot block body unavailable")
                assert not active.accept(raws[0])["changed"]
                rejects(lambda:active.history_range(pin["tip"],1,c.GENESIS.hex(),1),"snapshot wallet history unavailable")
                record=reference.history_range(pin["tip"],1,c.GENESIS.hex(),1)[1][9:]
                rejects(lambda:attach_history(active,bid,record[:-1]+bytes([record[-1]^1])),"commitment mismatch")
                assert attach_history(active,bid,record) and not attach_history(active,bid,record)
                assert state_digest(active)==pin["state_sha256"]
                active.close()
                handles.remove(active)
                active=opened("import")
                assert active.status()["bootstrap"]["history_attached"]==1
                active.accept(raws[2])
                original_active=opened("original")
                rejects(lambda:finish_replay(active,original_active),"fresh local genesis replay")
                incomplete=opened("incomplete",True)
                incomplete.accept(raws[0])
                rejects(lambda:finish_replay(active,incomplete),"not reached")
                assert active.status()["bootstrap"]["mode"]=="provisional"
                assert finish_replay(active,reference)["mode"]=="full" and active.block(bid)==raws[0]
                assert active.status()["tip"]==c.block_id(raws[2]).hex()
                assert state_digest(active)==state_digest(reference)
                # A fully registered but incorrect history commitment can pass structural checks.
                # Replay must reject even if no optional history bytes were downloaded.
                data=json.loads(state[len(STATE):])
                data["anchors"][0][-1]="00"*32
                altered=STATE+json.dumps(data,sort_keys=True,separators=(",",":")).encode()
                badpin=dict(pin,state_sha256=sha256(altered).hexdigest())
                bad=opened("bad")
                import_snapshot(bad,altered,work,badpin)
                incomplete.accept(raws[1])
                rejects(lambda:finish_replay(bad,incomplete),"differs from full")
                bad.close()
                handles.remove(bad)
                bad=opened("bad")
                assert bad.status()["bootstrap"]["mode"]=="quarantined" and "fees" not in bad.status()
                for call in (bad.pending,lambda:bad.tx(bid),lambda:bad.public_assets(b"",1,pin["tip"]),
                             lambda:bad.supply_observation([]),lambda:bad.page("nfs",0,1,pin["tip"]),
                             lambda:bad.accept(raws[2])):
                    rejects(call,"quarantined")
                return dict(base=2,suffix=1,truncated_work="rolled back",history="authenticated",
                            unavailable_prefix="provisional",audited="full",conflicting_commitment="quarantined after restart")
            finally:
                for db in reversed(handles):
                    db.close()
    finally:
        resources.close()


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("deployment",type=Path)
    parser.add_argument("blocks",type=Path)
    parser.add_argument("tip",type=bytes.fromhex)
    args=parser.parse_args()
    print(json.dumps(check(args.deployment.resolve(strict=True),args.blocks,args.tip),sort_keys=True))
