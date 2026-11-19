"""Exercise deterministic public rewards and wallet state replacement. Fixtures use private tmpfs."""
import argparse
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from wallet import FEE, Wallet, _wire


def refused(f, label):
    try:
        f()
    except ValueError as exc:
        if label not in str(exc):
            raise
        return
    raise ValueError("expected rejection: "+label)


def run(args):
    with ExitStack() as stack:
        private=Path(stack.enter_context(tempfile.TemporaryDirectory(dir="/dev/shm")))
        h=_wire.Role(args.binary,args.binary_sha,["hash"])
        v=_wire.Role(args.binary,args.binary_sha,["verify","/keys"],args.keys)
        stack.callback(h.abort);stack.callback(v.abort)
        def wallet(name,mode):
            return stack.enter_context(Wallet(args.binary,args.binary_sha,args.keys,private/name,mode))
        def header(leaves,height):
            root=h.call(b"R"+leaves)
            assert len(root)==32
            return bytes(32)+struct.pack("<I",height)+bytes(64)+root
        a=wallet("payer","create")
        b=wallet("payee","create")
        assert a.address!=b.address and a.scan(header(b"",0),b"",b"",b"",b"")["balance"]==0
        ctx=hashlib.sha256(b"PQDEV1 wallet check public reward context").digest()
        def reward(context, amount):
            body=context+a.spend_pk+struct.pack("<Q",amount)
            cm=h.call(b"C"+body)
            assert len(cm)==32
            return body+cm
        reward_row=reward(ctx,50)
        leaves=reward_row[-32:]
        reward_view=(header(leaves,1),leaves,reward_row,b"",b"")
        assert a.scan(*reward_view)["balance"]==50
        assert b.scan(*reward_view)["balance"]==0
        refused(lambda:a.pay(48,b.address),"insufficient funds")
        refused(lambda:a.pay(0,b.address),"positive")
        refused(lambda:a.scan(header(b"",0),leaves,reward_row,b"",b""),"invalid selected history")
        refused(lambda:a.pay(47,b.address),"scan selected history")
        more=[reward(hashlib.sha256(bytes([i])).digest(),10) for i in range(3)]
        cms=b"".join(row[-32:] for row in more)
        assert a.scan(header(cms,3),cms,b"".join(more),b"",b"")["balance"]==30
        refused(lambda:a.pay(20,b.address),"insufficient funds")
        assert a.scan(*reward_view)["balance"]==50
        b.close();b=wallet("payee","restore")
        report=dict(reward_helper_matches_scan=True,empty_genesis=True,invalid_history_clears=True,
                    fragmented_insufficient=True,profile="APV2")
        if args.prove:
            def effects(raw):
                reply=v.call(raw)
                assert reply[:1]==b"1" and len(reply)==1+172+3584
                s=reply[1:]
                return (s[100:164],s[100:132]+s[172:1964]+s[132:164]+s[1964:],s[36:100])
            raw=a.pay(47,b.address)
            assert a.last_payment==dict(amount=47,fee=FEE,input_total=50,change=0,real_inputs=1)
            next_cms,rows,nfs=effects(raw)
            leaves+=next_cms
            nxt=(header(leaves,2),leaves,reward_row,rows,nfs)
            assert b.scan(*nxt)["balance"]==47
            assert a.scan(*nxt)["balance"]==0
            assert any(o["source"]=="change" and o["amount"]==0 for o in a.history)
            successor=b.pay(39,a.address)
            assert b.last_payment==dict(amount=39,fee=FEE,input_total=47,change=5,real_inputs=1)
            c2,r2,n2=effects(successor)
            leaves+=c2
            end=(header(leaves,3),leaves,reward_row,rows+r2,nfs+n2)
            assert a.scan(*end)["balance"]==39 and b.scan(*end)["balance"]==5
            assert a.scan(*reward_view)["balance"]==50 and b.scan(*reward_view)["balance"]==0
            report.update(exact_amount_consumed=True,restored_recipient_spent=True,
                change_restored=True,orphaned_effects_removed=True,payment_bytes=[len(raw),len(successor)])
        report["wallet_meters"]=[a.close(),b.close()]
        h.close();report["public_meters"]=v.close()
        return report


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary",type=Path);p.add_argument("binary_sha");p.add_argument("keys",type=Path)
    p.add_argument("--prove",action="store_true")
    print(json.dumps(run(p.parse_args()),sort_keys=True,indent=2))
