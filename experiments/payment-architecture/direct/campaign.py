"""Fresh independently controlled wallets on an isolated DLF1 PoW branch; keep private homes outside evidence."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time

def require(ok, reason):
    if not ok:
        raise ValueError(reason)

def campaign(deploy, home, evidence):
    sys.path.insert(0,str(deploy/"devnet"))
    from cli import Lab, wait
    from chain import block_id, decode_block
    from transport import rpc
    lab=Lab(home,deploy/"runtime")
    if home.exists() or evidence.exists():
        raise ValueError("fresh private home and fresh public evidence directory required")
    os.umask(0o077)
    evidence.mkdir(parents=True); (evidence/"blocks").mkdir()
    start=time.monotonic()
    def cmd(*words):
        return json.loads(subprocess.check_output([sys.executable,"-IB",str(deploy/"devnet/cli.py"),
            "--runtime",str(lab.runtime),"--home",str(lab.home),*map(str,words)],timeout=240))
    def sync(nodes,height):
        return wait(lambda:[lab.status(n) for n in nodes],
                    lambda v:all(s["height"]==height for s in v) and len({s["tip"] for s in v})==1,
                    "selected heads at "+str(height),120)[0]
    def capture(node):
        order=lab.request(node,"selected",start=1,limit=128)[0]
        for key in order:
            block=lab.request(node,"block",id=key)[1]
            require(block_id(block).hex()==key,"public block identity")
            (evidence/"blocks"/(key+".bin")).write_bytes(block)
        return order
    def amount(name, expected, node):
        result=cmd("balance",name,"--node",node)
        require(result["balance"]==expected,"unexpected private balance")
        return result
    def pay(name,address,amount,ident,node):
        t=time.monotonic()
        p=cmd("send",name,"@"+str(address),amount,"--intent",ident,"--node",node)
        require(p["status"]=="submitted" and p["real_inputs"]==2 and
                p["input_total"]==amount+3+p["change"],"wallet funding or node admission")
        return {k:p[k] for k in ("amount","real_inputs","input_total","fee","change","packet_B","tx","anchor_height",
                                  "wallet_metrics","submission_frame")} | {"elapsed_s":time.monotonic()-t}
    def packet(node,p):
        raw=lab.request(node,"tx",id=p["tx"])[1]
        require(hashlib.sha256(raw).hexdigest()==p["tx"],"payment identity")
        return raw
    def partition(parts):
        for part in parts:
            for n in part:
                lab.links(n,[k for k in part if k!=n])
    def rejected(node,raw,reason):
        before=lab.status(node)
        try:
            lab.request(node,"submit",raw)
        except ValueError as exc:
            require(str(exc)==reason,"unexpected checking layer: "+str(exc))
        else:
            raise ValueError("invalid packet accepted")
        after=lab.status(node)
        for field in ("tip","work","issued","fees","spent_set_sha256","mempool","root"):
            if field in before:
                require(before[field]==after[field],"rejection modified "+field)
        return reason
    def participants_in_block(node,expected):
        raw=lab.request(node,"block",id=lab.status(node)["tip"])[1]
        actual=[hashlib.sha256(p).hexdigest() for p in decode_block(raw).packets]
        require(set(actual)==set(expected) and len(actual)==len(expected),"wrong included payment list")
        return actual
    try:
        lab.start(manual=True)
        with tempfile.TemporaryDirectory(dir=home) as disposable:
            private=Path(disposable)
            address=private/"offline.address"
            backup=private/"offline.seed"
            with tempfile.TemporaryDirectory(dir=private) as fresh:
                offline=Lab(Path(fresh),lab.runtime)
                offline.new_wallet("receive")
                offline.export_address("receive",address);offline.backup("receive",backup)
            neutral=private/"neutral.address"
            lab.new_wallet("neutral");lab.export_address("neutral",neutral)
            lab.new_wallet("carol")
            for label in ("miner-a","miner-b","carol"):
                lab.mine("b",2,label)
            sync("abc",6)
            for label in ("miner-a","miner-b","carol"):
                amount(label,200,"a")
            partition(["a","bc"])
            lone=pay("miner-a",address,150,"lone","a")
            lone_raw=packet("a",lone)
            # An unrelated PoW block wins before our prepared wallet packet reaches the direct validator.
            lab.mine("b",1,"neutral");sync("bc",7)
            lab.request("b","submit",lone_raw);lab.mine("b",1,"neutral")
            participants_in_block("b",[lone["tx"]])
            partition(["abc"]);sync("abc",8)
            partition(["a","bc"])
            lab.backup("miner-b",private/"other-branch.seed")
            cmd("restore","alternate",private/"other-branch.seed","--node","a")
            competing=pay("alternate",neutral,151,"alternative","a")
            other_raw=packet("a",competing);lab.mine("a",1,"neutral")
            participants_in_block("a",[competing["tx"]])
            orphan=capture("a")
            with ThreadPoolExecutor(max_workers=2) as pool:
                t=time.monotonic()
                left=pool.submit(pay,"miner-b",address,150,"parallel-b","b")
                right=pool.submit(pay,"carol",address,150,"parallel-c","c")
                both=[left.result(),right.result()]
                concurrent_wall=time.monotonic()-t
            wait(lambda:lab.request("c","pending")[0],lambda ids:set(ids)=={p["tx"] for p in both},"two independent payments")
            invalid={}
            invalid["pool_conflict"]=rejected("c",other_raw,"pool conflict")
            sample=packet("c",both[0])
            proof_n,=struct.unpack_from("<I",sample,5)
            # Alter data in canonical-length fields; these reach the genuine verifier.
            for label,offset in (("proof_opening",42),("public_statement",9+proof_n-26*8+32),("receipt",len(sample)-40)):
                changed=bytearray(sample);changed[offset]^=1
                invalid[label]=rejected("c",bytes(changed),"cryptographic payment rejection")
            lab.mine("c",1,"neutral");participants_in_block("c",[v["tx"] for v in both])
            invalid["spent_conflict"]=rejected("c",other_raw,"spent nullifier")
            lab.mine("c",1,"neutral");sync("bc",10)
            partition(["abc"]);sync("abc",10)
            require(orphan[-1]!=lab.request("a","selected",start=9,limit=1)[0][0],"expected real reorganization")
            amount("alternate",47,"a")
            received=cmd("restore","recovered",backup,"--node","c")
            require(received["balance"]==450 and received["incoming_notes"]==3,"offline incoming-only recovery")
            successor=pay("recovered",neutral,250,"restored-spend","c")
            require(successor["input_total"]==300 and successor["change"]==47,"respend accounting")
            lab.mine("c",1,"neutral");participants_in_block("c",[successor["tx"]])
            final=sync("abc",11)
            require(final["fees"]==12 and final["issued"]==1100,"supply")
            amount("recovered",197,"c")
            selected=capture("c")
            # A real, fresh, block-only client replay link; separate from the miner's polling traffic.
            transfer={"request_B":0,"reply_B":0,"block_payload_B":0}
            meter={}
            result,_=rpc(lab.cfg["ports"]["c"],"selected",start=1,limit=128,meter=meter)
            require(result==selected,"replay selected tip")
            for key in ("request_B","reply_B"):
                transfer[key]+=meter[key]
            for bid in selected:
                m={}
                _,raw=rpc(lab.cfg["ports"]["c"],"block",id=bid,meter=m)
                require(block_id(raw).hex()==bid,"peer replay body")
                for key in ("request_B","reply_B"):
                    transfer[key]+=m[key]
                transfer["block_payload_B"]+=len(raw)
            report=dict(format="DLF1-COMPLETE-1",proof_path="direct source-registered blinded leaf",
                bits=22,fee_per_payment=3,receipts_B_each=1792,lone=lone,concurrent=both,
                concurrent_wall_s=concurrent_wall,orphan_payment=competing,recipient_spend=successor,
                restored_received=450,restored_final_balance=197,cold_restore=received["sync"],
                orphan=orphan,selected=selected,final_tip=final["tip"],fees=final["fees"],issued=final["issued"],
                negative=invalid,block_relay=transfer,elapsed_s=time.monotonic()-start)
            (evidence/"RUN.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
            print(json.dumps(dict(tip=final["tip"],canonical_payments=4,independently_funded_senders=3,
                packet_B=lone["packet_B"],wall_s=report["elapsed_s"])))
    finally:
        lab.stop()

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for key in ("deploy","home","evidence"):
        p.add_argument(key,type=Path)
    a=p.parse_args()
    campaign(a.deploy.resolve(),a.home.resolve(),a.evidence.resolve())
