"""Create eight independent 2x2 transfers on one PoW branch while the archivist is offline."""
import argparse
from collections import Counter
from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent


def save(path, obj):
    path.write_text(json.dumps(obj, sort_keys=True, indent=2) + "\n")


def capture(network, home, evidence):
    sys.path.insert(0, str(network/"devnet"))
    from cli import Lab, wait
    import chain
    sys.path.insert(0,str(HERE.parents[1]/"devnet/wallet-review"))
    from wire_meter import Meter
    if evidence.exists() or home.exists():
        raise ValueError("fresh home and evidence directories required")
    os.umask(0o077)
    for sub in ("blocks", "packets"):
        (evidence/sub).mkdir(parents=True)
    lab = Lab(home, network/"runtime")
    names = ("miner-a", "miner-b", "third", "fourth", "fifth", "sixth", "seventh", "eighth", "ninth")
    def cli(*args):
        command=[sys.executable,"-IB",str(network/"devnet/cli.py"),"--home",str(home),"--runtime",str(lab.runtime)]
        return json.loads(subprocess.check_output(command+list(map(str,args)),timeout=200))
    def inventory(node):
        total=lab.status(node)["height"]
        ids=[]
        while len(ids)<total:
            ids.extend(lab.request(node,"selected",start=len(ids)+1,limit=min(128,total-len(ids)))[0])
        return ids
    def collect(node):
        result=inventory(node)
        for ident in result:
            dest=evidence/"blocks"/(ident+".bin")
            if not dest.exists():
                raw=lab.request(node,"block",id=ident)[1]
                assert chain.block_id(raw).hex()==ident
                dest.write_bytes(raw)
        return result
    meters={}
    group=ExitStack()
    def connect(node,neighbors):
        lab.admin(node,"peers",ports=[meters[n].port for n in neighbors])
    def pay(i,node,amount):
        name=names[i]
        start=time.monotonic()
        start_unix=time.time()
        result=cli("send",name,"@"+str(home/"offline.address"),amount,"--intent","offline","--node",node,"--wait",120)
        elapsed=time.monotonic()-start
        assert result["status"]=="confirmed" and result["input_total"]==200 and result["real_inputs"]==2
        sid=result["tx"]
        raw=lab.request(node,"tx",id=sid)[1]
        assert chain.txid_of(raw).hex()==sid and len(raw)==143187
        (evidence/"packets"/(str(i)+".bin")).write_bytes(raw)
        for height,bid in reversed(list(enumerate(inventory(node),1))):
            body=lab.request(node,"block",id=bid)[1]
            if any(chain.txid_of(p).hex()==sid for p in chain.decode_block(body).packets):
                break
        else:
            raise RuntimeError("confirmed effect absent")
        mined=[e["found_unix"] for n in "abc" if (home/"nodes"/n/"mined.jsonl").exists()
               for line in (home/"nodes"/n/"mined.jsonl").read_text().splitlines() if line
               for e in [json.loads(line)] if e["tip"]==bid]
        if not mined:
            raise ValueError("missing miner observation")
        return dict(command_to_mined_s=min(mined)-start_unix,sid=sid,anchor=result["anchor_height"],height=height,block=bid,amount=amount,fee=result["fee"],
                    change=result["change"],inputs=result["real_inputs"],attempts=len(result["attempts"]),
                    online_to_observed_s=elapsed,prover_wall_s=result["proving_wall_s"],frames=result["submission_frames"])
    def common(nodes):
        return wait(lambda:[lab.status(n) for n in nodes],lambda ss:len({s["tip"] for s in ss})==1,
                    "converged selected work",90)[0]
    try:
        lab.initialize()
        for n in "abc":
            meters[n]=group.enter_context(Meter(lab.cfg["ports"][n]))
        lab.cfg["ports"].update({"meter-"+n:m.port for n,m in meters.items()})
        save(home/"network.json",lab.cfg)
        for n in "abc":
            (home/"nodes"/n/"peers.json").write_text("[]")
            lab.launch(n,continuous=False)
        for n in "abc":
            connect(n,[m for m in "abc" if m!=n])
        for n in names[2:]+("neutral",):
            lab.new_wallet(n)
        with tempfile.TemporaryDirectory(dir=home) as tmp:
            offline=Lab(Path(tmp),lab.runtime)
            offline.new_wallet("offline")
            offline.export_address("offline",home/"offline.address")
            offline.backup("offline",home/"recipient.seed")
        assert len({lab.address(n) for n in names})==9
        for name in names:
            lab.mine("a",2,name)
        assert common("abc")["height"]==18
        # Both miners run their normal independent nonce-search loops without a certificate process.
        for n in "ab":
            lab.mining(n,-1,"neutral")
        payments=[]
        for i in range(7):
            payments.append(pay(i,"a",150))
        for n in "ab":
            lab.mining(n,0)
        split=common("abc")
        for node,others in (("a","b"),("b","a"),("c","")):
            connect(node,others)
        for n in "ab":
            lab.mining(n,-1,"neutral")
        payments.append(pay(7,"a",150))
        for n in "ab":
            lab.mining(n,0)
        main=common("ab")
        selected=collect("a")
        assert len(set(p["height"] for p in payments))>1
        first=dict(format="D8-LIVE-1",network=chain.NETWORK.hex(),payments=payments,
                   original_selected=selected,split=split["height"],original=main,
                   direct_wallet_bytes=sum(sum(f["request_B"] for f in p["frames"]) for p in payments))
        save(evidence/"CAPTURE.json",first)
        # Another real payer's singleton will remain outside the eight-slot certificate.
        lab.mining("c",-1,"neutral")
        outsider=pay(8,"c",151)
        wait(lambda:lab.status("c"),lambda s:s["height"]>main["height"],"greater independent work",180)
        lab.mining("c",0)
        winner=collect("c")
        alternate=lab.status("c")
        for n in "abc":
            connect(n,[x for x in "abc" if n!=x])
        final=common("abc")
        assert final["tip"]==alternate["tip"] and final["tip"]!=main["tip"]
        assert len(selected)>split["height"] and selected[:split["height"]]==winner[:split["height"]]
        assert final["spent"]==16 and final["fees"]==24
        costs={}
        for n,meter in meters.items():
            result={}
            for r in list(meter.rows):
                c=result.setdefault(r["op"],Counter())
                c.update(count=1,request_B=r["request_frame_B"],reply_B=r["reply_frame_B"],body_B=r["reply_payload_B"])
            costs[n]=result
        save(evidence/"RELAY.json",dict(scope="all three measured serving endpoints, both directions of peer polling through convergence; wallet submit billed separately",endpoints=costs))
        save(evidence/"BRANCH.json",dict(format="D8-BRANCH-1",winner=winner,winning_state=final,outside=outsider,
             losing_suffix=len(selected)-split["height"],winning_suffix=len(winner)-split["height"]))
        print(json.dumps(dict(split=split["height"],first_height=len(selected),winner_height=len(winner),
                              eight_senders=True,uncovered=1,original_ports_offline_on_exit=True)))
    finally:
        try:lab.stop()
        finally:group.close()


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for k in ("network","home","evidence"):
        p.add_argument(k,type=Path)
    a=p.parse_args()
    capture(a.network.resolve(),a.home.resolve(),a.evidence.resolve())
