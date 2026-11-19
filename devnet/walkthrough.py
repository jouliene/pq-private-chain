"""Exercise actual peers and isolated wallets via normal entry points; emit only public/synthetic evidence."""
import collections
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import tempfile
import sys
import time

from cli import HERE, wait
from chain import block_id, decode_block, UNDO
from transport import control

COMMON=("tip","height","work","anchor","header","issued","fees","notes","spent","spent_set_sha256","network","genesis")


def require(ok,why):
    if not ok:
        raise ValueError("walkthrough: "+why)


def exercise(lab):
    if lab.home.exists() and any(lab.home.iterdir()):
        raise ValueError("walkthrough requires an empty home; existing networks are preserved")
    os.umask(0o077)
    started=time.time()
    balances={}
    payments={}
    snapshots={}
    evidence=lab.home/"evidence"
    blocks=evidence/"blocks"
    def command(*args):
        cmd=[sys.executable,"-IB",str(HERE/"cli.py"),"--home",str(lab.home),"--runtime",str(lab.runtime),*map(str,args)]
        return json.loads(subprocess.check_output(cmd))
    def sync(nodes,height):
        def statuses():
            return {n:lab.status(n) for n in nodes}
        states=wait(statuses,lambda ss: all(s["height"]==height for s in ss.values())
                    and len({tuple(s[k] for k in COMMON) for s in ss.values()})==1,
                    f"state agreement at height {height} among {nodes}",240)
        return states
    def packet(src,txid):
        data=lab.request(src,"tx",id=txid)[1]
        require(hashlib.sha256(data).hexdigest()==txid,"packet identity")
        return data
    def pools(nodes,count):
        wait(lambda:[lab.request(n,"pending")[0] for n in nodes],
             lambda xs:all(len(x)==count and set(x)==set(xs[0]) for x in xs),"independent mempools")
    def money(which,expected,node="c"):
        result=command("balance",which,"--node",node)
        require(result["balance"]==expected,f"{which} expected {expected}, got {result['balance']}")
        balances.setdefault(which,[]).append(result)
        return result
    def capture(n):
        ids=lab.request(n,"selected",start=1,limit=128)[0]
        for ident in ids:
            path=blocks/(ident+".bin")
            if not path.exists():
                raw=lab.request(n,"block",id=ident)[1]
                require(block_id(raw).hex()==ident,"public block identity")
                path.write_bytes(raw)
        return ids
    def check_top(n,width,reward,offered):
        s=lab.status(n)
        b=decode_block(lab.request(n,"block",id=s["tip"])[1])
        require(len(b.packets)==width and b.amount==reward,"mined payment width or reward")
        ids=[hashlib.sha256(p).hexdigest() for p in b.packets]
        require(set(ids)==set(offered),"mined the independently submitted payment(s)")
        return ids
    def rejected(n,op,body,reasons):
        before=lab.status(n)
        try:
            lab.request(n,op,body)
        except ValueError as e:
            require(str(e) in reasons,"unexpected rejection "+str(e))
            reason=str(e)
        else:
            raise ValueError("walkthrough: accepted invalid operation "+op)
        after=lab.status(n)
        require(all(before[k]==after[k] for k in (*COMMON,"mempool")),"non-atomic rejection")
        return reason
    try:
        initial=lab.start(manual=True)
        blocks.mkdir(parents=True)
        require(len({s["pid"] for s in initial.values()})==3,"separate processes")
        require(all(s["height"]==s["issued"]==s["spent"]==s["notes"]==s["mempool"]==0 for s in initial.values()),"zero premine")
        for w in ("recipient","orphan-miner"):
            lab.new_wallet(w)
        lab.mine("a")
        sync("abc",1)
        lab.mine("b")
        snapshots["funded"]=sync("abc",2)
        money("miner-a",100)
        money("miner-b",100)
        money("recipient",0)
        # A prospective sole payer can submit directly to a validator with both miners disconnected.
        for n in "abc":
            lab.links(n,[])
        payments["lone"]=command("send","miner-a","recipient",37)
        one=payments["lone"]
        require(one["input_total"]==100 and one["change"]==60 and one["fee"]==3,"user amount/change")
        pools("ab",0)
        pools("c",1)
        # A different genuine proof spending the same reward must be rejected without changing the pool.
        _,hist=lab.snapshot("c")
        with lab.wallet("miner-a") as w:
            w.scan(*hist)
            conflict=w.pay(36,lab.address("recipient"))
        conflict_reason=rejected("c","submit",conflict,{"pool conflict"})
        for n in "abc":
            lab.links(n,[p for p in "abc" if p!=n])
        pools("abc",1)
        lab.mine("b")
        snapshots["lone"]=sync("abc",3)
        check_top("a",1,103,[one["tx"]])
        spent_reason=rejected("a","submit",conflict,{"spent nullifier"})
        money("recipient",37)
        with tempfile.TemporaryDirectory(dir=lab.home) as tmp:
            seed=Path(tmp)/"seed.backup"
            command("backup","recipient",seed)
            command("restore","recovered",seed)
        require(lab.address("recipient")==lab.address("recovered"),"seed-only address restoration")
        money("recovered",37)
        payments["restored"]=command("send","recovered","miner-a",11,"--node","a")
        # Two independently mined rewards deliberately require both inputs for this amount.
        payments["independent"]=command("send","miner-b","miner-a",124,"--node","b")
        second=payments["independent"]
        require(second["real_inputs"]==2 and second["input_total"]==203 and second["change"]==76,"two-input amount/change")
        pools("abc",2)
        lab.mine("a")
        snapshots["multi"]=sync("abc",4)
        order=check_top("b",2,106,[payments["restored"]["tx"],second["tx"]])
        money("miner-a",301)
        money("miner-b",76)
        money("recovered",23)
        common=lab.status("a")["tip"]
        for n,neighbors in (("a",[]),("b",["c"]),("c",["b"])):
            lab.links(n,neighbors)
        # Both operators start independent real searches from H4, with no test-selected branch.
        lab.mining("b",11)
        lab.mine("a",1,"orphan-miner")
        money("orphan-miner",100,"a")
        payments["detached"]=command("send","orphan-miner","recipient",13,"--node","a")
        lab.mine("a")
        check_top("a",1,103,[payments["detached"]["tx"]])
        orphan_packet=packet("a",payments["detached"]["tx"])
        money("recovered",36,"a")
        lab.mine("a",8)
        wait(lambda:lab.status("b"),lambda s:s["remaining"]==0,"second miner",900)
        snapshots["before_rejoin"]={n:lab.status(n) for n in "abc"}
        a,b=(snapshots["before_rejoin"][n] for n in "ab")
        require(a["height"]==14 and b["height"]==15 and a["fees"]==12 and b["fees"]==9,"competing branch accounting")
        losing,winning=capture("a"),capture("b")
        require(losing[:4]==winning[:4] and losing[3]==common and losing[4]!=winning[4],"fork after H4")
        for n in "abc":
            lab.links(n,[p for p in "abc" if p!=n])
        final=sync("abc",15)
        require(final["a"]["tip"]==winning[-1] and final["a"]["deep_replays"]>=1 and 14-4>UNDO,"automatic deep reorganization")
        require(final["a"]["issued"]==1500 and final["a"]["fees"]==9 and final["a"]["spent"]==6,"winner monetary state")
        orphan_reason=rejected("a","submit",orphan_packet,{"anchor age","anchor branch"})
        money("orphan-miner",0,"a")
        money("recovered",23,"a")
        # No chain data or trusted tip is imported into D.
        s=lab.launch("d")
        require(s["height"]==s["issued"]==0 and not s["peers"],"new unfunded node")
        lab.links("d",["b"])
        final=sync("abcd",15)
        require(final["d"]["deep_replays"]==0,"fresh sequential replay")
        lab.admin("a","stop")
        wait(lambda:not control(lab.home,"a").exists(),bool,"A shutdown")
        lab.launch("a")
        final=sync("abcd",15)
        # Publication allowlist. Only public blocks, identifiers, timings and known fixture totals leave the lab.
        mining={n:[json.loads(line) for line in (lab.home/"nodes"/n/"mined.jsonl").read_text().splitlines()] for n in "ab"}
        all_events={e["tip"]:e for events in mining.values() for e in events}
        times=[all_events[x]["found_unix"] for x in winning]
        intervals=[round(b-a,6) for a,b in zip(times,times[1:])]
        chosen=[decode_block((blocks/(x+".bin")).read_bytes()) for x in winning]
        sizes=[(blocks/(x+".bin")).stat().st_size for x in winning]
        result=dict(protocol="PQDEVBL1",source_base="46932763d7a0e6d03ea848ae2e22ab65ef48d5df",
            runtime_sha256=lab.native.binary_sha,work_bits=22,genesis=initial["a"]["genesis"],
            elapsed_s=time.time()-started,balances=balances,payments=payments,states=snapshots,final=final,
            reorg=dict(common=common,detached=losing[4:],attached=winning[4:],retained_undo=UNDO),
            controls=dict(pool_conflict=conflict_reason,confirmed_conflict=spent_reason,orphan=orphan_reason),
            ordered_multi_tx=order,winning=winning,observed_blocks=mining,archive_B=sum(sizes),
            elected_payments=sum(len(x.packets) for x in chosen),blocks_by_payment_count=dict(collections.Counter(len(x.packets) for x in chosen)),
            observed_selected_intervals_s=intervals,median_observed_interval_s=statistics.median(intervals),
            mean_observed_interval_s=statistics.mean(intervals),median_search_wall_s=statistics.median(e["search_wall_s"] for e in all_events.values()),
            initial_pids={n:s["pid"] for n,s in initial.items()})
        (evidence/"RESULT.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
        return dict(result=str(evidence/"RESULT.json"),tip=winning[-1],height=15,issued=1500,fees=9,
                    selected_payments=result["elected_payments"],selected_block_bytes=sum(sizes),deep_detached=len(losing)-4)
    finally:
        lab.stop()
