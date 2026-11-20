"""Exercise old funded notes, private managed supply and an irreversible simulated payout on real PoW forks."""
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
HOME = Path(sys.argv[1]).resolve()
sys.path[:0] = [str(HOME/"deployment/devnet"),str(HERE)]
from chain import GENESIS, NETWORK, PROFILE, WINDOW, block_id, decode_block
from cli import Lab, wait
from managed_inventory import inventory
from managed_ops import parse
from legacy_prefix import prepare

LAB = Lab(HOME, HOME/"deployment/runtime")
PUBLIC = HOME/"public"
OWNERS = ("miner-a","miner-b","treasury","fixed-user","recovered","fork-miner","winning-miner")
FIELDS = ("network","genesis","tip","height","work","anchor","header","notes","spent","spent_set_sha256","issued","fees")
REQUEST = "redemption-001"


def need(test, msg):
    if not test:
        raise ValueError(msg)


def command(*args, refusal=None, code=None):
    result = subprocess.run([ROOT/"pqd","managed","--home",HOME,*map(str,args)],capture_output=True,text=True,timeout=420)
    if code is not None:
        need(result.returncode==code,"unexpected exit from "+str(args[0])+": "+result.stderr[-500:])
        return code
    if refusal:
        need(result.returncode and refusal in result.stderr,"missing refusal: "+result.stderr[-500:])
        return refusal
    if result.returncode:
        raise RuntimeError(str(args[0])+" failed: "+result.stderr[-700:])
    return json.loads(result.stdout)


def state(node):
    st=LAB.status(node)
    return {k:st[k] for k in FIELDS}


def converge(nodes):
    return wait(lambda:[state(n) for n in nodes],lambda states:all(s==states[0] for s in states),
                "valid work convergence "+nodes)[0]


def retained(node, tip):
    while tip!=GENESIS.hex():
        file=PUBLIC/"blocks"/(tip+".bin")
        if file.exists():
            break
        raw=LAB.request(node,"block",id=tip)[1]
        need(block_id(raw).hex()==tip,"block identity")
        file.write_bytes(raw)
        b=decode_block(raw)
        for packet in b.packets:
            (PUBLIC/"packets"/(sha256(packet).hexdigest()+".bin")).write_bytes(packet)
        tip=b.parent.hex()


def funds(row):
    return dict(native=row["balance"],assets=row["assets"])


def address(name):
    return "@"+str(HOME/(name+".addr"))


class Trial:
    def __init__(self):
        self.r=dict(network=NETWORK.hex(),genesis=GENESIS.hex(),vk=PROFILE.hex(),tips={},registries={},balances={},
                    payments={},controls={},payout={},miner_keys={})

    def snapshot(self,label,node,owners):
        st=state(node)
        self.r["tips"][label]=st
        self.r["registries"][label]=inventory(LAB,node,st["tip"])
        self.r["balances"][label]={k:funds(command("balance",k,"--node",node)) for k in owners}
        retained(node,st["tip"])

    def observe(self,node,tx):
        return LAB.request(node,"supply-observation",txs=[tx])[0]["events"][0]

    def selected(self,tx,node,depth):
        return all(e and e["confirmations"]>=depth for e in [self.observe(n,tx) for n in ("abc" if node=="c" else node)])

    def pay(self,label,payer,payee,args,*,node="c",settle=True,resume=None):
        intent=resume or label
        cli=("resume",payer,intent) if resume else (*args,"--intent",intent)
        result=command(*cli,"--node",node,"--wait",180 if settle else 0)
        if settle:
            for attempt in range(4):
                tx=result["tx"]
                end=time.monotonic()+100
                while time.monotonic()<end:
                    if self.selected(tx,node,3):
                        break
                    if state(node)["height"]>result["anchor_height"]+WINDOW+3:
                        break
                    time.sleep(.28)
                if self.selected(tx,node,3):
                    break
                need(attempt<3,"payment failed to settle "+label)
                result=command("resume",payer,intent,"--node",node,"--wait",180)
        row={k:result[k] for k in ("tx","amount","asset_id","token_amount","issue_supply","input_total","token_input_total",
                                  "change","token_change","fee","real_inputs","packet_B","anchor_height","prover_cpu_s",
                                  "prover_role_peak_rss_KiB","proving_wall_s","operation","minted","burned")}
        row.update(payer=payer,payee=payee,output_count=2,
                   wallet_native_meters=[m for m in result["wallet_metrics"] if m["operation"] in ("wallet_setup","compact_prove")])
        self.r["payments"][label]=row
        return row

    def node_refuses(self,node,name,packet,want):
        before=state(node)
        pool=LAB.status(node)["mempool"]
        try:
            LAB.request(node,"submit",packet)
        except ValueError as exc:
            need(str(exc)==want,"wrong rejection for "+name+": "+str(exc))
        else:
            raise ValueError(name+" accepted")
        need(before==state(node) and pool==LAB.status(node)["mempool"],"state changed after rejection")
        self.r["controls"][name]=dict(reason=want,unchanged=True,packet_sha256=sha256(packet).hexdigest())
        (PUBLIC/"controls"/(name+".bin")).write_bytes(packet)

    def policy_checks(self,ids):
        from managed_wallet import Request
        from wallet_sync import synced_wallet

        r=self.r
        node="c"
        self.node_refuses(node,"duplicate-mint",LAB.request(node,"tx",id=r["payments"]["mint"]["tx"])[1],"stale issuer state")
        before=state(node)
        reason=command("mint","miner-b",address("miner-b"),ids["USD"],1,"--intent","foreign-mint","--node",node,
                       refusal="wrong issuer authority")
        directory=LAB.walletdir("miner-b")
        with sqlite3.connect((directory/"mng1-intents.sqlite").as_uri()+"?mode=ro",uri=True) as db:
            packet=db.execute("SELECT packet FROM attempts WHERE intent='foreign-mint' ORDER BY rowid DESC LIMIT 1").fetchone()[0]
        self.node_refuses(node,"unregistered-authority",packet,reason)
        fixed=r["registries"]["common"][ids["FIX"]]
        request=Request(0,bytes.fromhex(ids["FIX"]),1,1,"mint",sequence=fixed["sequence"],previous=bytes.fromhex(fixed["tx"]))
        # The ordinary CLI declines fixed mints locally. This control submits an actual signed native proof
        # with fresh lawful fee inputs to exercise the node's independently enforced immutable policy.
        with LAB.locked_wallet("miner-a") as directory, LAB.wallet("miner-a") as w:
            with synced_wallet(LAB,node,w,directory) as (wallet,_):
                pins=wallet.select(request)
                packet=wallet.pay(request,w.address,pins)
        self.node_refuses(node,"mint-fixed",packet,"immutable fixed supply")
        r["controls"]["foreign-return"]=command("burn","fixed-user",ids["USD"],200,r["payments"]["return"]["tx"],
                                               "--node",node,"--intent","foreign-burn",
                                               refusal="expected one unspent incoming return")
        need(before==state(node) and not LAB.status(node)["mempool"],"controls changed selected state")

    def run(self):
        legacy=prepare(HOME)
        (PUBLIC/"controls").mkdir(exist_ok=False)
        need(not (HOME/"nodes").exists(),"managed walkthrough requires unused node stores")
        for n in ("miner-a","miner-b"):
            seed=HOME/"legacy-backups"/(n+".seed")
            LAB.install_wallet(n,seed.read_bytes())
        original=LAB.start(manual=True)
        for bid in legacy["blocks"]:
            packet=(PUBLIC/"blocks"/(bid+".bin")).read_bytes()
            LAB.request("c","publish",packet)
        wait(lambda:converge("abc"),lambda s:s["tip"]==legacy["tip"],"historical AST1 selected tip")
        for n in (*OWNERS,"offline"):
            if n=="recovered":
                continue
            if n not in ("miner-a","miner-b"):
                command("create",n)
            command("export-address",n,HOME/(n+".addr"))
        self.r["miner_keys"]={n:LAB.address(n)[1:33].hex() for n in ("miner-a","miner-b","fork-miner","winning-miner")}
        seed=HOME/"offline-backup"
        command("backup","offline",seed)
        need(seed.stat().st_size==32,"offline seed")
        fixed=legacy["payment"]
        self.r["payments"]["fixed"]=dict(fixed,payer="miner-a",payee="miner-a",operation="fixed",minted=17,burned=0)
        self.snapshot("upgrade","c",["miner-a","miner-b"])
        f=fixed["asset_id"]
        need(self.r["balances"]["upgrade"]["miner-a"]["assets"]=={f:17},"old funded notes lost")
        for n in "ab":
            LAB.mining(n,-1)
        self.pay("fixed-pay","miner-a","fixed-user",("send","miner-a",address("fixed-user"),0,f,5))
        self.pay("fund-treasury","miner-a","treasury",("send","miner-a",address("treasury"),30,"native",0))
        reg=self.pay("register","treasury","treasury",("register","treasury",1000))
        usd=reg["asset_id"]
        mint=self.pay("mint","treasury","treasury",("mint","treasury",address("treasury"),usd,300))
        self.r["asset_ids"]={"USD":usd,"FIX":f}
        self.pay("deliver","treasury","offline",("send","treasury",address("offline"),12,usd,400))
        need(not (LAB.walletdir("offline")/"mng1-wallet-state.sqlite").exists() and not LAB.walletdir("recovered").exists(),"recipient unexpectedly online")
        self.r["offline_restore"]=funds(command("restore","recovered",seed))
        need(self.r["offline_restore"]==dict(native=12,assets={usd:400}),"cold private receipt")
        returned=self.pay("return","recovered","treasury",("send","recovered",address("treasury"),3,usd,200))
        p=self.r["payout"]
        p["enrolled"]=command("redeem","enroll",REQUEST,"treasury",usd,200,returned["tx"],"test-customer")
        self.r["continuous"]={n:{k:LAB.status(n)[k] for k in ("found","remaining")} for n in "ab"}
        need(all(v["remaining"]==-1 for v in self.r["continuous"].values()),"miners not autonomous")
        for n in "ab":
            LAB.mining(n,0)
        common=converge("abc")
        self.snapshot("common","c",OWNERS)
        need(self.r["registries"]["common"][usd]["supply"]==1300 and reg["asset_id"]==mint["asset_id"],"managed mint")
        self.policy_checks(self.r["asset_ids"])
        for n,peers in (("a",[]),("b",["c"]),("c",["b"])):
            LAB.links(n,peers)
        LAB.mining("b",-1,"winning-miner")
        LAB.mine("a",1,"fork-miner")
        burn=self.pay("branch-burn","treasury","treasury",("burn","treasury",usd,200,returned["tx"]),node="a",settle=False)
        LAB.mine("a",1,"fork-miner")
        settle=("redeem","settle",REQUEST,burn["tx"],"--node","a")
        p["one_confirmation"]=command(*settle)
        need((p["one_confirmation"]["confirmations"],p["one_confirmation"]["paid"])==(1,0),"confirmation floor")
        self.node_refuses("a","duplicate-burn",LAB.request("a","tx",id=burn["tx"])[1],"spent nullifier")
        LAB.mine("a",2,"fork-miner")
        command(*settle,"--crash-after-bank",code=75)
        with sqlite3.connect((HOME/"redemptions/bank.sqlite").as_uri()+"?mode=ro",uri=True) as bank:
            rows=bank.execute("SELECT count(*),sum(amount) FROM payments WHERE request=?",(REQUEST,)).fetchone()
        with sqlite3.connect((HOME/"redemptions/requests.sqlite").as_uri()+"?mode=ro",uri=True) as db:
            ack=db.execute("SELECT acknowledged FROM requests WHERE request=?",(REQUEST,)).fetchone()[0]
        need(rows==(1,200) and ack is None,"post-bank crash boundary")
        p["crash"]=dict(exit=75,rows=rows[0],bank_paid=rows[1],local_ack=False)
        p["paid"]=command(*settle)
        p["retried"]=command(*settle)
        need(p["paid"]["bank_receipt"]==p["retried"]["bank_receipt"] and p["paid"]["confirmations"]==3
             and p["paid"]["paid"]==200 and p["paid"]["payout_count"]==1,"single simulated payout")
        LAB.mine("a",6,"fork-miner")
        self.snapshot("loser","a",OWNERS)
        loser=self.r["tips"]["loser"]
        wait(lambda:state("b")["height"],lambda h:h>=loser["height"]+2,"heavier branch")
        LAB.mining("b",0)
        winner=converge("bc")
        for n in "abc":
            LAB.links(n,[p for p in "abc" if p!=n])
        converge("abc")
        self.snapshot("winner","c",OWNERS)
        need(state("a")==winner and LAB.status("a")["deep_replays"]>0 and self.r["registries"]["winner"][usd]["supply"]==1300,
             "burn reorg")
        p["after_reorg"]=command("redeem","status",REQUEST)
        need((p["after_reorg"]["paid"],p["after_reorg"]["owed"],p["after_reorg"]["exposure"])==(200,0,200),"payout exposure")
        for n in "ab":
            LAB.mining(n,-1,"miner-"+n)
        winburn=self.pay("burn","treasury","treasury",(),resume="branch-burn")
        p["recovered"]=command("redeem","settle",REQUEST,winburn["tx"])
        need(p["recovered"]["confirmations"]>=3 and p["recovered"]["exposure"]==0 and p["recovered"]["paid"]==200
             and p["recovered"]["payout_count"]==1 and p["recovered"]["bank_receipt"]==p["paid"]["bank_receipt"],"recovery payout")
        for n in "ab":
            LAB.mining(n,0)
        final=converge("abc")
        need(not (HOME/"nodes/d/chain.sqlite").exists(),"cold node exists")
        d=LAB.launch("d")
        need(d["height"]==0 and d["issued"]==0,"cold genesis")
        LAB.links("d",["c"])
        need(converge("cd")==final,"cold replay")
        self.snapshot("final","d",OWNERS)
        r=self.r
        r["original_peers_retained"]=all(LAB.status(n)["pid"]==original[n]["pid"] for n in "abc")
        r["deep_replays"]={"a":LAB.status("a")["deep_replays"],"d":LAB.status("d")["deep_replays"]}
        r["cold_tip"]=[d["tip"],final["tip"]]
        r["legacy_tip"]=legacy["tip"]
        wallets=r["balances"]["final"]
        need(r["original_peers_retained"] and final["fees"]==24 and
             sum(x["native"] for x in wallets.values())==final["issued"]==final["height"]*100,"native account totals")
        for aid,qty in [(f,17),(usd,1100)]:
            need(sum(x["assets"].get(aid,0) for x in wallets.values())==r["registries"]["final"][aid]["supply"]==qty,"asset totals")
        need(wallets["treasury"]["assets"]=={usd:900} and wallets["recovered"]["assets"]=={usd:200}
             and wallets["fixed-user"]["assets"]=={f:5} and wallets["fork-miner"]["native"]==0,"individual balances")
        (PUBLIC/"RUN.json").write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
        return dict(outstanding=1100,paid=200,fees=final["fees"],height=final["height"],public=str(PUBLIC))


if __name__=="__main__":
    try:
        print(json.dumps(Trial().run(),indent=2))
    finally:
        if (HOME/"network.json").exists():
            LAB.stop()
