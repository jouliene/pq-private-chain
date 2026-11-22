"""Exercise two online partial fills, one full swap and a heavier competing branch through pqd."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from prepare import ROOT,ROLES,agree,cli,load_lab,need
sys.path.insert(0,str(HERE.parent/"stranger-swap"))
from lab_hosts import Service,free_ports
from link import CiphertextLink


def market(home, role, action, *args, success=True):
    argv=[ROOT/"pqd","market","--home",home/"participants"/role,action,role,*map(str,args)]
    p=subprocess.run(argv,capture_output=True,text=True,timeout=300)
    try:
        result=json.loads(p.stdout)
    except ValueError:
        raise RuntimeError(f"invalid {action} result: "+p.stderr[-700:]) from None
    if success is not None:
        need((p.returncode==0)==success,f"unexpected {role} {action} result: "+str(result.get("error","exit "+str(p.returncode))))
    return result


def subset(row, keys):
    return {k:row[k] for k in keys}


class Demo:
    def __init__(self,home,stack):
        self.home,self.stack=home,stack
        self.lab=load_lab(home)
        self.funding=json.loads((home/"funding.json").read_bytes())
        self.a,self.b=self.funding["asset_a"],self.funding["asset_b"]
        self.policy=("--give",self.a,"--take",self.b,"--lot","10","--price","1","--fee","3")
        self.out=dict(funding=self.funding,inventory={},wallets={},fills={},controls={},wire={})
        self.services={}
        self.logs=home/"local-services"
        self.logs.mkdir(exist_ok=True)

    def service(self,role,action,*args):
        place=self.home/"participants"/role
        logfile=self.logs/(role+"-"+action+".log")
        srv=Service([ROOT/"pqd","market","--home",place,action,role,*map(str,args)],logfile)
        self.stack.callback(srv.stop)
        ready=srv.ready(75)
        self.services[role]=srv
        return ready

    def start(self):
        self.lab.start(manual=True)
        self.stack.callback(self.lab.stop)
        agree(self.lab,self.funding["tip"])
        ports=free_ports(4)
        self.endpoints=dict(zip(("seller","full-seller"),(f"127.0.0.1:{p}" for p in ports[2:]),strict=True))
        self.link=self.stack.enter_context(CiphertextLink(ports[2]))
        self.listen=self.endpoints["seller"]
        self.endpoints["seller"]=f"127.0.0.1:{self.link.port}"
        relays=[f"127.0.0.1:{p}" for p in ports[:2]]
        for i,addr in enumerate(relays):
            s=Service([ROOT/"pqd","market","relay","--listen",addr],self.logs/f"relay-{i}.log")
            self.stack.callback(s.stop)
            s.ready()
        for role in ROLES:
            path=self.home/"participants"/role/"network.json"
            config=json.loads(path.read_bytes())
            config["market_relays"]=relays
            path.write_text(json.dumps(config))

    def offer(self,role):
        listen=("--listen",self.listen) if role=="seller" else ()
        ready=self.service(role,"offer",*self.policy,"--total",100,"--endpoint",self.endpoints[role],*listen)
        need(all(m["ok"] for m in ready["discovery"]),"directory did not accept listing")
        return ready["offer"],ready["advert"]

    def discover(self,role,order,advert,available):
        directory=market(self.home,role,"discover","--partial")
        need(advert in directory["makers"] and all(m["ok"] for m in directory["discovery"]),"missing advertised maker")
        seen=market(self.home,role,"inspect-offer",advert)
        need((seen["offer"],seen["asset"],seen["take"],seen["total"],seen["lot"],seen["price"],seen["fee"],
              seen["available"],seen["payer"])==(order,self.a,self.b,100,10,1,3,available,"a"),"wrong private offer")
        self.out.setdefault("discovery",[]).append(dict(role=role,available=available,
            directory_request_B=sum(m["request_B"] for m in directory["discovery"]),
            directory_reply_B=sum(m["reply_B"] for m in directory["discovery"]),
            inspect_request_B=sum(m["wire_request_B"] for m in seen["private_transport"]),
            inspect_reply_B=sum(m["wire_reply_B"] for m in seen["private_transport"])))
        return seen

    def reserve(self,role,order,ad,amount,success=True):
        row=market(self.home,role,"reserve",ad,"--offer",order,*self.policy,"--quantity",amount,success=success)
        if "error" not in row:
            need((row["offer"],row["quantity"],row["payment"],row["payer"])==(order,amount,amount//10,"a"),
                 "wallet accepted inconsistent fill")
        return row

    def fill(self,role,q,*extra,success=True):
        return market(self.home,role,"fill",q["quote"],"--offer",q["offer"],*self.policy,"--quantity",q["quantity"],
                      "--expiry",q["expiry_height"],*extra,success=success)

    def status(self,label,seller,offer,expected):
        r=market(self.home,seller,"offer-status",offer)
        need(r["tip"]==self.lab.status("c")["tip"],"inventory observed another branch")
        keys=("remaining","available","reserved","exposed","confirmed")
        need(tuple(r[k] for k in keys)==expected,f"{label} inventory: "+str(subset(r,keys)))
        self.out["inventory"][label]=subset(r,("tip","height","closed",*keys))

    def balances(self,label,values):
        rows={}
        for role,(a,b,native) in values.items():
            r=cli(self.home/"participants"/role,"c","balance",role)
            expected={asset:qty for asset,qty in ((self.a,a),(self.b,b)) if qty}
            need(r["assets"]==expected and r["balance"]==native,f"wrong controlled wallet holdings for {role} at {label}")
            rows[role]=dict(A=a,B=b,native=native)
        self.out["wallets"][label]=rows

    def mine_swap(self,label,raw,fee_before,common):
        from chain import decode_block
        from swap_wire_c import split,pair
        frames=split(raw)
        a,b=pair(frames)
        need(a.payer==b.payer==0 and a.leg.startswith(b"SLG3") and b.leg.startswith(b"SLG3"),"wrong swap registration")
        mined=self.lab.mine("c",1,pay_to="miner-a")
        blockraw=self.lab.request("c","block",id=mined["tip"])[1]
        block=decode_block(blockraw)
        need(tuple(frames)==block.packets and block.amount==103 and mined["fees"]==fee_before+3,
             "incorrect atomic inclusion or fee at "+label)
        if common:
            agree(self.lab,mined["tip"])
        row=dict(bundle_sha256=sha256(raw).hexdigest(),block=mined["tip"],height=block.height,packet_B=len(raw),
                 legs_B=[len(a.leg),len(b.leg)],physical_frames_B=list(map(len,frames)),
                 block_B=len(blockraw),packet_list_B=1+sum(4+len(f) for f in frames),fee=3,reward=block.amount)
        self.out["fills"][label]=row
        return row

    def wire(self,label,*rows):
        meters=[meter for row in rows for meter in row["private_transport"]]
        need(all(m["authenticated"] for m in meters) and len(meters)>=2,"missing secure transport counts")
        self.out["wire"][label]=dict(encrypted_to_maker_B=sum(m["wire_request_B"] for m in meters),
            encrypted_to_buyer_B=sum(m["wire_reply_B"] for m in meters),connections=len(meters),
            submit_request_B=rows[-1]["submit"]["request_B"],submit_reply_B=rows[-1]["submit"]["reply_B"])

    def run(self):
        self.start()
        order,ad=self.offer("seller")
        for role in ("buyer-one","buyer-two","full-buyer"):
            self.discover(role,order,ad,100)
        self.out["controls"]["independent_discovery_same_private_order"]=True
        fees=self.funding["fees"]
        bad=self.reserve("buyer-one",order,ad,15,False)
        need("lot" in bad["error"],"non-lot quantity rejection")
        # Occupy 90 A from its own funded note. Both other wallets race for the actual last 10-A lot.
        ninety=self.reserve("full-buyer",order,ad,90)
        self.status("last_ten_open","seller",order,(100,10,90,0,0))
        with ThreadPoolExecutor(max_workers=2) as pool:
            contenders=("buyer-one","buyer-two")
            race=dict(zip(contenders,pool.map(lambda r:self.reserve(r,order,ad,10,None),contenders),strict=True))
        wins=[r for r in contenders if "error" not in race[r]]
        need(len(wins)==1,"last-lot winner count: "+str(len(wins)))
        loser=next(r for r in contenders if r!=wins[0])
        # A simultaneous TLS request may hit the one-active-request service gate before wallet accounting.
        # Demand a definite inventory refusal once the winner is durably reserved.
        denied=self.reserve(loser,order,ad,10,False)
        need(denied["error"]=="maker declined this reservation","capacity refusal after contention: "+denied["error"])
        self.status("last_ten_reserved","seller",order,(100,0,100,0,0))
        for owner,handle in ((wins[0],race[wins[0]]),("full-buyer",ninety)):
            need(market(self.home,owner,"cancel-fill",handle["quote"])["remote"]=="cancelled","unsigned cancel")
        self.status("race_released","seller",order,(100,100,0,0,0))
        self.out["controls"]["last_lot"]=dict(lot_A=10,competing_buyers=2,accepted=1,rejected=1,initial_hold_A=90)
        q20=self.reserve("buyer-one",order,ad,20)
        wrong=self.fill("buyer-one",{**q20,"quantity":30},"--prepare-only",success=False)
        need("differ" in wrong["error"],"changed buyer instruction was not rejected")
        self.fill("buyer-one",q20,"--prepare-only")
        self.status("twenty_prepared","seller",order,(100,80,20,0,0))
        cancelled=market(self.home,"buyer-one","cancel-fill",q20["quote"])
        need(cancelled["remote"]=="cancelled","unsigned funded reservation did not cancel")
        self.status("twenty_cancelled","seller",order,(100,100,0,0,0))
        self.out["controls"].update(non_lot_rejected=True,alternate_prepared=dict(A=20,B=2),
                                   alternative_zero_fees=self.lab.status("c")["fees"]==fees)
        need(self.out["controls"]["alternative_zero_fees"],"unused reservation charged")
        q1=self.reserve("buyer-one",order,ad,50)
        complete=self.fill("buyer-one",q1)
        raw1=Path(complete["packet"]).read_bytes()
        self.wire("first",q1,complete)
        self.mine_swap("first",raw1,fees,True)
        self.status("first_confirmed","seller",order,(50,50,0,0,50))
        self.balances("first",{"seller":(50,5,0),"buyer-one":(50,0,0),"buyer-two":(0,5,3)})
        self.discover("buyer-two",order,ad,50)
        q2=self.reserve("buyer-two",order,ad,50)
        self.status("last_reserved","seller",order,(50,0,50,0,50))
        # Save the common point. The two arms will pick their own blocks and work.
        for n in "abc":
            self.lab.links(n,[])
        common=self.lab.status("a")
        before=self.link.snapshot()
        self.link.arm()
        missing=self.fill("buyer-two",q2,"--sign-only",success=False)
        lost=self.link.snapshot()
        delta={k:lost[k]-before[k] for k in ("connections","maker_received","maker_forwarded","maker_withheld",
                                             "client_forwarded","drops")}
        need(delta["drops"]==1 and delta["maker_withheld"]>0 and "error" in missing,"expected a lost final reply")
        pending=market(self.home,"buyer-two","fill-status",q2["quote"])
        need(pending["state"]=="released" and pending["delivery"]=="attempted","buyer did not retain ambiguity")
        self.status("signed_before_restart","seller",order,(50,0,0,50,50))
        self.services["seller"].stop()
        resumed=self.service("seller","serve-offer",order)
        need(resumed["offer"]==order,"restart changed the maker order")
        self.status("restart","seller",order,(50,0,0,50,50))
        refused=market(self.home,"buyer-two","cancel-fill",q2["quote"],success=False)
        need("released" in refused["error"],"signed cancellation should disclose exposure")
        close=market(self.home,"seller","cancel-offer",order)
        need(close["closed"] and close["exposed"]==50,"closing the offer revoked or lost a signature")
        claim=market(self.home,"seller","recover-fill",order,q2["quote"],"--submit")
        raw2=Path(claim["packet"]).read_bytes()
        retry=market(self.home,"seller","recover-fill",order,q2["quote"],"--submit")
        need(claim["ack"]==retry["ack"]==sha256(raw2).hexdigest() and self.lab.request("c","pending")[0]==[claim["ack"]],
             "signed recovery or idempotent in-flight submission")
        self.services["seller"].stop()
        self.out["wire"]["second"]=dict(encrypted_to_maker_B=sum(x["wire_request_B"] for x in q2["private_transport"])+delta["client_forwarded"],
            encrypted_from_maker_B=sum(x["wire_reply_B"] for x in q2["private_transport"])+delta["maker_received"],
            encrypted_to_buyer_B=sum(x["wire_reply_B"] for x in q2["private_transport"])+delta["maker_forwarded"],
            withheld_B=delta["maker_withheld"],connections=len(q2["private_transport"])+delta["connections"],
            submit_request_B=claim["submit"]["request_B"],submit_reply_B=claim["submit"]["reply_B"])
        self.mine_swap("second_before_reorg",raw2,fees+3,False)
        recovered=self.fill("buyer-two",q2)
        need(recovered["state"]=="confirmed" and recovered["recovered"] and recovered["private_transport"]==[]
             and "submit" not in recovered and recovered["ack"]==claim["ack"]
             and Path(recovered["packet"]).read_bytes()==raw2,"buyer did not recover exact selected settlement offline")
        self.out["controls"]["lost_final_reply"]=dict(receiver_state=pending["state"],withheld_B=delta["maker_withheld"],
            seller_recovered_signed_packet=True,buyer_recovered_from_validated_chain=True,maker_offline=True)
        self.status("second_confirmed","seller",order,(0,0,0,0,100))
        self.balances("second",{"seller":(0,10,0),"buyer-one":(50,0,0),"buyer-two":(50,0,0)})
        alt=self.lab.mine("a",2,pay_to="miner-b")
        need(alt["height"]==common["height"]+2 and alt["fees"]==fees+3,"unexpected competing branch economics")
        for n in "abc":
            self.lab.links(n,[k for k in "abc" if k!=n])
        agree(self.lab,alt["tip"])
        self.status("second_detached","seller",order,(50,0,0,50,50))
        self.balances("detached",{"seller":(50,5,0),"buyer-one":(50,0,0),"buyer-two":(0,5,3)})
        need(self.lab.status("c")["fees"]==fees+3,"orphan retained fee")
        selected=self.fill("buyer-two",q2)
        need(selected["ack"]==claim["ack"],"replay changed previously authorized pair")
        self.mine_swap("second_reconfirmed",raw2,fees+3,True)
        self.status("reconfirmed","seller",order,(0,0,0,0,100))
        self.out["controls"].update(signed_cancellation_refused=True,closed_offer_honors_prior_signature=True,
            duplicate_pending_idempotent=True,orphan_fee_reversed=True,exact_packet_reincluded=True)
        # Equal notional, independent funding and the same lot/fee policy on the same selected C branch.
        fo,fa=self.offer("full-seller")
        self.discover("full-buyer",fo,fa,100)
        fq=self.reserve("full-buyer",fo,fa,100)
        settled=self.fill("full-buyer",fq)
        self.wire("full",fq,settled)
        self.mine_swap("full",Path(settled["packet"]).read_bytes(),fees+6,True)
        self.status("full_confirmed","full-seller",fo,(0,0,0,0,100))
        self.balances("final",{"seller":(0,10,0),"buyer-one":(50,0,0),"buyer-two":(50,0,0),
                               "full-seller":(0,10,0),"full-buyer":(100,0,0)})
        before=self.lab.status("c")
        try:
            self.lab.request("c","submit",raw2)
        except ValueError as e:
            need("spent" in str(e) or "commitment" in str(e),"unexpected confirmed duplicate refusal: "+str(e))
        else:
            raise ValueError("already spent confirmed bundle admitted")
        after=self.lab.status("c")
        need(after["tip"]==before["tip"] and after["spent_set_sha256"]==before["spent_set_sha256"]
             and self.lab.request("c","pending")[0]==[] and after["fees"]==fees+9,"duplicate affected ledger")
        self.out["controls"]["confirmed_duplicate_no_effect"]=True
        self.out["selected"]=subset(after,("tip","height","fees","issued","spent","spent_set_sha256"))
        for leg,labels in (("two_partial",("first","second_reconfirmed")),("one_full",("full",))):
            self.out.setdefault("comparison",{})[leg]={k:sum(self.out["fills"][i][k] for i in labels)
                for k in ("packet_B","packet_list_B","block_B","fee")}
        return self.out


def main():
    os.umask(0o077)
    home,result=map(lambda s:Path(s).resolve(),sys.argv[1:])
    with ExitStack() as stack:
        report=Demo(home,stack).run()
    result.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print(json.dumps(report["comparison"]),flush=True)


if __name__=="__main__":
    main()
