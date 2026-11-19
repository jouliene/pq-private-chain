"""Acceptance for the ordinary APV2 wallet on real PoW branches. Only public test metrics are exported."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/"wallet-review"))
from wire_meter import Meter, summary
from cli import Lab, wait
from wallet import private_directory
from chain import block_id, decode_block, WINDOW


def check(condition,message):
    if not condition:
        raise ValueError("wallet walkthrough: "+message)


def args_for(client,*args):
    return [sys.executable,"-IB",str(HERE/"cli.py"),"--home",str(client.home),
            "--runtime",str(client.runtime),*map(str,args)]


def run_cli(client,*args):
    with tempfile.TemporaryDirectory() as temp:
        costs=Path(temp)/"time"
        started=time.monotonic()
        cmd=["/usr/bin/time","-f","%U %S %M","-o",str(costs),*args_for(client,*args)]
        proc=subprocess.run(cmd,capture_output=True,timeout=480)
        if proc.returncode:
            raise ValueError(f"{args[0]} failed: "+proc.stderr.decode(errors="replace")[-800:])
        cpu_user,cpu_system,peak=costs.read_text().split()
        return json.loads(proc.stdout),dict(wall_s=time.monotonic()-started,user_cpu_s=float(cpu_user),
            system_cpu_s=float(cpu_system),peak_rss_kib=int(peak))


class FaultRelay(Meter):
    """Faults alter delivery only. The daemon and wallet always use their normal cryptographic paths."""
    def __init__(self,port):
        super().__init__(port)
        self.cut_before_submit=False
        self.stalled_page=threading.Event()
        self.release_page=threading.Event()
        self.cut_restore=False
        self.page_count=0
        self.first_target=None
        self.second_start=None
        self.packets={}
        self.history_requests=[]
    def before(self,op,params,body):
        if op in ("history_head","history_range","history_check"):
            self.history_requests.append((op,params.copy()))
        if op=="submit":
            self.packets[hashlib.sha256(body).hexdigest()]=bytes(body)
            if self.cut_before_submit:
                self.cut_before_submit=False
                return True
        if op=="history_range" and self.cut_restore:
            self.page_count+=1
            if self.page_count==1:
                self.first_target=params["target"]
            if self.page_count==2:
                self.second_start=params["start"]
                self.stalled_page.set()
                self.release_page.wait(40)
                return True
        return False


def client_at(path,runtime,ports):
    private_directory(path,create=True)
    (path/"network.json").write_text(json.dumps(dict(version=1,ports=ports)))
    return Lab(path,runtime)


def same_heads(lab,nodes,height=None):
    def read():
        return [lab.status(n) for n in nodes]
    return wait(read,lambda xs:len({x["tip"] for x in xs})==1 and
                (height is None or xs[0]["height"]==height),"peer fork choice",240)[0]


def equivalent(client,node,name):
    """Rebuild all leaves and positional Merkle paths independently of the append algorithm."""
    from wallet_sync import synced_wallet
    s,full=client.snapshot(node)
    with client.wallet(name) as old:
        old_inventory=old.scan(*full)
        expected=old.history
    with client.locked_wallet(name) as private,client.wallet(name) as wallet:
        with synced_wallet(client,node,wallet,private) as (state,_):
            check(state.tip.hex()==s["tip"] and state.inventory()==old_inventory and state.history==expected,
                  "full replay inventory or cursor differs")
            leaves=[full[1][i:i+32] for i in range(0,len(full[1]),32)]
            levels=[]
            current=leaves
            while current:
                levels.append(current)
                parents=[]
                for i in range(0,len(current),4):
                    group=current[i:i+4]
                    parents.append(state.hashes.call(b"N"+b"".join(group+[bytes(32)]*(4-len(group)))))
                if len(parents)==1:
                    check(parents[0]==full[0][-32:],"independently rebuilt funded root")
                    break
                current=parents
            paths=words=0
            for row in expected:
                if row["spent"] or not row["amount"]:
                    continue
                pos,actual=state.witness(row["commitment"])
                check(leaves[pos].hex()==row["commitment"],"owned position")
                desired=[]
                for level in levels:
                    begin=pos//4*4
                    group=level[begin:begin+4]
                    group=group+[bytes(32)]*(4-len(group))
                    desired.append(tuple(group[:pos%4]+group[pos%4+1:]))
                    pos//=4
                check([tuple(r) for r in actual]==desired,"private witness differs from complete tree")
                paths+=1
                words+=3*len(desired)
            return dict(height=s["height"],funded=len(leaves),paths=paths,siblings=words,
                        owned_records=len(expected),balance=old_inventory["balance"])


def archive(lab,node,directory):
    directory.mkdir(parents=True,exist_ok=True)
    ids=[]
    h=lab.status(node)["height"]
    for start in range(1,h+1,100):
        ids.extend(lab.request(node,"selected",start=start,limit=min(100,h-start+1))[0])
    for ident in ids:
        dest=directory/(ident+".bin")
        if dest.exists():
            continue
        raw=lab.request(node,"block",id=ident)[1]
        check(block_id(raw).hex()==ident,"archived block identity")
        dest.write_bytes(raw)
    return ids


def deliberately_disconnected(client,*args):
    p=subprocess.run(args_for(client,*args),capture_output=True,timeout=240)
    check(p.returncode and b"resume saved intent" in p.stderr,"lost reply must leave a resumable intent")


def interrupt_restore(client,relay,name,seed):
    relay.cut_restore=True
    proc=subprocess.Popen(args_for(client,"restore",name,seed),stdout=subprocess.DEVNULL,
                          stderr=subprocess.PIPE,start_new_session=True)
    try:
        check(relay.stalled_page.wait(40),"restore never fetched a second page")
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid,signal.SIGKILL)
        proc.communicate(timeout=20)
        relay.cut_restore=False
        relay.release_page.set()
    return dict(target=relay.first_target,next_requested=relay.second_start)


def exercise(lab):
    from sync_scaling import scale_branch
    if lab.home.exists() and any(lab.home.iterdir()):
        raise ValueError("wallet-walkthrough requires an empty or absent home")
    os.umask(0o077)
    t=time.monotonic()
    report={"format":"PQD-WALLET-ACCEPT-1","scaling_fixture":"real mined branches","differential":{}}
    try:
        lab.start(manual=True)
        lab.new_wallet("neutral")
        evidence=lab.home/"evidence"
        evidence.mkdir()
        with ExitStack() as stack:
            tmp=Path(stack.enter_context(tempfile.TemporaryDirectory(dir=lab.home)))
            relays={n:stack.enter_context(FaultRelay(lab.cfg["ports"][n])) for n in "abc"}
            ports={n:r.port for n,r in relays.items()}
            client=client_at(lab.home/"client",lab.runtime,ports)
            target=tmp/"recipient.addr"
            offline_backup=tmp/"offline.seed"
            with tempfile.TemporaryDirectory(dir=tmp) as empty:
                offline=Lab(Path(empty),lab.runtime)
                run_cli(offline,"create","recipient")
                run_cli(offline,"export-address","recipient",target)
                run_cli(offline,"backup","recipient",offline_backup)
            sender_seed=tmp/"payer.seed"
            live_seed=tmp/"live.seed"
            lab.backup("miner-a",sender_seed)
            lab.backup("miner-b",live_seed)
            neutral_file=tmp/"miner.addr"
            lab.export_address("neutral",neutral_file)
            lab.mine("a")
            same_heads(lab,"abc",1)
            lab.mine("b")
            same_heads(lab,"abc",2)
            for n,p in (("a",[]),("b",["c"]),("c",["b"])):
                lab.links(n,p)
            cases={}
            for name,node,base in (("small","a",4),("large","b",40)):
                lab.mine(node,base-2,"neutral")
                cases[name]=scale_branch(lab,client,relays[node],node,base,name,sender_seed,target,run_cli)
                report["differential"][name]=equivalent(client,node,name)
            report["scale"]=cases
            same_heads(lab,"bc",43)
            lab.links("b",[])
            lab.links("c",[])
            lab.mine("b",1,"miner-a")
            sb,_=run_cli(client,"balance","large","--node","b")
            check(sb["balance"]==180,"shallow coinbase funding")
            report["shallow_old"]=archive(lab,"b",evidence/"blocks")[-1]
            lab.mine("c",2,"neutral")
            lab.links("b",["c"])
            lab.links("c",["b"])
            same_heads(lab,"bc",45)
            rb,_=run_cli(client,"balance","large","--node","b")
            check(rb["balance"]==80,"shallow reward rollback")
            check(rb["sync"]["rewound_blocks"]==1 and rb["sync"]["deep_resets"]==0,"expected shallow rewind")
            report["shallow"]=rb["sync"]
            report["differential"]["shallow"]=equivalent(client,"b","large")
            lab.mine("a",7,"neutral")
            short,_=run_cli(client,"balance","small","--node","a")
            check(short["height"]==14 and short["balance"]==80,"losing cached wallet")
            prior,_=run_cli(client,"resume","small","scale-small","--node","a")
            check(prior["status"]=="confirmed","original authorization absent on losing branch")
            report["losing_chain"]=archive(lab,"a",evidence/"blocks")
            for n in "abc":
                lab.links(n,[p for p in "abc" if p!=n])
            same_heads(lab,"abc",45)
            rb,_=run_cli(client,"balance","small","--node","a")
            check(rb["balance"]==80 and rb["height"]==45,"deep branch reconstruction")
            check(rb["sync"]["deep_resets"]==1,"expected deep replay")
            report["deep"]=rb["sync"]
            report["differential"]["deep"]=equivalent(client,"a","small")
            orphan=subprocess.run(args_for(client,"resume","small","scale-small","--node","a"),capture_output=True)
            check(orphan.returncode and b"reserved real input unavailable" in orphan.stderr,"orphan intent cannot switch inputs")
            after,_=run_cli(client,"send","small","@"+str(neutral_file),8,"--intent","after-deep","--node","a")
            check(after["change"]==69,"spend using canonical rebuilt change")
            run_cli(client,"create","observer")
            run_cli(client,"balance","observer","--node","a")
            lab.mine("a",1,"neutral")
            same_heads(lab,"abc",46)
            a_meter=relays["a"]
            index=len(a_meter.history_requests)
            observed,_=run_cli(client,"balance","observer","--node","a")
            request_list=a_meter.history_requests[index:]
            index=len(a_meter.history_requests)
            owned,_=run_cli(client,"balance","small","--node","a")
            check(observed["balance"]==0 and owned["balance"]==69 and
                  request_list==a_meter.history_requests[index:],"ownership-dependent history lookup")
            report["ownership_independent_requests"]=dict(identical=True,height=46,
                request_ops=[op for op,_ in request_list])
            lab.mining("a",-1)
            head=lab.status("c")["height"]
            interrupted=interrupt_restore(client,relays["c"],"live",live_seed)
            wait(lambda:lab.status("c")["height"],lambda h:h>head,"mining during interrupted scan",120)
            mark=len(relays["c"].history_requests)
            restored,resource=run_cli(client,"restore","live",live_seed)
            ranges=[params for op,params in relays["c"].history_requests[mark:] if op=="history_range"]
            check(restored["height"]>head and restored["balance"]>=100 and ranges
                  and ranges[0]["target"]==interrupted["target"] and ranges[0]["start"]==interrupted["next_requested"]
                  and ranges[0]["start"]>1,"interrupted restore reread a committed prefix")
            report["live_restore"]=dict(interrupted=interrupted,resumed_first_range=ranges[0],
                                        completed=restored["sync"],resources=resource)
            lab.mining("b",-1)
            ident="offline-order"
            relays["c"].cut_before_submit=True
            deliberately_disconnected(client,"send","live","@"+str(target),29,"--intent",ident)
            first=list(relays["c"].packets.values())[-1]
            old_height=lab.status("c")["height"]
            wait(lambda:lab.status("c")["height"],lambda h:h>=old_height+WINDOW,"stale real branch anchor",180)
            try:
                lab.request("c","submit",first)
            except ValueError as e:
                check(str(e)=="anchor age","actual stale admission reason")
            else:
                raise ValueError("expired authorization admitted")
            relays["b"].drop_next=True
            deliberately_disconnected(client,"resume","live",ident,"--node","b","--wait",180)
            check(any(r["dropped_reply"] for r in relays["b"].rows),"lost acknowledged real submission")
            payment,cost=run_cli(client,"resume","live",ident,"--node","c","--wait",240)
            check(payment["status"]=="confirmed" and payment["amount"]==29 and
                  payment["input_total"]==32+payment["change"],"sender-only reconciliation")
            again,_=run_cli(client,"send","live","@"+str(target),29,"--intent",ident)
            check(again["status"]=="confirmed" and again["tx"]==payment["tx"] and
                  again["attempts"]==payment["attempts"],"idempotent repeated send")
            receiver=client_at(lab.home/"receiver",lab.runtime,ports)
            received,restore_cost=run_cli(receiver,"restore","recipient",offline_backup)
            check(received["balance"]==46 and received["incoming_notes"]==2,"offline receipt after seed recovery")
            spent,spend_cost=run_cli(receiver,"send","recipient","@"+str(neutral_file),37,
                                     "--intent","recipient-spend","--wait",240)
            check(spent["status"]=="confirmed" and spent["real_inputs"]==2 and spent["change"]==6,
                  "two real restored receipts spent")
            lab.mining("a",0)
            lab.mining("b",0)
            final=same_heads(lab,"abc")
            report["differential"]["live_sender"]=equivalent(client,"c","live")
            report["differential"]["restored_recipient"]=equivalent(receiver,"c","recipient")
            # Re-verify each transmitted replacement, outside the measured wallet and server roles.
            from run import Resources
            v=Resources(lab.native)
            try:
                bank={k:p for relay in relays.values() for k,p in relay.packets.items()}
                slots=[v.backend.verify(bank[x])[0] for x in payment["attempts"]]
                common=set(slots[0].nfs)
                for slot in slots[1:]:
                    common.intersection_update(slot.nfs)
                check(len(slots)>=2 and common,"replacement authorizations must conflict on-chain")
            finally:
                v.close()
            selected=archive(lab,"c",evidence/"blocks")
            (evidence/"attempts").mkdir()
            for tx in payment["attempts"]:
                (evidence/"attempts"/(tx+".bin")).write_bytes(bank[tx])
            report["selected_chain"]=selected
            matches=[]
            for bid in selected:
                raw=lab.request("c","block",id=bid)[1]
                check(block_id(raw).hex()==bid,"selected block identity")
                for p in decode_block(raw).packets:
                    h=hashlib.sha256(p).hexdigest()
                    if h in payment["attempts"]:
                        matches.append(h)
            check(matches==[payment["tx"]],"exactly one canonical payment for durable intent")
            report["live_intent"]=dict(confirmed=payment["tx"],amount=29,change=payment["change"],
                input_total=payment["input_total"],attempts=payment["attempts"],shared_nullifier_count=len(common),
                canonical_count=len(matches),dropped_reply=True,stale_reason="anchor age",resumption_cost=cost)
            report["offline_recipient"]=dict(received=46,incoming_notes=2,spent=37,change=6,
                spend_tx=spent["tx"],restore_cost=restore_cost,spend_cost=spend_cost)
            report.update(final_height=final["height"],final_tip=final["tip"],elapsed_s=time.monotonic()-t)
            (evidence/"WALLET.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
            return dict(record=str(evidence/"WALLET.json"),final_height=final["height"],
                        offline_paid=payment["amount"],recipient_change=6,canonical_authorizations=len(matches))
    finally:
        lab.stop()
