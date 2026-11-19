"""Four independently funded DLF1 wallets, four concurrent direct proofs, one full real PoW block."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

HERE=Path(__file__).resolve().parent
NAMES=("miner-a","miner-b","third","fourth")
PROFILE="5d6cfc6ccff5792e4899799124b2fb1e7dac50f727825c4886485dc01a564ce8"


def require(ok,msg):
    if not ok:
        raise ValueError(msg)


def save(path,data):
    path.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n")


def wallet_process(deploy,home,role,meter_dir):
    """Run normal CLI send with an observer around its own local K call, recording only call boundary timestamps."""
    sys.path.insert(0,str(deploy/"devnet"))
    from cli import main
    from wallet import _wire
    original=_wire.Role.call
    def observe(self,*messages):
        if self.name!="wallet" or not messages or messages[0][:1]!=b"K":
            return original(self,*messages)
        (meter_dir/(role+".enter")).write_text(str(time.monotonic_ns()))
        packet=original(self,*messages)
        (meter_dir/(role+".exit")).write_text(str(time.monotonic_ns()))
        return packet
    _wire.Role.call=observe
    sys.argv=["pqd","--runtime",str(deploy/"runtime"),"--home",str(home),"send",role,
              "@"+str(meter_dir/"receiver.address"),"150","--intent","busy","--node","a"]
    main()


def replay(deploy,evidence):
    sys.path.insert(0,str(deploy/"devnet"))
    import chain
    from runtime import config
    from run import Resources
    report=json.loads((evidence/"BUSY.json").read_bytes())
    require(chain.PROFILE.hex()==PROFILE and chain.BITS==22,"incorrect DLF1 verifier profile or PoW")
    result={}
    t=time.monotonic()
    actors=Resources(config(deploy/"runtime"))
    try:
        with tempfile.TemporaryDirectory() as temp:
            ledger=chain.Chain(Path(temp)/"cold.sqlite",actors.backend)
            try:
                widths=[]
                reward_keys=Counter()
                for h,bid in enumerate(report["selected"],1):
                    raw=(evidence/"blocks"/(bid+".bin")).read_bytes()
                    b=chain.decode_block(raw)
                    assert b.height==h and chain.block_id(raw).hex()==bid and int(bid,16)<=chain.TARGET
                    if h<=8:
                        assert not b.packets and b.amount==100
                        reward_keys[b.pk]+=1
                    if h==9:
                        assert not b.packets and b.amount==100
                    widths.append(len(b.packets))
                    ledger.accept(raw)
                assert widths==[0]*9+[4] and sorted(reward_keys.values())==[2]*4
                st=ledger.status()
                assert st["height"]==10 and st["fees"]==12 and st["issued"]==1000 and st["spent"]==8 and st["tip"]==bid
                assert b.amount==112
                inputs=set()
                outputs=set()
                txids=[]
                for packet in b.packets:
                    assert packet[:4]==b"DLF1" and len(packet)==143187
                    slot,=actors.backend.verify(packet)
                    assert slot.fee==3 and slot.height==8 and len(slot.cts)==len(slot.cms)==len(slot.nfs)==2
                    assert slot.anchor==ledger.db.execute("SELECT b.ap FROM sel s JOIN blocks b USING(id) WHERE s.h=8").fetchone()[0]
                    inputs.update(slot.nfs)
                    outputs.update(slot.cms)
                    txids.append(sha256(packet).hexdigest())
                    try:
                        ledger.offer(packet)
                    except ValueError as err:
                        assert str(err)=="spent nullifier"
                    else:
                        raise AssertionError("already spent transaction accepted")
                assert len(inputs)==len(outputs)==8 and set(txids)==set(report["wallet_txs"])
                assert st["tip"]==ledger.status()["tip"] and ledger.pending()==[]
                result=dict(height=10,current_spent=8,fees=12,issued=1000,last_gross_reward=112,
                            registered_profile=PROFILE,four_distinct_public_reward_keys_each_paid_twice=True,
                            tip=st["tip"],root=st["header"][-64:],selected_work=st["work"],nonces_and_full_bodies_verified=10,
                            four_fresh_registered_verifications=True,standalone_spent_readmissions_rejected=4,
                            distinct_nullifiers=8,distinct_outputs=8,payment_anchor_height=8,included_height=10)
            finally:
                ledger.close()
        costs=actors.finish("verifier")
        result["verifier_meters"]=costs["meters"]
        result["fresh_replay_and_controls_wall_s"]=time.monotonic()-t
        return result
    finally:
        actors.close()


def capture(deploy,home,evidence):
    sys.path.insert(0,str(deploy/"devnet"))
    sys.path.insert(0,str(HERE.parents[2]/"devnet/wallet-review"))
    from cli import Lab,wait
    from chain import BITS,PROFILE as chain_profile,block_id,decode_block
    from wire_meter import Meter
    require(not home.exists() and not evidence.exists(),"supply fresh private and public directories")
    require(chain_profile.hex()==PROFILE and BITS==22,"incorrect DLF1 verifier profile or PoW")
    os.umask(0o077)
    evidence.mkdir(parents=True)
    (evidence/"blocks").mkdir()
    lab=Lab(home,deploy/"runtime")
    def cli(*args):
        return json.loads(subprocess.check_output([sys.executable,"-IB",str(deploy/"devnet/cli.py"),
                           "--home",str(home),"--runtime",str(deploy/"runtime"),*map(str,args)],timeout=120))
    def sync(nodes,height):
        return wait(lambda:[lab.status(n) for n in nodes],lambda ss:all(s["height"]==height for s in ss) and
                    len({s["tip"] for s in ss})==1,"same controlled selected branch",120)[0]
    def traffic(rows):
        summary={}
        for row in rows:
            v=summary.setdefault(row["op"],dict(count=0,request_B=0,reply_B=0,response_body_B=0))
            v["count"]+=1
            v["request_B"]+=row["request_frame_B"]
            v["reply_B"]+=row["reply_frame_B"]
            v["response_body_B"]+=row["reply_payload_B"]
        return summary
    try:
        lab.initialize()
        with ExitStack() as group:
            pre=group.enter_context(Meter(lab.cfg["ports"]["a"]))
            relay=group.enter_context(Meter(lab.cfg["ports"]["c"]))
            lab.cfg["ports"].update(meter_a=pre.port,meter_c=relay.port)
            save(home/"network.json",lab.cfg)
            for node in "abc":
                lab.launch(node,continuous=False)
            group.callback(lab.stop)
            private=Path(group.enter_context(tempfile.TemporaryDirectory(dir=home)))
            for name in ("third","fourth","neutral"):
                lab.new_wallet(name)
            lab.export_address("neutral",private/"receiver.address")
            assert len({lab.address(n) for n in (*NAMES,"neutral")})==5
            for name in NAMES:
                lab.mine("c",2,name)
            sync("abc",8)
            for name in NAMES:
                balance=cli("balance",name,"--node","a")
                assert balance["balance"]==200 and balance["reward_notes"]==balance["notes"]==2
            for node in "abc":
                lab.links(node,[])
            def pay(name):
                before=time.monotonic()
                cmd=[sys.executable,"-IB",str(Path(__file__).resolve()),"--one-wallet",str(deploy),str(home),name,str(private)]
                result=json.loads(subprocess.check_output(cmd,timeout=180))
                assert result["status"]=="submitted" and result["real_inputs"]==2 and result["input_total"]==200
                assert result["fee"]==3 and result["amount"]==150 and result["change"]==47
                assert result["anchor_height"]==8 and len(result["submission_frames"])==1
                return dict(tx=result["tx"],packet_B=result["packet_B"],real_inputs=2,fee=3,
                            wallet_call_wall_s=time.monotonic()-before,wallet_metrics=result["wallet_metrics"],
                            submit=result["submission_frame"])
            epoch=time.monotonic()
            wall_offset=time.time()-epoch
            with ThreadPoolExecutor(max_workers=4) as pool:
                tasks=[pool.submit(pay,name) for name in NAMES]
                wait(lambda:sum((private/(n+".enter")).exists() for n in NAMES),lambda n:n==4,
                     "four isolated native authorizations",40)
                # No retry, no timer-driven production: grant the isolated miner exactly one
                # opportunity, shortly after all K requests entered. It has no submitted packets.
                time.sleep(1.7)
                grant=time.monotonic()-epoch
                lab.mining("c",1,"neutral")
                payments=[job.result() for job in tasks]
                four_wallet_session=time.monotonic()-epoch
            save(home/"proof-cost-checkpoint.json",dict(payments=payments,epoch=epoch,wall_offset=wall_offset,
                 grant=grant,four_wallet_session=four_wallet_session,
                 K_enter_ns=[int((private/(n+".enter")).read_text()) for n in NAMES],
                 K_exit_ns=[int((private/(n+".exit")).read_text()) for n in NAMES]))
            tenants={p["tx"] for p in payments}
            assert len(tenants)==4 and set(lab.request("a","pending")[0])==tenants
            sync("c",9)
            unrelated=lab.status("c")
            assert not decode_block(lab.request("c","block",id=unrelated["tip"])[1]).packets
            assert lab.status("a")["height"]==8 and not lab.request("c","pending")[0]
            event=next(json.loads(line) for line in (home/"nodes/c/mined.jsonl").read_text().splitlines()
                       if json.loads(line)["height"]==9)
            found=event["found_unix"]-wall_offset-epoch
            search_enter=found-event["search_wall_s"]
            certain=[]
            for name,p in zip(NAMES,payments,strict=True):
                enter=int((private/(name+".enter")).read_text())/1e9-epoch
                end=int((private/(name+".exit")).read_text())/1e9-epoch
                setup=next(m for m in p["wallet_metrics"] if m["operation"]=="wallet_prover_setup")
                proof=next(m for m in p["wallet_metrics"] if m["operation"]=="compact_prove")
                # K includes setup, then the Rust proof interval, then reply. Bracket the
                # true proof inside K with its measured duration, without accessing the witness.
                latest_start=end-proof["elapsed_s"]
                earliest_finish=enter+setup["elapsed_s"]+proof["elapsed_s"]
                interval=(latest_start,earliest_finish)
                certain.append(interval)
                p.update(K_enter_s=enter,K_return_s=end,proof_certain_interval_s=list(interval),
                    minimum_proof_overlap_with_H9_worker_lifecycle_s=max(0,min(earliest_finish,found)-max(latest_start,search_enter)))
            lab.admin("c","peers",ports=[pre.port])
            wait(lambda:set(lab.request("c","pending")[0]),lambda ids:ids==tenants,"four peer-fetched direct authorizations",60)
            lab.admin("c","peers",ports=[])
            lab.mine("c",1,"neutral")
            final=sync("c",10)
            lab.admin("b","peers",ports=[relay.port])
            sync("bc",10)
            lab.admin("b","peers",ports=[])
            selected=lab.request("b","selected",start=1,limit=128)[0]
            sizes=[]
            for bid in selected:
                block=lab.request("b","block",id=bid)[1]
                assert block_id(block).hex()==bid
                (evidence/"blocks"/(bid+".bin")).write_bytes(block)
                sizes.append(len(block))
            pks=decode_block(block).packets
            assert {sha256(raw).hexdigest() for raw in pks}==tenants and len(pks)==4
            assert final["fees"]==12 and final["spent"]==8 and final["issued"]==1000
            transfer=traffic(pre.rows)
            core_relay=traffic(relay.rows)
            assert transfer["tx"]["count"]==4 and transfer["tx"]["response_body_B"]==sum(map(len,pks))
            assert core_relay["block"]["count"]==2 and core_relay["block"]["response_body_B"]==sum(sizes[-2:])
            bulk=sum(len(raw) for raw in pks)
            assert sizes[-1]==222+4*4+bulk
            report=dict(format="DLF1-BUSY-1",scenario="one controlled H9 opportunity, four independent concurrent direct senders, paid H10",
                bank="real 22-bit selected PoW",selected=selected,wallet_txs=[p["tx"] for p in payments],payments=payments,
                packet_B=list(map(len,pks)),payment_proof_B=[int.from_bytes(r[5:9],"little") for r in pks],
                receipt_B_per_payment=3584,packet_framing_B_per_payment=9,core_prefix_and_nonce_B=222,
                bulk_packet_B=bulk,full_paid_block_B=sizes[-1],full_selected_archive_B=sum(sizes),empty_blocks=9,
                paid_block_B_per_included=sizes[-1]/4,all_selected_B_per_included=sum(sizes)/4,
                four_wallet_session_wall_s=four_wallet_session,all_four_minimum_simultaneous_native_proof_s=
                    max(0,min(x[1] for x in certain)-max(x[0] for x in certain)),
                H9_controlled_grant_s=grant,H9_worker_lifecycle_relative_s=[search_enter,found],
                H9_search_cpu_s=event["search_cpu_s"],H9_wall_search_and_accept_s=event["search_wall_s"],
                H9_empty_and_unrelated=True,common_H8_anchor=True,paid_H10=True,independent_wallet_processes=4,
                node_preinclusion_fetch_frames=transfer,node_selected_relay_frames=core_relay,
                paid_block_single_fetch=next(dict(request_B=row["request_frame_B"],reply_B=row["reply_frame_B"],
                    block_payload_B=row["reply_payload_B"]) for row in relay.rows if row["op"]=="block" and row["reply_payload_B"]==sizes[-1]))
            save(evidence/"BUSY.json",report)
    finally:
        lab.stop()
    cmd=[sys.executable,"-IB",str(Path(__file__).resolve()),"--replay",str(deploy),str(evidence)]
    public=json.loads(subprocess.check_output(cmd,timeout=120))
    save(evidence/"REPLAY.json",public)
    print(json.dumps(dict(height=public["height"],payments=4,archive_B=report["full_selected_archive_B"],
                          four_wallet_wall_s=report["four_wallet_session_wall_s"],public_replay=True)))


if __name__=="__main__":
    if sys.argv[1:2]==["--one-wallet"]:
        _,_,deploy,home,name,private=sys.argv
        wallet_process(Path(deploy),Path(home),name,Path(private))
    elif sys.argv[1:2]==["--replay"]:
        print(json.dumps(replay(Path(sys.argv[2]).resolve(),Path(sys.argv[3]).resolve()),sort_keys=True,indent=2))
    else:
        p=argparse.ArgumentParser(description=__doc__)
        for key in ("deploy","home","evidence"):
            p.add_argument(key,type=Path)
        a=p.parse_args()
        capture(a.deploy.resolve(),a.home.resolve(),a.evidence.resolve())
