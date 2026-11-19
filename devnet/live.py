"""Submit one ordinary wallet intent while two default miners independently advance a fresh local chain."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import chain
from cli import Lab
from runtime import DEFAULT
from wallet import _wire


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path,data):
    with path.open("x") as f:
        json.dump(data,f,indent=2,sort_keys=True)
        f.write("\n")


def capture(directory,identity,raw):
    p=directory/(identity+".bin")
    if p.exists():
        if p.read_bytes()!=raw:
            raise ValueError("public artifact identity collision")
    else:
        with p.open("xb") as f:
            f.write(raw)


def counts(lab):
    a,b=(lab.status(n) for n in ("a","b"))
    if a["remaining"]!=-1 or b["remaining"]!=-1:
        raise ValueError("both default miners must run continuously")
    return dict(a=a["found"],b=b["found"])


def selected_prefix(lab, tip, directory):
    """Check public block identity/ancestry through a particular snapshot, even if new blocks arrive."""
    h=tip["height"]
    parent=chain.GENESIS
    records=[]
    for start in range(1,h+1,128):
        n=min(128,h-start+1)
        ids=lab.request("c","selected",start=start,limit=n)[0]
        if len(ids)!=n:
            return None
        for height,identity in enumerate(ids,start):
            raw=lab.request("c","block",id=identity)[1]
            b=chain.decode_block(raw)
            if b.parent!=parent or b.height!=height:
                return None
            if chain.block_id(raw).hex()!=identity or int(identity,16)>chain.TARGET:
                raise ValueError("invalid PoW in captured public prefix")
            records.append((identity,b,raw))
            parent=bytes.fromhex(identity)
    if parent.hex()!=tip["tip"] or lab.request("c","selected",start=h,limit=1)[0]!=[tip["tip"]]:
        return None
    for identity,_,raw in records:
        capture(directory,identity,raw)
    return records


def effects(verifier, packet):
    row=verifier.call(packet)
    if len(row)!=1+172+3584 or row[0:1]!=b"1":
        raise ValueError("fresh public packet verification failed")
    return {row[37:69],row[69:101]}, {row[101:133].hex(),row[133:165].hex()}


def selected_status(lab,receiver,txid,nfs,cms,amount,blocks):
    tip,hist=lab.snapshot("c")
    prefix=selected_prefix(lab,tip,blocks)
    if prefix is None:
        return None
    receiver.scan(*hist)
    spent={hist[4][i:i+32] for i in range(0,len(hist[4]),32)}
    opened=[x for x in receiver.history if x["source"]=="incoming" and x["commitment"] in cms]
    matches=[(identity,b.height,len(raw)) for identity,b,raw in prefix
             if any(digest(p)==txid for p in b.packets)]
    if len(matches)>1:
        raise ValueError("duplicate canonical inclusion")
    included=None
    if matches:
        bid,height,block_B=matches[0]
        if not nfs<=spent or len(opened)!=1 or opened[0]["amount"]!=amount or opened[0]["spent"]:
            raise ValueError("selected proof, spentness and received amount disagree")
        on_all=all(lab.request(n,"selected",start=height,limit=1)[0]==[bid] for n in "abc")
        included=dict(height=height,block=bid,block_B=block_B,all_three_select=on_all,
                      successors=tip["height"]-height,recipient_amount=opened[0]["amount"])
    return dict(height=tip["height"],tip=tip["tip"],included=included,
                spent_nfs=len(nfs & spent),opened_expected_receipts=len(opened),
                prefix=[x for x,_,_ in prefix])


def trial(lab,evidence,amount):
    start=time.monotonic()
    evidence.mkdir(mode=0o700,parents=True,exist_ok=False)
    blocks=evidence/"blocks";blocks.mkdir()
    packets=evidence/"packets";packets.mkdir()
    report=dict(mode="pqd default continuous A/B",amount=amount,fee=3,attempts=[],outcome="incomplete")
    last_seen=None
    try:
        subprocess.run([str(HERE.parent/"pqd"),"--home",str(lab.home),"--runtime",str(lab.runtime),"start"],
                       stdout=subprocess.DEVNULL,check=True)
        lab.new_wallet("live-recipient")
        n=lab.native
        verifier=_wire.Role(n.binary,n.binary_sha,["verify","/keys"],n.keys)
        try:
            with lab.wallet("miner-a") as sender, lab.wallet("live-recipient") as receiver:
                # The sender process retains its compiled prover across retries. Each attempt obtains a new tip.
                fund_deadline=time.monotonic()+180
                done=False
                for attempt in range(1,5):
                    while True:
                        tip,hist=lab.snapshot("c")
                        wallet=sender.scan(*hist)
                        if wallet["balance"]>=amount+3 and wallet["reward_notes"]>=1:
                            break
                        if time.monotonic()>=fund_deadline:
                            raise TimeoutError("fresh selected miner funding")
                        time.sleep(.20)
                    before=counts(lab)
                    t=time.monotonic()
                    record=dict(attempt=attempt,anchor_height=tip["height"],anchor_tip=tip["tip"],
                                proof_start_s=t-start,found_before_proof=before)
                    report["attempts"].append(record)
                    packet=sender.pay(amount,receiver.address)
                    ready=time.monotonic()
                    tx=digest(packet)
                    after=counts(lab)
                    record.update(ready_s=ready-start,client_proof_wall_s=ready-t,
                                  height_after_proof=lab.status("c")["height"],found_after_proof=after,
                                  solved_during_proof=sum(after.values())-sum(before.values()),
                                  packet=tx,packet_B=len(packet),real_inputs=sender.last_payment["real_inputs"])
                    capture(packets,tx,packet)
                    nfs,cms=effects(verifier,packet)
                    meter={}
                    submission=time.monotonic()
                    record["height_before_submit"]=lab.status("c")["height"]
                    try:
                        accepted,_=lab.request("c","submit",packet,meter=meter)
                    except ValueError as exc:
                        if str(exc) not in {"anchor age","anchor branch"}:
                            raise
                        acknowledgement=False
                        record["rejection"]=str(exc)
                    else:
                        if accepted["id"]!=tx:
                            raise ValueError("incorrect submission acknowledgement")
                        acknowledgement=True
                    record.update(acknowledged=acknowledgement,submit_s=submission-start,
                                  submission_returned_s=time.monotonic()-start,submission_frame=meter)
                    deadline=time.monotonic()+120
                    while time.monotonic()<deadline:
                        state=selected_status(lab,receiver,tx,nfs,cms,amount,blocks)
                        if state is None:
                            continue
                        last_seen=state
                        inclusion=state["included"]
                        if inclusion and inclusion["all_three_select"] and inclusion["successors"]>=1:
                            record["inclusion"]=inclusion
                            record["confirmed_observed_s"]=time.monotonic()-start
                            report["outcome"]="included"
                            done=True
                            break
                        if not acknowledgement:
                            if inclusion or state["opened_expected_receipts"] or state["spent_nfs"]:
                                report["outcome"]="uncertain after stale rejection"
                                done=True
                            # Explicit stale refusal, no selected expenditure and no matching receiver output.
                            # One new proof may now be created by the original sender.
                            record["rejection_view"]=dict(height=state["height"],tip=state["tip"],
                                spent_nfs=state["spent_nfs"],opened_expected_receipts=state["opened_expected_receipts"])
                            break
                        if inclusion is None and state["height"]>=tip["height"]+chain.WINDOW:
                            report["outcome"]="acknowledged, no selected inclusion before expiry"
                            done=True
                            break
                        time.sleep(.15)
                    else:
                        report["outcome"]="uncertain pending confirmation"
                        done=True
                    if done:
                        break
                if not done:
                    report["outcome"]="four stale submissions"
                report["sender_meters"]=sender.close()
                report["receiver_meters"]=receiver.close()
            report["verifier_meters"]=verifier.close()
        finally:
            verifier.abort()
        if last_seen:
            report["observed_prefix"]=last_seen["prefix"]
            report["observed_tip"]=last_seen["tip"]
        report["found_at_end"]=counts(lab)
    finally:
        lab.stop()
        report["elapsed_s"]=time.monotonic()-start
        report["miners"]={}
        for name in "ab":
            logfile=lab.home/"nodes"/name/"mined.jsonl"
            events=[json.loads(line) for line in logfile.read_text().splitlines()] if logfile.is_file() else []
            report["miners"][name]=dict(solved=len(events),successful_search_cpu_s=sum(x["search_cpu_s"] for x in events),
                                         successful_hashes=sum(x["hashes"] for x in events))
        save(evidence/"LIVE.json",report)
    return report


def replay(evidence,runtime_dir):
    """Replay this captured selected prefix, packet verification and the recorded admission decisions."""
    from run import Resources
    from runtime import config
    r=json.loads((evidence/"LIVE.json").read_bytes())
    if r["outcome"]!="included" or not 1<=len(r["attempts"])<=4:
        raise ValueError("replay requires a successful bounded selected trace")
    resources=Resources(config(runtime_dir))
    try:
        with tempfile.TemporaryDirectory() as td:
            db=chain.Chain(Path(td)/"replay.sqlite",resources.backend)
            try:
                prefix=r["observed_prefix"]
                included={}
                checks=0
                for height in range(len(prefix)+1):
                    if height:
                        ident=prefix[height-1]
                        raw=(evidence/"blocks"/(ident+".bin")).read_bytes()
                        if chain.block_id(raw).hex()!=ident or not db.accept(raw)["selected"]:
                            raise ValueError("selected prefix mismatch")
                        for packet in chain.decode_block(raw).packets:
                            included[digest(packet)]=height
                    for proposal in r["attempts"]:
                        if proposal["height_before_submit"]!=height:
                            continue
                        packet=(evidence/"packets"/(proposal["packet"]+".bin")).read_bytes()
                        if digest(packet)!=proposal["packet"] or len(packet)!=proposal["packet_B"]:
                            raise ValueError("standalone packet identity")
                        slots=resources.backend.verify(packet)
                        if len(slots)!=1 or slots[0].height!=proposal["anchor_height"]:
                            raise ValueError("verified anchor height")
                        if proposal["acknowledged"]:
                            if db.offer(packet)["id"]!=proposal["packet"]:
                                raise ValueError("fresh submission identity")
                        else:
                            try:
                                db.offer(packet)
                            except ValueError as error:
                                if str(error)!=proposal["rejection"]:
                                    raise
                            else:
                                raise ValueError("unexpected admission of previously rejected packet")
                        checks+=1
                paid=[x for x in r["attempts"] if x["acknowledged"]]
                if (checks!=len(r["attempts"]) or len(paid)!=1 or
                        included!={paid[0]["packet"]:paid[0]["inclusion"]["height"]} or
                        db.status()["tip"]!=r["observed_tip"]):
                    raise ValueError("final replayed payment or head mismatch")
                return dict(verified_proposals=checks,selected_blocks=len(prefix),
                            inclusion_height=included[paid[0]["packet"]],tip=r["observed_tip"])
            finally:
                db.close()
    finally:
        resources.close()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--home",type=Path)
    p.add_argument("--check",action="store_true",help="public-only replay of a captured successful run")
    p.add_argument("--runtime",type=Path,default=DEFAULT)
    p.add_argument("--evidence",type=Path,required=True)
    p.add_argument("--amount",type=int,default=17)
    a=p.parse_args()
    if a.check:
        print(json.dumps(replay(a.evidence,a.runtime),sort_keys=True))
        return
    if a.home is None or not 1<=a.amount<=97 or a.home.exists() or a.evidence.exists():
        p.error("provide fresh home/evidence directories and an amount between 1 and 97")
    os.umask(0o077)
    r=trial(Lab(a.home,a.runtime),a.evidence,a.amount)
    print(json.dumps(dict(outcome=r["outcome"],attempts=len(r["attempts"]),elapsed_s=r["elapsed_s"])))


if __name__=="__main__":
    main()
