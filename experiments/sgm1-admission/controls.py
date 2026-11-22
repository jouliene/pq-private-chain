"""Independent full-tree/monetary oracle and public differential tests outside timed roles."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import sqlite3
from packets import parse, need, anchor, digest
from ledger import Ledger, verify_operation
from fixtures_public import read_prefix, read_rows
from relation import FundedTree

def reject(fn,label,reason=None):
    try:
        fn()
    except ValueError as ex:
        if reason and reason not in str(ex):
            raise AssertionError(f"{label}: unexpected reason {ex}") from ex
        return
    raise AssertionError(f"accepted {label}")

def state(db):
    return (db.tip(), tuple(db.db.execute("SELECT pos,occ,cm FROM outputs ORDER BY pos")),
            tuple(db.db.execute("SELECT nf FROM spends ORDER BY nf")),
            tuple(db.db.execute("SELECT level,pos,val FROM nodes ORDER BY level,pos")),
            tuple((height,ident,root,count,auth,fee,digest(wire) if wire is not None else None)
                  for height,ident,root,count,auth,fee,wire in db.db.execute(
                      "SELECT height,id,root,count,anchor,fees,wire FROM blocks ORDER BY height")),
            tuple(db.db.execute("SELECT height,level,pos,old FROM undo ORDER BY height,level,pos")))

def tests(public,dbpath):
    pin,chain,initial=read_prefix(public)
    wires=list(read_rows(public,len(list(public.glob("op-*.bin")))))
    db=Ledger(dbpath,public,pin)
    rows=list(initial)
    roots={}
    spent=set()
    fee=ordinary=pairs=0
    checked=[]
    heights={}
    def check_state():
        root=FundedTree(rows).root
        height,_,r,n,f=db.tip()
        need((r,n,f)==(root,len(rows),fee),"full replay root/count/fee disagreement")
        need(list(db.db.execute("SELECT occ,cm FROM outputs ORDER BY pos"))==rows,"occurrence set")
        need({x[0] for x in db.db.execute("SELECT nf FROM spends")}==spent,"spent set")
        roots[anchor(pin.hex(),chain,root,n)]=(root,n)
    check_state()
    ref_jobs=[]
    with ThreadPoolExecutor(max_workers=2) as pool:
        for height,wire in enumerate(wires,1):
            legs=parse(wire)
            st=tuple(l.statement(chain,*roots[l.body.anchor]).encode() for l in legs)
            ref_jobs.append(pool.submit(verify_operation,pin,chain,legs,st,"reference"))
            if height in (64,65):
                # Both checks use the same complete conflict packet and current spent inputs.
                expected="already spent" if height==64 else "ineligible branch anchor"
                reject(lambda:db.prepare((public/"conflict.bin").read_bytes()),"64-block anchor boundary",expected)
            db.admit(wire)
            for l in legs:
                need(spent.isdisjoint(l.body.nfs),"unanticipated conflict")
                spent.update(l.body.nfs)
                fee+=l.body.fee
                rows.extend(l.rows(chain))
            if len(legs)==2:
                pairs+=1
            else:
                ordinary+=1
            check_state()
            if height in (9,10,len(wires)):
                heights[height]=state(db)
            checked.append(digest(wire).hex())
        for future in ref_jobs:
            future.result()
    need(ordinary*1 == pairs*9 and fee==len(wires),"workload accounting")
    if len(wires)==100:
        reject(lambda:db.prepare(wires[-1]),"expired swap at candidate height 101","swap expired")
    final=state(db)
    db.close()
    db=Ledger(dbpath,public,pin)
    need(final==state(db),"durable restart")
    pair=parse(wires[9])
    conflict=(public/"conflict.bin").read_bytes()
    observations={}
    def observe_pair(stage):
        height,_,_,count,fees=db.tip()
        def present(sql,values):
            return sum(db.db.execute(sql,(v,)).fetchone() is not None for v in values)
        observations[stage]=dict(height=height,count=count,fees=fees,
            spent_per_owner=[present("SELECT 1 FROM spends WHERE nf=?",l.body.nfs) for l in pair],
            swap_outputs_per_owner=[present("SELECT 1 FROM outputs WHERE occ=?",
                [occ for occ,cm in l.rows(chain)]) for l in pair])
    reject(lambda:db.admit(conflict),"second use of funded note")
    # A failed reorg must restore even the detached suffix, in one write transaction.
    damaged=bytearray(wires[9]);damaged[-1]^=1
    reject(lambda:db.replace_suffix(9,[bytes(damaged)]),"bad second approval","invalid pair approval")
    need(state(db)==final,"partial failed replacement")
    db.replace_suffix(9,[])
    need(state(db)==heights[9],"swap, both sides, fees and dependents did not rewind")
    observe_pair("rollback_to_common_prefix")
    reject(lambda:db.admit(wires[10]),"detached root","ineligible branch anchor")
    # Mutate genuine signed packets without changing the first proof's encoding.
    offset=20+int.from_bytes(wires[9][4:12],"little")
    for name,at,reason in [("first approval",offset-1,"invalid pair approval"),
                           ("second approval",len(wires[9])-1,"invalid pair approval"),
                           ("second proof",offset+4126+50,"proof rejected")]:
        altered=bytearray(wires[9]);altered[at]^=1
        reject(lambda:db.admit(bytes(altered)),name,reason)
        need(state(db)==heights[9],"pair admitted partially")
    reject(lambda:db.admit(pair[0].core+pair[0].signature),"unpaired leg")
    # Both submitted operations pass full cryptography at the same snapshot.
    _,verify_swap=db.prepare(wires[9])
    _,verify_conflict=db.prepare(conflict)
    commit_swap=verify_swap()
    commit_conflict=verify_conflict()
    with db.transaction():
        commit_conflict()
    alt=state(db)
    observe_pair("competing_ordinary")
    def publish(callback):
        with db.transaction():
            callback()
    reject(lambda:publish(commit_swap),"competing verified swap at ordered publication","already spent")
    need(state(db)==alt and db.tip()[4]==10,"rejected swap debit or fee")
    existing={x[0] for x in db.db.execute("SELECT nf FROM spends")}
    need(existing.isdisjoint(pair[1].body.nfs) and
         set(pair[0].body.nfs).intersection(existing),"unaffected swap owner")
    db.replace_suffix(9,[wires[9]])
    need(state(db)==heights[10],"atomic swap readmission")
    observe_pair("selected_swap")
    need(observations["selected_swap"]["spent_per_owner"]==[2,2] and
         observations["selected_swap"]["swap_outputs_per_owner"]==[2,2] and
         observations["competing_ordinary"]["swap_outputs_per_owner"]==[0,0], "partial swap effects")
    reject(lambda:db.admit(conflict),"conflicting alternative after swap","already spent")
    _,verify_onward=db.prepare(wires[10])
    commit_onward=verify_onward()
    db.replace_suffix(9,[conflict])
    reject(lambda:publish(commit_onward),"previously verified detached root","ineligible branch anchor")
    need(state(db)==alt,"stale in-flight proof changed alternate fork")
    db.replace_suffix(9,[wires[9]])
    # Replay the original suffix and compare every persisted commitment and spent identity.
    for wire in wires[10:]:
        db.admit(wire)
    need(state(db)==final,"winning replay mismatch")

    first=parse(wires[0])
    st=first[0].statement(chain,FundedTree(initial).root,len(initial)).encode()
    differential=0
    def both(leg,statement,p=pin):
        nonlocal differential
        for backend in ("native","reference"):
            reject(lambda:verify_operation(p,chain,(leg,),(statement,),backend),backend)
        differential+=1
    from dataclasses import replace
    def flip(buf,at):
        a=bytearray(buf);a[at]^=1;return bytes(a)
    # Root, degree digest, masked round, AS projections, square response, Q,
    # opened column, Merkle proof and R completion all preserve packet length.
    pf=first[0].proof
    trace_end=128+584*32
    for pos in (0,64,128,trace_end,trace_end+512,trace_end+544,trace_end+544+7744,
                trace_end+544+7744+2*(647+32+75)+32,len(pf)-1):
        both(replace(first[0],proof=flip(pf,pos)),st)
    for pos in (0,64,128,134,142,270,398,462):
        both(first[0],flip(st,pos))
    both(first[0],st,flip(pin,0))
    # Network paths recompute the intent over receipt/canonical fields.
    for field in (70,398,2190):
        l=parse(flip(wires[0],field))[0]
        both(l,l.statement(chain,FundedTree(initial).root,len(initial)).encode())
    db.close()
    return dict(distinct_operations=len(checked),ordinary=ordinary,swaps=pairs,fees=fee,
                funded_prefix=len(initial),final_count=len(rows),spent=len(spent),
                accepted_proof_legs=ordinary+2*pairs,restored_onward_operation=11,
                anchor_age_64_and_65_checked=len(wires)>=65,swap_expiry_100_and_101_checked=len(wires)==100,
                fully_encoded_differential_rejections=differential,canonical_root=final[0][2].hex(),
                distinct_anchor_counts=sorted({n for r,n in roots.values() if anchor(pin.hex(),chain,r,n)
                    in {l.body.anchor for wire in wires for l in parse(wire)}}),
                public_packet_list_sha256=digest(b"".join(bytes.fromhex(v) for v in checked)).hex(),
                pair_state=observations,rollback_both_sides_fee_and_restart=True,conflicting_alternative_then_original=True)

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("public",type=Path);ap.add_argument("new_db",type=Path)
    args=ap.parse_args()
    need(not args.new_db.exists(),"controls need an empty store")
    print(json.dumps(tests(args.public,args.new_db),indent=2))
