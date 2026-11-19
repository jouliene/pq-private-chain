"""Fresh local payments, real Unix ingress/failover, branch switches and an offered-load sample."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path
import os
import socket
import sqlite3
import struct
import tempfile
import time

from ingress import BATCH_WAIT, Endpoint, admit_queue, create_pool, recvexact, upload
from run import Records, payment, put, reject, rescan, save, snapshot
from state import Ledger, UNDO
from wire import CT, need, packet_width, sha, split_block, u32


def transfer(raw):
    # A receiver actually reads each complete framed block. Local stream/TCP/IP overheads differ.
    sender,peer=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
    with sender,peer,ThreadPoolExecutor(max_workers=1) as executor:
        write=executor.submit(sender.sendall,u32(len(raw))+raw)
        size=int.from_bytes(recvexact(peer,4),"little")
        need(size==len(raw),"relay size")
        data=recvexact(peer,size)
        write.result()
        return data


def public_block_at_tip(n):
    return n.db.execute("SELECT body FROM blocks ORDER BY h DESC LIMIT 1").fetchone()[0]


def campaign(args,res):
    args.evidence.mkdir(parents=True,exist_ok=False)
    args.work.mkdir(parents=True,exist_ok=False)
    rec=Records(args.evidence)
    report=dict(uploads=[],opportunities=[],relay=[],controls=[],wallet_preparation=[],events=[])
    with ExitStack() as stack:
        private=Path(stack.enter_context(tempfile.TemporaryDirectory(dir="/dev/shm",prefix="ap-wallet-")))
        transport=Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="ap-ingress-")))
        actors=[]; addrs=[]; funds=[]
        for i in range(4):
            store=private/str(i)
            store.mkdir(mode=0o700)
            wallet=res.role("wallet"+str(i),["wallet","/keys","/private/seed","create"],store)
            addr,cms=wallet.get(),wallet.get()
            need(len(addr)==1601 and len(cms)==24*32 and addr not in addrs,"independent wallet setup")
            actors.append(wallet);addrs.append(addr);funds.append(cms)
        genesis=b"APGEN001"+u32(96)+b"".join(funds)
        approved=sha(genesis)
        put(args.evidence/"genesis.bin",genesis)
        def open_node(name,create,prune=False):
            n=Ledger(args.work/(name+".sqlite"),res.backend,genesis,approved,create,prune)
            stack.callback(n.close)
            return n
        node=open_node("selected",True)
        # The independent receiving node owns separate database and proof verifier processes.
        peer_v=res.role("peer_verify",["verify","/keys"])
        from state import PublicBackend
        peer=Ledger(args.work/"peer.sqlite",PublicBackend(res.h,peer_v,args.profile_sha),genesis,approved,True,True)
        stack.callback(peer.close)
        pool=args.work/"offers.sqlite"
        create_pool(pool)
        primary=Endpoint(transport/"builder",pool,False)
        alternate=Endpoint(transport/"direct",pool,True)
        stack.callback(primary.stop);stack.callback(alternate.stop)
        paths=[transport/"builder",transport/"direct"]
        builders={}
        events=report["events"]

        def build(k):
            if k not in builders:
                b=res.role("builder"+str(k),["builder","/keys",str(k)])
                need(b.get()==b"READY","builder readiness")
                builders[k]=b
            return builders[k]

        def anchor():
            return node.head()["header"],node.leaves()

        def pay(name,i,pair,at,to=None):
            start=time.monotonic()
            dest=addrs[(i+1)%4 if to is None else to]
            raw=payment(actors[i],pair,*at,dest)
            report["wallet_preparation"].append(dict(label=name,wallet=i,elapsed_s=time.monotonic()-start,
                                                     downloaded_leaf_payload_B=len(at[1]),packet_B=len(raw)))
            return rec.submission(name,raw)

        def offer(name,raw):
            entries=upload(paths,raw)
            report["uploads"].append(dict(label=name,attempts=entries))
            return entries

        def compare():
            need(snapshot(node)==snapshot(peer),"local relayed branch divergence")

        def record(block):
            start=time.monotonic()
            received=transfer(block)
            peer.accept(received)
            report["relay"].append(dict(block_B=len(block),full_stream_B=len(block)+4,receive_validate_wall_s=time.monotonic()-start))
            compare()
            bid=rec.block(block)
            events.append(dict(op="extend",block=bid,state=snapshot(node)))
            return bid

        def settle(label,count,nonce):
            if count>=2: build(count)
            raw,stat=admit_queue(pool,node,builders,nonce)
            need(stat["count"]==count,label+" expected occupancy")
            report["opportunities"].append(dict(label=label,**stat))
            if raw is not None:
                record(raw)
            return stat

        def badpay(label,p,reason):
            report["controls"].append(reject(node,label,lambda:node.produce(p,99),reason))
            events.append(dict(op="reject",packet=rec.packet(p),reason=reason,state=snapshot(node)))

        g=anchor()
        group=[pay("waiting"+str(i),i,0,g) for i in range(4)]
        unrelated=pay("unrelated",3,11,g,to=2)
        conflict=pay("different-authorization-same-input",0,0,g,to=3)
        # P frames are flushed before advancing the chain. This wallet actually proves in parallel with h1.
        from run import pages
        actor=actors[0]
        actor.send(b"P"+struct.pack("<H",1)+g[0])
        for page in pages(g[1],32): actor.send(page)
        actor.send(addrs[1]); start=time.monotonic()
        unrelated_block=node.produce(unrelated,1)
        record(unrelated_block)
        while_proving=time.monotonic()-start
        solo=rec.submission("lone",actor.get())
        duration=time.monotonic()-start
        need(packet_width(solo)==1 and while_proving<duration,"advancing chain while paying")
        report["concurrent"]=dict(anchor_height=0,during_proof_height=1,advance_and_peer_wall_s=while_proving,
                                  wallet_response_s=duration,unrelated_body_B=len(unrelated))
        h1=anchor()
        offer("lone",solo)
        single=settle("lone-bounded-wait",1,2)
        need(BATCH_WAIT<=single["oldest_accepted_to_commit_s"]<3,"local singleton deadline")
        h2=anchor()
        two=[pay("mixed0",0,2,g),pay("mixed1",1,2,h1)]
        for i,p in enumerate(two):offer("mixed"+str(i),p)
        settle("two-distinct-anchor-heights",2,3)
        triple=[pay("triple"+str(i),i,3,h2) for i in range(3)]
        for i,p in enumerate(triple):offer("triple"+str(i),p)
        settle("three",3,4)
        common=node.head()["id"]
        common_at=anchor()
        for i,p in enumerate(group):offer("waiting"+str(i),p)
        first4=settle("four-independent-genesis-anchors",4,5)
        four_packet=split_block(public_block_at_tip(node))[2]
        h5=anchor()
        badpay("conflict-on-old-valid-anchor",conflict,"spent nullifier")
        # A structurally valid packet with a changed Merkle proof receives no state effects.
        corrupt=bytearray(group[1])
        corrupt[9]^=1
        badpay("corrupt-proof",bytes(corrupt),"cryptographic payment rejection")
        # Stop the preferred process and all warm aggregation workers. The direct node can work alone.
        primary.stop()
        for k in sorted(builders):
            res.finish("builder"+str(k))
        builders.clear()
        fallback=pay("builder-offline",3,1,h5,to=0)
        result=offer("builder-offline",fallback)
        need([r["accepted"] for r in result]==[False,True],"direct fallback delivery")
        # Retransmit the same bytes after the independent durable acknowledgement.
        duplicate=offer("duplicate-delivery",fallback)
        need(duplicate[-1]["accepted"],"idempotent delivery")
        stat=settle("builder-processes-offline",1,6)
        need(stat["oldest_accepted_to_commit_s"]<3,"direct service bound")
        h6=anchor()
        old6=rec.blocks[events[-1]["block"]]
        # A fresh DB connection and brand new receipt wallet with only its private seed and public history.
        early_busy=[pay(f"busy{j}-0",0,5+j,common_at) for j in range(3)]
        old=snapshot(node)
        node.close()
        node=open_node("selected",False)
        need(snapshot(node)==old,"durable restart")
        res.finish("wallet0")
        actors[0]=res.role("restore0",["wallet","/keys","/private/seed","restore"],private/"0")
        need(actors[0].get()==addrs[0] and actors[0].get()==b"","key-only wallet restart")
        history=bytearray(); canonical_blocks=0
        for row in node.db.execute("SELECT body FROM blocks WHERE h>0 ORDER BY h"):
            block=row[0]
            packet=split_block(block)[2]
            canonical_blocks+=len(block)
            if packet:
                for s in res.backend.verify(packet):
                    for cm,ct in zip(s.cms,s.cts):
                        history.extend(cm+ct)
        visible=rescan(actors[0],history,node.nfs())
        need(visible>=2,"open received notes on restore")
        report["recovery"]=dict(genesis_B=len(genesis),complete_archived_blocks_B=canonical_blocks,
            common_receipt_rows_B=len(history),common_nfs_B=len(node.nfs()),local_membership_leaf_payload_B=len(node.leaves()),
            opened_unspent=visible,private_backup_B=(private/"0"/"seed").stat().st_size)
        successor=pay("restored-recipient-spend",0,65535,h6)
        offer("restored-recipient-spend",successor)
        settle("restored-recipient-direct",1,7)

        # Construct a competing valid history solely from accepted public bytes, using the original prefix.
        fork=open_node("fork",True)
        for row in node.db.execute("SELECT body FROM blocks WHERE h BETWEEN 1 AND 4 ORDER BY h"):
            fork.accept(row[0])
        need(fork.head()["id"]==common,"fork point")
        b5=fork.produce(conflict,500); b6=fork.produce(b"",600)
        b5id,b6id=rec.block(b5),rec.block(b6)
        from run import public_block
        old6raw=public_block(args.evidence,old6)
        report["controls"].append(reject(node,"atomic-invalid-fork",lambda:node.switch(common,[b5,old6raw]),"anchor branch"))
        events.append(dict(op="reject_switch",base=common.hex(),blocks=[b5id,sha(old6raw)],reason="anchor branch",state=snapshot(node)))
        node.switch(common,[b5,b6]);peer.switch(common,[transfer(b5),transfer(b6)])
        compare()
        events.append(dict(op="switch",base=common.hex(),blocks=[b5id,b6id],state=snapshot(node)))
        badpay("orphaned-recipient-authorization",successor,"anchor branch")
        # Old full aggregate contains an input spent on this branch. Three unspent legs must not be applied.
        badpay("indivisible-conflicting-ordinary-batch",four_packet,"spent nullifier")
        record(node.produce(group[1],700))
        edge=pay("window-edge",2,4,g)
        too_old=pay("expired-window",3,4,g)
        record(node.produce(edge,800))
        badpay("one-block-past-window",too_old,"anchor expired or future")

        # Independently submitted distinct real payments arrive on a monotonic clock, while the producer works.
        # Fixed adaptive interval uses the first measured warm four-origin service plus explicit headroom.
        primary=Endpoint(paths[0],pool,False);stack.callback(primary.stop)
        b=build(4)
        arrivals=[]
        at=anchor()
        for round_id in range(3):
            arrivals.append([early_busy[round_id]]+[pay(f"busy{round_id}-{i}",i,5+round_id,at) for i in range(1,4)])
        interval=max(1.,1.5*(first4["builder_call_s"]+first4["state_admission_s"]+.3))
        epoch=time.monotonic()+.1
        groups=[]
        def scheduled_uploads():
            for j,batch in enumerate(arrivals):
                deadline=epoch+j*interval
                time.sleep(max(0,deadline-time.monotonic()))
                for i,p in enumerate(batch):offer(f"busy{j}-{i}",p)
        with ThreadPoolExecutor(max_workers=1) as runner:
            sending=runner.submit(scheduled_uploads)
            c=sqlite3.connect(pool)
            try:
                for j in range(3):
                    end=epoch+(j+1)*interval+30
                    while c.execute("SELECT count(*) FROM pool").fetchone()[0]<4:
                        need(time.monotonic()<end,"busy load timeout")
                        time.sleep(.005)
                    st=settle("clocked-four-"+str(j),4,901+j)
                    groups.append(dict(scheduled_s=j*interval,completed_s=time.monotonic()-epoch,
                                       builder_wall_s=st["builder_call_s"],queue_head_to_commit_s=st["oldest_accepted_to_commit_s"]))
                sending.result()
                need(c.execute("SELECT count(*) FROM pool").fetchone()[0]==0,"busy queue drained")
            finally:c.close()
        report["busy"]=dict(interval_s=interval,offered_per_second=4/interval,rounds=groups,
                            deadline_misses=sum(r["completed_s"]>(i+1)*interval for i,r in enumerate(groups)),
                            synchronized_prepared_payments=12,origin_anchor_heights=[4,8,8,8],last_admission_height=11)
        # Disclose pruning on a real retained prefix. Empty advances are separately charged.
        for i in range(9):
            record(node.produce(b"",1000+i))
        report["controls"].append(reject(peer,"beyond-retained-undo",lambda:peer.switch(common,[]),"rollback horizon"))
        tip=node.head()["h"]
        floor=tip-UNDO
        tip_id=node.head()["id"]
        base=node.db.execute("SELECT id FROM blocks WHERE h=?",(floor,)).fetchone()[0]
        earlier=node.db.execute("SELECT id FROM blocks WHERE h=?",(floor-1,)).fetchone()[0]
        suffix=[r[0] for r in node.db.execute("SELECT body FROM blocks WHERE h>? ORDER BY h",(floor,))]
        node.switch(base,[]);peer.switch(base,[])
        compare()
        events.append(dict(op="switch",base=base.hex(),blocks=[],state=snapshot(node)))
        for n in (node,peer):
            reject(n,"monotonic-undo-floor",lambda:n.switch(earlier,[]),"rollback horizon")
        events.append(dict(op="reject_switch",base=earlier.hex(),blocks=[],reason="rollback horizon",state=snapshot(node)))
        node.switch(base,suffix);peer.switch(base,suffix)
        compare();need(node.head()["id"]==tip_id,"reselected original branch")
        events.append(dict(op="switch",base=base.hex(),blocks=[rec.block(v) for v in suffix],state=snapshot(node)))
        for name,n in [("archive",node),("pruned",peer)]:
            report[name]=dict(sqlite_B=n.path.stat().st_size,body_B=n.db.execute("SELECT coalesce(sum(length(body)),0) FROM blocks").fetchone()[0],
                retained_frontiers=n.db.execute("SELECT count(frontier) FROM blocks").fetchone()[0],retained_bodies=n.db.execute("SELECT count(body) FROM blocks").fetchone()[0],
                first_restorable_height=n.db.execute("SELECT min(h) FROM blocks WHERE frontier IS NOT NULL").fetchone()[0])
        report["final"]=snapshot(node)
        report["roots"]=__import__("run").roots(res.h)
        for name in list(res.roles):
            res.finish(name)
        report["roles"]=res.finished
        trace=dict(genesis_sha256=approved,profile_sha256=args.profile_sha,binary_sha256=args.binary_sha,
                   blocks=rec.blocks,submissions=rec.submissions,events=events)
        save(args.evidence/"TRACE.json",trace)
        save(args.evidence/"RESULT.json",{k:v for k,v in report.items() if k!="events"})
        return dict(genesis_sha256=approved,events=len(events),final=report["final"],busy=report["busy"])
