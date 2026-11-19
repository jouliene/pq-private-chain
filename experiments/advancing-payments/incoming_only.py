"""Prove a new spend by an unfunded recipient whose only notes came from another wallet."""
import argparse
import json
from pathlib import Path
import signal
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from run import Records, Resources, payment, public_block, put, rescan, save, snapshot
from state import Ledger
from wire import need, packet_width, sha, split_block, u32


def trial(a, res):
    a.evidence.mkdir(parents=True,exist_ok=False)
    records = Records(a.evidence)
    with tempfile.TemporaryDirectory(dir="/dev/shm") as private:
        def new(name):
            store = Path(private)/name
            store.mkdir(mode=0o700)
            role = res.role(name,["wallet","/keys","/private/seed","create"],store)
            return role,role.get(),role.get(),store
        sender, return_addr, funds, _ = new("funder")
        recipient, dest, unfunded, store = new("receiver")
        need(dest!=return_addr and len(unfunded)==len(funds)==24*32,"separate wallet identities")
        to_words = lambda raw:{raw[i:i+32] for i in range(0,len(raw),32)}
        need(to_words(funds).isdisjoint(to_words(unfunded)),"receiver has no genesis funding")
        res.finish("receiver")
        genesis = b"APGEN001"+u32(24)+funds
        origin = sha(genesis)
        put(a.evidence/"genesis.bin",genesis)
        node = Ledger(a.work/"incoming.sqlite",res.backend,genesis,origin,True)
        try:
            order = []
            rows = bytearray()
            def include(packet, nonce):
                block = node.produce(packet,nonce)
                order.append(records.block(block))
                if packet:
                    slot, = res.backend.verify(packet)
                    for cm,ct in zip(slot.cms,slot.cts,strict=True):
                        rows.extend(cm+ct)
            at = node.head()["header"]
            leaves = node.leaves()
            for pair in (0,1):
                p = payment(sender,pair,at,leaves,dest)
                include(p,pair+1)
            include(b"",3)
            need(sorted(f.name for f in store.iterdir())==["seed"] and (store/"seed").stat().st_size==32,
                 "seed-only restore inventory")
            restored = res.role("restored_receiver",["wallet","/keys","/private/seed","restore"],store)
            need(restored.get()==dest and restored.get()==b"", "restore receiver without genesis notes")
            per_payment = len(rows)//2
            counts = [rescan(restored, part, node.nfs()) for part in (b"",rows[:per_payment],rows[per_payment:],rows)]
            need(counts==[0,1,1,2],"one distinct confirmed receipt from each external payment")
            prior = snapshot(node)
            successor = payment(restored,65535,node.head()["header"],node.leaves(),return_addr)
            include(successor,4)
            remaining = rescan(restored,rows,node.nfs())
            final = snapshot(node)
            need(remaining == 1 and final["spent"]==prior["spent"]+2 and final["fees"]==prior["fees"]+3,
                 "incoming inputs consumed and one fresh change receipt")
            for name in list(res.roles):
                res.finish(name)
            save(a.evidence/"TRACE.json",dict(genesis_sha256=origin,profile_sha256=a.profile_sha,
                 blocks=records.blocks,order=order,final=final))
            result=dict(genesis_sha256=origin,profile_sha256=a.profile_sha,genesis_receiver_notes=0,
                        funding_source_wallets=1,receiver_backup_B=32,opened_empty_each_both=counts,
                        received_spend_height=4,opened_after_spend=remaining,before=prior,after=final,roles=res.finished)
            save(a.evidence/"RECEIPT.json",result)
            return result
        finally:
            node.close()


def replay(a,res):
    t=json.loads((a.evidence/"TRACE.json").read_bytes())
    need(t["profile_sha256"]==a.profile_sha and t["genesis_sha256"]==a.genesis_sha,"approved incoming trace")
    node=Ledger(a.work/"replay.sqlite",res.backend,(a.evidence/"genesis.bin").read_bytes(),a.genesis_sha,True)
    try:
        widths=[]
        for identity in t["order"]:
            b=public_block(a.evidence,t["blocks"][identity])
            need(sha(b)==identity,"incoming public body")
            p=split_block(b)[2]
            widths.append(packet_width(p) if p else 0)
            node.accept(b)
        final=snapshot(node)
        need(widths==[1,1,0,1] and final==t["final"] and final["spent"]==6 and final["fees"]==9,
             "public incoming payment chain")
        return dict(final=final,public_widths=widths)
    finally:node.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode",choices=["trial","replay"])
    for key in ["binary","keys","evidence","work"]:
        parser.add_argument("--"+key,type=Path,required=True)
    for key in ["binary-sha","profile-sha"]:
        parser.add_argument("--"+key,required=True)
    parser.add_argument("--genesis-sha")
    a=parser.parse_args()
    signal.alarm(300)
    a.work.mkdir(parents=True,exist_ok=False)
    res=Resources(a)
    try:print(json.dumps(trial(a,res) if a.mode=="trial" else replay(a,res),sort_keys=True,indent=2))
    finally:res.close()


if __name__=="__main__":
    main()
