"""Build fresh 90/10 payment/swap waves with two resident, separately keyed swap wallets."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import threading

from packets import HERE, SIGNATURE, digest, funded, le, need, pair_frame, parse, parse_leg
from wallet import Coin, descriptor, prepare, prove
from funding_fixture import GRANTS, ISSUE_FILES, POLICY
from relation import FundedTree, ZERO, h, new_note, spend_key


class PublicChannel:
    """Request/reply endpoint. Both directions carry public protocol material only."""
    def __init__(self,public,slot):
        self.process = subprocess.Popen([sys.executable,"-B",HERE/"swap_owner.py",str(slot),public],
                                        stdin=subprocess.PIPE,stdout=subprocess.PIPE)
        self.lock = threading.Lock()

    def call(self,action,**kwargs):
        with self.lock:
            self.process.stdin.write((json.dumps({"action":action,**kwargs})+"\n").encode())
            self.process.stdin.flush()
            line = self.process.stdout.readline()
            if not line:
                raise RuntimeError(f"wallet exited while handling {action}")
            return json.loads(line)

    def close(self):
        try:
            self.process.stdin.close()
        finally:
            self.process.stdout.close()
            self.process.wait()


def initial(public,owners,pool):
    prefix = public/"prefix"
    prefix.mkdir()
    nonce = secrets.token_bytes(64)
    chain = h("chain",nonce,POLICY)
    offers = list(pool.map(lambda o:o.call("initial",nonce=nonce.hex()),owners))
    # Only the nine ordinary senders and the offline recipient have backup material in this fixture driver.
    seeds = {i:secrets.token_bytes(64) for i in range(2,GRANTS+1)}
    desc = {i:descriptor(chain,seed) for i,seed in seeds.items()}
    desc.update({i:bytes.fromhex(v["descriptor"]) for i,v in enumerate(offers)})
    notes = {i:new_note(desc[i][:64],100+i,ZERO,0) for i in range(2,GRANTS)}
    grants = [bytes.fromhex(o["grant"]) for o in offers]+[n.encode() for n in notes.values()]
    genesis = b"FSG1"+nonce+POLICY+le(GRANTS,4)+b"".join(grants)
    (prefix/"genesis.bin").write_bytes(genesis)
    pin = digest(genesis)
    (public/"genesis.sha256").write_text(pin.hex()+"\n")
    for i,filename in enumerate(ISSUE_FILES):
        (prefix/filename).write_bytes(bytes.fromhex(offers[i]["issuance"]))
    checked,rows = funded(prefix,pin)
    need(checked==chain,"chain identity")
    root = FundedTree(rows).root.hex()
    for i,wallet in enumerate(owners):
        need(wallet.call("register",pin=pin.hex(),peer_descriptor=desc[1-i].hex())["funding_root"]==root,
             "wallet funding disagreement")
    pockets = {i:[Coin(i,n,spend_key(chain,seeds[i]))] for i,n in notes.items()}
    return pin,chain,rows,seeds,desc,pockets


def main(public,workers,waves):
    os.umask(0o077)
    public.mkdir()
    with ExitStack() as stack:
        owners = []
        for i in range(2):
            channel = PublicChannel(public,i)
            stack.callback(channel.close)
            owners.append(channel)
        pool = stack.enter_context(ThreadPoolExecutor(max_workers=workers))
        pin,chain,rows,seeds,desc,pockets = initial(public,owners,pool)
        (public/"onward.addr").write_bytes(desc[2])
        for wave in range(waves):
            base = list(rows)
            offers = list(pool.map(lambda w:w.call("offer",wave=wave),owners))
            salt = secrets.token_bytes(64).hex()
            agreements = list(pool.map(lambda w:w.call("agree",offers=offers,salt=salt),owners))
            need(agreements[0]==agreements[1],"swap wallets derived different terms")
            if wave==0:
                conflict = pool.submit(owners[0].call,"conflict",destination=desc[8].hex())
            ops = []
            for i in range(2,11):
                ix = 10*wave+i-1
                # The offline recipient gets only its original backup and ten complete public frames.
                if wave==1 and i==2:
                    def restored():
                        return subprocess.check_output([sys.executable,"-B",HERE/"wallet.py","recover",public],
                                                       input=seeds[11],cwd=public)
                    ops.append((ix,pool.submit(restored)))
                    rows.extend([None,None])
                    continue
                dest = desc[11] if wave==0 and i==2 else desc[(i+1)%11]
                cash = sum(c.note.native for c in pockets[i])
                recipients = [(dest,8,ZERO,0),(desc[i],cash-9,ZERO,0)]
                body,st,wit,effects,notes = prepare(pin,chain,base,pockets[i],recipients,1)
                ops.append((ix,pool.submit(prove,pin,body,st,wit)))
                pockets[i] = [Coin(len(rows)+1,notes[1],spend_key(chain,seeds[i]))]
                rows.extend(effects)
            if wave==0:
                (public/"conflict.bin").write_bytes(bytes.fromhex(conflict.result()["core"]))
            drafts = [pool.submit(w.call,"draft") for w in owners]
            for ix,job in ops:
                wire = job.result()
                (public/f"op-{ix:02}.bin").write_bytes(wire)
                if ix==11:
                    rows[len(base):len(base)+2] = parse(wire)[0].rows(chain)
            cores = [bytes.fromhex(f.result()["core"]) for f in drafts]
            for i,c in enumerate(cores):
                rows.extend(parse_leg(c+bytes(SIGNATURE),i+1).rows(chain))
            public_cores = [c.hex() for c in cores]
            approvals = list(pool.map(lambda w:w.call("approve",cores=public_cores),owners))
            sigs = [bytes.fromhex(v["signature"]) for v in approvals]
            wire = pair_frame(cores[0],sigs[0],cores[1],sigs[1])
            (public/f"op-{10*(wave+1):02}.bin").write_bytes(wire)
            expected = {"height":10*(wave+1),"root":FundedTree(rows).root.hex()}
            for result in pool.map(lambda w:w.call("confirm"),owners):
                need(result==expected,"wallet confirmation or history disagreement")
            print(f"Completed fresh operations {wave*10+1} through {(wave+1)*10}",flush=True)
    need(len({digest(p.read_bytes()) for p in public.glob("op-*.bin")})==10*waves,"distinct packets")


if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("public",type=Path)
    ap.add_argument("--workers",type=int,default=3,choices=range(1,7))
    ap.add_argument("--waves",type=int,default=2,choices=range(2,11))
    args=ap.parse_args()
    main(args.public.resolve(),args.workers,args.waves)
