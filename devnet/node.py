"""Loopback peer daemon. Each peer validates and selects its own persistent chain."""
import argparse
import asyncio
from collections import deque
import fcntl
import json
import os
from pathlib import Path
import secrets
import signal
import struct
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import chain
import runtime
from transport import control, frame, length, unpack


def hexid(value):
    if not isinstance(value,str) or len(value)!=64:
        raise ValueError("identifier length")
    result = bytes.fromhex(value)
    if result.hex()!=value:
        raise ValueError("identifier encoding")
    return result


def integer(value, lo, hi):
    if type(value) is not int or not lo <= value <= hi:
        raise ValueError("integer out of range")
    return value


async def receive(reader):
    size = length(await reader.readexactly(4))
    return unpack(await reader.readexactly(size))


async def peer_request(port, metadata):
    reader,writer = await asyncio.open_connection("127.0.0.1",port)
    try:
        writer.write(frame(metadata))
        await writer.drain()
        meta,body = await receive(reader)
        if meta.get("ok") is not True:
            raise ValueError(meta.get("error","peer rejected request"))
        return meta["result"],body
    finally:
        writer.close()
        await writer.wait_closed()


HISTORY_FIELDS = {
    "history_head": {"op","locator"},
    "history_range": {"op","target","start","base","limit"},
    "history_check": {"op","target"},
    "history_info": {"op"},
}


class Node:
    def __init__(self, args, db):
        self.home = args.home
        self.name = args.node
        self.db = db
        self.directory = args.home/"nodes"/args.node
        cfg = json.loads((args.home/"network.json").read_bytes())
        self.port = cfg["ports"][args.node]
        self.allowed = set(cfg["ports"].values())-{self.port}
        self.peers = set(json.loads((self.directory/"peers.json").read_bytes()))
        self.generation = 0
        self.cursor = {}
        self.default_pk = bytes.fromhex((self.directory/"miner.pk").read_text())
        self.pk = self.default_pk
        self.remaining = -1 if args.continuous else 0
        self.found = 0
        self.worker = None
        self.job = 0
        self.shutdown = asyncio.Event()
        self.clients = 0
        self.errors = deque(maxlen=5)

    def status(self):
        return dict(self.db.status(), node=self.name, pid=os.getpid(),port=self.port,
                    peers=sorted(self.peers),found=self.found,remaining=self.remaining,
                    errors=list(self.errors))

    def dispatch(self, m, body, admin):
        op = m["op"]
        if body and op not in ("submit","publish"):
            raise ValueError("unexpected body")
        if op=="status":
            return self.status(),b""
        if op in HISTORY_FIELDS and set(m) != HISTORY_FIELDS[op]:
            raise ValueError("unexpected history request fields")
        if op=="history_head":
            return self.db.history_head(m["locator"]),b""
        if op=="history_range":
            return self.db.history_range(m["target"],m["start"],m["base"],m["limit"])
        if op=="history_check":
            return self.db.history_check(m["target"]),b""
        if op=="history_info":
            return dict(version=1,startup=self.db.history.startup),b""
        if op=="locate":
            loc = m["locator"]
            if not isinstance(loc,list) or not 1<=len(loc)<=128:
                raise ValueError("locator size")
            for v in loc:
                hexid(v)
            return self.db.after(loc,16),b""
        if op=="selected":
            return self.db.selected(integer(m["start"],0,2**32),integer(m["limit"],1,128)),b""
        if op=="block":
            return {},self.db.block(hexid(m["id"]))
        if op=="tx":
            b=self.db.tx(hexid(m["id"]))
            if b is None:
                raise ValueError("unknown transaction")
            return {},b
        if op=="pending":
            return self.db.pending(),b""
        if op=="submit":
            return self.db.offer(body),b""
        if op=="publish":
            return self.db.accept(body),b""
        if op=="page":
            hexid(m["tip"])
            body,nxt = self.db.page(m["kind"],integer(m["start"],0,2**32),integer(m["limit"],1,128),m["tip"])
            return dict(next=nxt),body
        if not admin:
            raise ValueError("unknown public operation")
        if op=="peers":
            peers = m["ports"]
            if not isinstance(peers,list) or len(peers)>len(self.allowed) or any(type(p) is not int or p not in self.allowed for p in peers):
                raise ValueError("unconfigured peer")
            tmp=self.directory/"peers.new"
            tmp.write_text(json.dumps(peers))
            os.replace(tmp,self.directory/"peers.json")
            self.peers=set(peers)
            self.generation+=1
            return {},b""
        if op=="mining":
            count=integer(m["count"],-1,1000)
            pk=hexid(m["pk"]) if "pk" in m else self.default_pk
            self.job+=1
            if self.worker and self.worker.returncode is None:
                self.worker.terminate()
            self.remaining,self.pk=count,pk
            return self.status(),b""
        if op=="stop":
            self.shutdown.set()
            return {},b""
        raise ValueError("unknown operation")

    async def serve(self, reader,writer,admin):
        if self.clients>=32:
            writer.close()
            return
        self.clients+=1
        try:
            m,b=await asyncio.wait_for(receive(reader),5)
            result,body=self.dispatch(m,b,admin)
            writer.write(frame(dict(ok=True,result=result),body))
        except (ValueError,KeyError,TypeError,OverflowError,RuntimeError,asyncio.TimeoutError,asyncio.IncompleteReadError) as e:
            writer.write(frame(dict(ok=False,error=str(e)[:200])))
        finally:
            try:
                await asyncio.wait_for(writer.drain(),5)
            except (OSError,asyncio.TimeoutError):
                pass
            writer.close()
            self.clients-=1

    async def sync_peer(self,p):
        gen=self.generation
        async def request(op,**kw):
            reply=await asyncio.wait_for(peer_request(p,dict(op=op,**kw)),15)
            if self.generation!=gen or p not in self.peers:
                raise ConnectionError("peer topology changed")
            return reply
        theirs,_=await request("status")
        if theirs["network"]!=chain.NETWORK.hex():
            raise ValueError("peer network")
        if not self.db.has(hexid(theirs["tip"])):
            loc=self.db.locator()
            if p in self.cursor:
                loc.insert(0,self.cursor[p])
            ids,_=await request("locate",locator=loc)
            if not isinstance(ids,list) or len(ids)>16:
                raise ValueError("peer inventory")
            for ident in ids:
                bid=hexid(ident)
                if not self.db.has(bid):
                    _,b=await request("block",id=ident)
                    if chain.block_id(b)!=bid:
                        raise ValueError("block response identity")
                    self.db.accept(b)
                self.cursor[p]=ident
        pending,_=await request("pending")
        if not isinstance(pending,list) or len(pending)>chain.MAX_PENDING:
            raise ValueError("peer pool bounds")
        for ident in pending:
            txid=hexid(ident)
            if self.db.tx(txid) is None:
                _,b=await request("tx",id=ident)
                if chain.sha256(b).digest()!=txid:
                    raise ValueError("transaction response identity")
                try:
                    self.db.offer(b)
                except ValueError as e:
                    if str(e) not in chain.INELIGIBLE:
                        raise

    async def sync(self):
        while True:
            for p in sorted(self.peers):
                try:
                    await self.sync_peer(p)
                except (ConnectionError, OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                    pass
                except (ValueError,KeyError,TypeError,RuntimeError) as e:
                    self.errors.append(str(e)[:160])
            await asyncio.sleep(.12)

    async def miner(self):
        while True:
            if self.remaining==0:
                await asyncio.sleep(.08)
                continue
            job=self.job
            parent=self.db.status()["tip"]
            template=self.db.template(self.pk)
            start=secrets.randbits(63)
            worker=await asyncio.create_subprocess_exec(sys.executable,"-IB",__file__,"work",str(start),
                stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE)
            self.worker=worker
            t=time.monotonic()
            task=asyncio.create_task(worker.communicate(template))
            try:
                while not task.done():
                    await asyncio.wait([task],timeout=.12)
                    if (self.job!=job or parent!=self.db.status()["tip"]) and worker.returncode is None:
                        worker.terminate()
                data,_=task.result()
                if self.job!=job or parent!=self.db.status()["tip"]:
                    continue
                if worker.returncode!=0:
                    raise RuntimeError("nonce worker exited unexpectedly")
                nonce,cpu=struct.unpack("<Qd",data)
                raw=template+struct.pack("<Q",nonce)
                self.db.accept(raw)
                if self.remaining>0:
                    self.remaining-=1
                self.found+=1
                event=dict(tip=chain.block_id(raw).hex(),parent=parent,height=chain.decode_block(raw).height,
                    found_unix=time.time(),search_wall_s=time.monotonic()-t,search_cpu_s=cpu,
                    hashes=nonce-start+1,bytes=len(raw),payments=len(chain.decode_block(raw).packets))
                with (self.directory/"mined.jsonl").open("a") as out:
                    out.write(json.dumps(event)+"\n")
            finally:
                if worker.returncode is None:
                    worker.kill()
                await task
                self.worker=None

    async def run(self):
        path=control(self.home,self.name)
        path.unlink(missing_ok=True)
        tcp=await asyncio.start_server(lambda r,w:self.serve(r,w,False),"127.0.0.1",self.port)
        unix=await asyncio.start_unix_server(lambda r,w:self.serve(r,w,True),str(path))
        os.chmod(path,0o600)
        loop=asyncio.get_running_loop()
        for sig in (signal.SIGINT,signal.SIGTERM):
            loop.add_signal_handler(sig,self.shutdown.set)
        tasks=[asyncio.create_task(self.sync()),asyncio.create_task(self.miner()),asyncio.create_task(self.shutdown.wait())]
        try:
            finished,_=await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
            for t in finished:
                t.result()
        finally:
            tcp.close()
            unix.close()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks,return_exceptions=True)
            path.unlink(missing_ok=True)


def main():
    if sys.argv[1:2]==["work"]:
        template=sys.stdin.buffer.read(chain.MAX_BLOCK+1)
        start=int(sys.argv[2])
        t=time.process_time()
        raw=chain.mine(template,start)
        sys.stdout.buffer.write(raw[-8:]+struct.pack("<d",time.process_time()-t))
        return
    parser=argparse.ArgumentParser()
    parser.add_argument("--home",type=Path,required=True)
    parser.add_argument("--runtime",type=Path,required=True)
    parser.add_argument("--node",required=True)
    parser.add_argument("--continuous",action="store_true")
    args=parser.parse_args()
    from run import Resources
    with (args.home/"nodes"/args.node/"lock").open("a") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        resources=Resources(runtime.config(args.runtime))
        try:
            db=chain.Chain(args.home/"nodes"/args.node/"chain.sqlite",resources.backend)
            try:
                asyncio.run(Node(args,db).run())
            finally:
                db.close()
        finally:
            resources.close()


if __name__=="__main__":
    main()
