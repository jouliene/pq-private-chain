"""Local archival P2P service and from-genesis client. Public inventory is an untrusted hint."""
import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import socketserver
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from archive import (Checks, ColdBackend, MissingEvidence, Store, decode_core, enable_cold_chain, hydrate)
from block_format import COMPACT, core


def key(value):
    if not isinstance(value,str) or len(value)!=64:
        raise ValueError("identifier length")
    b=bytes.fromhex(value)
    if b.hex()!=value:
        raise ValueError("identifier representation")
    return b


def serve(store_path,ready):
    from transport import length,unpack,frame
    store=Store(store_path)
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            try:
                size=length(self.rfile.read(4))
                if size>16384:
                    raise ValueError("archival requests carry no attachments")
                m,b=unpack(self.rfile.read(size))
                if b:
                    raise ValueError("unexpected attachment")
                op=m["op"]
                result,body=None,b""
                if op=="inventory" and set(m)=={"op","start","limit"}:
                    result=store.inventory(m["start"],m["limit"])
                elif op=="lookup" and set(m)=={"op","id"}:
                    result=store.link(key(m["id"])).hex()
                elif op in ("core","proof") and set(m)=={"op","id"}:
                    body=store.body("cores" if op=="core" else "proofs",key(m["id"]))
                else:
                    raise ValueError("invalid archival request")
                response=frame(dict(ok=True,result=result),body)
            except (ValueError,KeyError,TypeError) as e:
                response=frame(dict(ok=False,error="unavailable" if isinstance(e,MissingEvidence) else "invalid request"))
            self.wfile.write(response)
    with socketserver.TCPServer(("127.0.0.1",0),Handler) as server:
        ready.write_text(str(server.server_address[1]))
        server.serve_forever()


class Reader:
    def __init__(self,port):
        self.port=port
        self.count=Counter()

    def get(self,op,**kwargs):
        from transport import rpc
        meter={}
        try:
            result,body=rpc(self.port,op,meter=meter,**kwargs)
            if op=="proof":
                self.count["source_"+body[:4].decode("ascii")]+=1
            self.count[op+"_body_B"]+=len(body)
            return result,body
        finally:
            self.count[op+"_requests"]+=1
            self.count["request_B"]+=meter.get("request_B",0)
            self.count["reply_B"]+=meter.get("reply_B",0)


def sync(net,archive,ledger,crypto,port,limit=None,fallback=None):
    import chain
    store=Store(archive)
    checks=Checks(net,crypto)
    connection=Reader(port)
    cold=enable_cold_chain()(ledger,ColdBackend(store,checks))
    other=Reader(fallback) if fallback is not None else None
    seen=accepted=0
    missing=[]
    blocked=None
    reorgs=[]
    try:
        while limit is None or seen<limit:
            ids,_=connection.get("inventory",start=seen,limit=min(64,limit-seen) if limit is not None else 64)
            if not isinstance(ids,list) or len(ids)>64:
                raise ValueError("inventory shape")
            if not ids:
                break
            for ident in ids:
                bid=key(ident)
                if cold.has(bid):
                    accepted+=1
                    try:
                        store.body("cores",bid)
                    except MissingEvidence:
                        stored=cold.block(bid)
                        if chain.block_id(stored)!=bid:
                            raise ValueError("local validated core identity")
                        store.put_core(bid,core(chain.NETWORK,stored))
                    seen+=1
                    continue
                _,raw=connection.get("core",id=ident)
                sids=decode_core(raw,chain.NETWORK)
                pow_id=sha256(b"PQDEV1/work\0"+sha256(b"D8/core/v1\0"+raw[:-8]).digest()+raw[-8:]).digest()
                if pow_id!=bid or int.from_bytes(bid,"big")>chain.TARGET:
                    raise ValueError("core work mismatch")
                if not cold.has(raw[41:73]):
                    missing.append({"block":ident,"parent":raw[41:73].hex()})
                    seen+=1
                    continue
                problem=None
                attachments=[]
                for sid in sids:
                    try:
                        cid=store.link(sid)
                    except MissingEvidence:
                        for provider in ([connection,other] if other else [connection]):
                            try:
                                cid=key(provider.get("lookup",id=sid.hex())[0])
                                _,body=provider.get("proof",id=cid.hex())
                                break
                            except OSError:
                                continue
                            except ValueError as e:
                                if str(e)!="unavailable":
                                    raise
                        else:
                            problem=dict(block=ident,sid=sid.hex(),height=int.from_bytes(raw[73:77],"little"))
                            break
                        if sha256(body).digest()!=cid or sid not in checks.read(body):
                            raise ValueError("unrelated evidence response")
                        store.add(body,checks)
                    verified=checks.read(store.body("proofs",cid))
                    if sid not in verified:
                        raise ValueError("source does not authorize required effect")
                    attachments.append(COMPACT+verified[sid])
                if problem:
                    blocked=blocked or problem
                    missing.append(problem)
                    seen+=1
                    continue
                materialized=hydrate(raw,attachments)
                if core(chain.NETWORK,materialized)!=raw:
                    raise ValueError("archival statement order")
                # Install the core and authenticate its branch before committing the archive index.
                # On process death the next inventory pass repairs the missing index from the
                # validated ledger; a fetched but invalid core never becomes served inventory.
                result=cold.accept(materialized)
                store.put_core(bid,raw)
                if result["detached"]:
                    reorgs.append(dict(bid=ident,detached=result["detached"],attached=result["attached"]))
                seen+=1
                accepted+=1
        return dict(verified_inventory=accepted,inspected_inventory=seen,missing_count=len(missing),fallback_traffic=dict(other.count) if other else {},state=cold.status(),pending_evidence=blocked,traffic=dict(connection.count),
                    newly_verified_sources=checks.calls,reorgs=reorgs)
    finally:
        cold.close()
        checks.close()
        store.db.close()


def wallet_node(net,home,archive,crypto):
    import asyncio
    import chain
    from node import Node
    from types import SimpleNamespace
    store=Store(archive)
    checks=Checks(net,crypto)
    db=enable_cold_chain()(home/"nodes/c/chain.sqlite",ColdBackend(store,checks))
    try:
        asyncio.run(Node(SimpleNamespace(home=home,node="c",continuous=False),db).run())
    finally:
        db.close()
        store.db.close()
        checks.close()


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("network",type=Path)
    sub=p.add_subparsers(dest="mode",required=True)
    sp=sub.add_parser("serve");sp.add_argument("archive",type=Path);sp.add_argument("ready",type=Path)
    sp=sub.add_parser("sync")
    for k in ("archive","ledger","crypto"):sp.add_argument(k,type=Path)
    sp.add_argument("port",type=int);sp.add_argument("--limit",type=int);sp.add_argument("--fallback",type=int)
    sp=sub.add_parser("wallet-node")
    for k in ("home","archive","crypto"):sp.add_argument(k,type=Path)
    a=p.parse_args()
    net=a.network.resolve()
    sys.path.insert(0,str(net/"devnet"))
    import chain
    if a.mode=="serve":
        serve(a.archive,a.ready)
    elif a.mode=="sync":
        print(json.dumps(sync(net,a.archive,a.ledger,a.crypto,a.port,a.limit,a.fallback),sort_keys=True))
    else:
        wallet_node(net,a.home,a.archive,a.crypto)
