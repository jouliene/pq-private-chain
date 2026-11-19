"""Load a public retained interchange, bootstrap an empty validator via TCP, then verify a recovered spend."""
import argparse
from pathlib import Path
from hashlib import sha256
import json
import struct
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from archive import Checks, Store, ColdBackend, decode_core, enable_cold_chain
from exercise import cold_command, server, save


def exact(f,n):
    raw=f.read(n)
    if len(raw)!=n:raise ValueError("truncated archive")
    return raw


def replay(net,runtime,evidence,work):
    import chain
    work.mkdir(parents=True)
    store=Store(work/"source.sqlite")
    check=Checks(net,runtime)
    try:
        with (evidence/"retained.d8").open("rb") as f:
            if exact(f,8)!=b"D8ARCH01":raise ValueError("archive domain")
            count,ns=struct.unpack("<II",exact(f,8))
            if count>50000 or ns>count*4:raise ValueError("fixture inventory budget")
            for _ in range(count):
                n,=struct.unpack("<I",exact(f,4))
                if not 222<=n<=350:raise ValueError("archival core size")
                raw=exact(f,n);decode_core(raw,chain.NETWORK)
                bid=sha256(b"PQDEV1/work\0"+sha256(b"D8/core/v1\0"+raw[:-8]).digest()+raw[-8:]).digest()
                if int.from_bytes(bid,"big")>chain.TARGET:raise ValueError("archival PoW")
                store.put_core(bid,raw)
            for _ in range(ns):
                n,=struct.unpack("<I",exact(f,4))
                if not 9<=n<=2**20:raise ValueError("archival source limit")
                store.add(exact(f,n),check)
            if f.read(1):raise ValueError("archive trailing data")
        archive=store.counts()
    finally:
        store.db.close();check.close()
    local=work/"node"
    local.mkdir()
    with server(net,work/"source.sqlite",work,"source") as port:
        verified=cold_command(net,runtime,local/"evidence.sqlite",local/"ledger.sqlite",port)
    expected=json.loads((evidence/"successor/SUMMARY.json").read_bytes())
    if verified["pending_evidence"] or verified["state"]["tip"]!=expected["parent"]:
        raise ValueError("bootstrap endpoint mismatch")
    store=Store(local/"evidence.sqlite");check=Checks(net,runtime)
    ledger=enable_cold_chain()(local/"ledger.sqlite",ColdBackend(store,check))
    try:
        paid=(evidence/"successor/payment.bin").read_bytes()
        assert chain.txid_of(paid).hex()==expected["payment"] and len(check.read(paid))==1
        matched=0
        for bid in expected["selected"]:
            raw=(evidence/"successor"/(bid+".bin")).read_bytes()
            assert chain.block_id(raw).hex()==bid
            matched+=chain.decode_block(raw).packets.count(paid)
            ledger.accept(raw)
        actual=ledger.status()
        if matched!=1 or any(actual[k]!=v for k,v in expected["state"].items()):
            raise ValueError("restored spend or endpoint differs")
    finally:
        ledger.close();check.close();store.db.close()
    result=dict(format="D8-PUBLIC-1",archive=archive,from_empty=verified,
                successor=expected["payment"],final={k:actual[k] for k in expected["state"]})
    save(work/"PUBLIC.json",result)
    print(json.dumps({"verified_core_count":verified["verified_inventory"],"restored_payment":expected["payment"],"final_height":actual["height"]}))
    return result


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for k in ("network","runtime","evidence","work"):p.add_argument(k,type=Path)
    a=p.parse_args();sys.path.insert(0,str(a.network.resolve()/"devnet"));import chain
    replay(a.network.resolve(),a.runtime.resolve(),a.evidence.resolve(),a.work.resolve())
