"""Read a quiet loopback node through public TCP, independently check all selected blocks and wallet views."""
import argparse
import json
from pathlib import Path
import socket
import struct
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from network_oracle import GENESIS,decode,examine,proof_public,sha


class Peer:
    def __init__(self, port):
        self.port=port
        self.sent=self.received=self.requests=0

    def request(self, operation, **fields):
        # Read-only operations. Distinct connections and independent network-order frame codec.
        data=json.dumps({"op":operation,**fields},separators=(",",":")).encode()
        req=struct.pack("!II",4+len(data),len(data))+data
        with socket.create_connection(("127.0.0.1",self.port),timeout=25) as sock:
            sock.sendall(req)
            with sock.makefile("rb") as src:
                size,=struct.unpack("!I",src.read(4))
                assert 5<=size<=2**21
                payload=src.read(size)
                assert len(payload)==size
        self.sent+=len(req)
        self.received+=4+size
        self.requests+=1
        n,=struct.unpack("!I",payload[:4])
        assert 1<=n<=min(size-4,16384)
        meta=json.loads(payload[4:4+n])
        assert meta["ok"] is True,meta
        return meta["result"], payload[4+n:]


def check_peer(port,ref,reward):
    client=Peer(port)
    status,_=client.request("status")
    ids=[]
    while len(ids)<=status["height"]:
        batch,_=client.request("selected",start=len(ids),limit=3)
        assert 1<=len(batch)<=3
        ids.extend(batch)
    assert len(ids)==status["height"]+1 and ids[0]==GENESIS.hex() and ids[-1]==status["tip"]
    _,gen=client.request("block",id=ids[0])
    assert gen==b""
    blocks=[]
    for bid in ids[1:]:
        _,raw=client.request("block",id=bid)
        assert decode(raw)["id"].hex()==bid
        blocks.append(raw)
    result=examine(blocks,ref,reward)
    fields={"tip":"tip","height":"height","work":"work","anchor":"anchor","issued":"issued","fees":"fees",
            "spent":"spent","notes":"funded","network":"network","genesis":"genesis"}
    for remote,key in fields.items():
        assert status[remote]==result[key],remote
    data={k:[] for k in ("leaves","receipts","rewards","nfs")}
    for body in blocks:
        b=decode(body)
        for p in b["packets"]:
            slot,=proof_public(p)
            data["nfs"].extend(slot[2])
            for i,cm in enumerate(slot[3]):
                data["leaves"].append(cm)
                data["receipts"].append(cm+slot[-1][1792*i:1792*(i+1)])
        data["leaves"].append(b["cm"])
        data["rewards"].append(b["reward_body"]+b["cm"])
    data["nfs"].sort()
    digests={}
    for kind,expected in data.items():
        cursor=0
        while True:
            response,page=client.request("page",kind=kind,start=cursor,limit=3,tip=ids[-1])
            assert page==b"".join(expected[cursor:cursor+3])
            if cursor+3>=len(expected):
                assert response["next"] is None
                break
            cursor+=3
            assert response["next"]==cursor
        digests[kind]=sha(b"".join(expected)).hex()
    last_status,_=client.request("status")
    assert last_status["tip"]==status["tip"]
    return dict(selected={k:v for k,v in result.items() if k!="headers"},page_hashes=digests,
                process=status["pid"],node=status["node"],port=port,wire_bytes_out=client.sent,
                wire_bytes_in=client.received,public_requests=client.requests,deep_replays=status.get("deep_replays"))


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("reference",type=Path)
    p.add_argument("reward",type=Path)
    p.add_argument("ports",type=int,nargs="+")
    a=p.parse_args()
    views=[check_peer(port,a.reference.resolve(),a.reward.resolve()) for port in a.ports]
    assert all(x["selected"]==views[0]["selected"] and x["page_hashes"]==views[0]["page_hashes"] for x in views)
    assert len({x["process"] for x in views})==len(views)
    print(json.dumps(views,indent=2,sort_keys=True))
