"""Count real loopback frames for a wallet client and optionally drop one committed public submit reply.

This transparent test relay does not decode private data or retain packet bodies. Supply it only
as the endpoint of a disposable wallet. The real validating node still performs every operation.
"""
from collections import Counter
import hashlib
import json
import socket
import socketserver
import struct
import threading


def receive(stream):
    head=stream.read(4)
    if not head:
        return None
    assert len(head)==4
    size,=struct.unpack("!I",head)
    assert 5<=size<=2**21
    body=stream.read(size)
    assert len(body)==size
    n,=struct.unpack_from("!I",body)
    assert 1<=n<=min(16384,size-4)
    return head+body,json.loads(body[4:4+n]),body[4+n:]


def history_counts(body):
    if not body:
        return 0,0
    assert body[:8]==b"PQHIST01"
    blocks=body[8]
    assert 1<=blocks<=16
    pos=9
    slots=0
    for _ in range(blocks):
        width=body[pos+304]
        assert width<=4
        pos+=305+width*3744
        slots+=width
    assert len(body)==pos
    return blocks,slots


class Meter(socketserver.ThreadingTCPServer):
    daemon_threads=True

    def __init__(self,upstream,drop_first_ack=False):
        super().__init__(("127.0.0.1",0),Handler)
        self.upstream=upstream
        self.drop_next=drop_first_ack
        self.lock=threading.Lock()
        self.rows=[]
        self.thread=threading.Thread(target=self.serve_forever,daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self,*args):
        self.shutdown()
        self.server_close()
        self.thread.join()

    @property
    def port(self):
        return self.server_address[1]

    def before(self,op,params,body):
        """A test may close the client connection before this request reaches the real node."""
        return False

    def record(self,op,params,request,request_body,reply,response_meta,reply_body):
        result=response_meta.get("result",{})
        ok=response_meta.get("ok") is True
        row=dict(op=op,fields=sorted(params),request_frame_B=len(request),reply_frame_B=len(reply),
                 request_payload_B=len(request_body),reply_payload_B=len(reply_body),response_ok=ok)
        if op=="history_range" and ok:
            row["blocks"],row["transactions"]=history_counts(reply_body)
        if op=="submit" and request_body.startswith(b"APV2"):
            row["packet_sha256"]=hashlib.sha256(request_body).hexdigest()
        if isinstance(result,dict) and isinstance(result.get("reads"),dict):
            row["reported_reads"]={k:v for k,v in result["reads"].items() if type(v) is int}
        with self.lock:
            drop=self.drop_next and op=="submit" and ok
            if drop:
                self.drop_next=False
            row["dropped_reply"]=drop
            self.rows.append(row)
        return drop


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        with self.request.makefile("rb") as inp:
            incoming=receive(inp)
        if incoming is None:
            return
        frame,meta,req_body=incoming
        params={k:v for k,v in meta.items() if k!="op"}
        if self.server.before(meta["op"],params,req_body):
            return
        with socket.create_connection(("127.0.0.1",self.server.upstream),timeout=90) as peer:
            peer.sendall(frame)
            with peer.makefile("rb") as upstream:
                outgoing=receive(upstream)
        if outgoing is None:
            return
        answer,info,reply_body=outgoing
        if not self.server.record(meta["op"],params,frame,req_body,answer,info,reply_body):
            self.request.sendall(answer)


def summary(rows):
    totals=Counter()
    ops=Counter()
    reads=Counter()
    for r in rows:
        ops[r["op"]]+=1
        for field in ("request_frame_B","reply_frame_B","request_payload_B","reply_payload_B","blocks","transactions"):
            totals[field]+=r.get(field,0)
        if r["op"]=="history_range":
            totals["history_payload_B"]+=r["reply_payload_B"]
        reads.update(r.get("reported_reads",{}))
    return dict(operations=dict(ops),observed=dict(totals),server_reported=dict(reads))
