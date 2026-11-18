"""Independent local admission endpoints and a bounded FIFO. The queue contains only public packets."""
import hashlib
import multiprocessing
import os
from pathlib import Path
import socket
import sqlite3
import struct
import time

from wire import LIMIT, need, packet_width, u32

BATCH_WAIT = .20
POLL = .01
CAPACITY = 64


def db(path):
    conn=sqlite3.connect(path,isolation_level=None,timeout=10)
    conn.execute("PRAGMA synchronous=FULL")
    return conn


def create_pool(path):
    with Path(path).open("xb"):
        pass
    c=db(path)
    c.execute("CREATE TABLE pool (seq INTEGER PRIMARY KEY, tx BLOB UNIQUE NOT NULL, packet BLOB NOT NULL, arrival INTEGER NOT NULL, direct INTEGER NOT NULL)")
    c.close()


def recvexact(sock,n):
    out=bytearray()
    while len(out)<n:
        part=sock.recv(n-len(out))
        need(part, "truncated local delivery")
        out.extend(part)
    return bytes(out)


def serve(path,pool,direct,started):
    c=db(pool)
    with socket.socket(socket.AF_UNIX) as s:
        s.bind(path)
        os.chmod(path,0o600)
        s.listen(4)
        started.set()
        while True:
            peer,_=s.accept()
            with peer:
                peer.settimeout(5)
                try:
                    n,=struct.unpack("<I",recvexact(peer,4))
                    need(0<n<=LIMIT, "oversize submission")
                    p=recvexact(peer,n)
                    need(packet_width(p)==1, "ingress accepts only wallet proof")
                    identity=hashlib.sha256(p).digest()
                    c.execute("BEGIN IMMEDIATE")
                    try:
                        exists=c.execute("SELECT 1 FROM pool WHERE tx=?",(identity,)).fetchone()
                        if not exists:
                            need(c.execute("SELECT count(*) FROM pool").fetchone()[0]<CAPACITY, "public pool full")
                            c.execute("INSERT INTO pool(tx,packet,arrival,direct) VALUES (?,?,?,?)",
                                      (identity,p,time.monotonic_ns(),int(direct)))
                        elif direct:
                            c.execute("UPDATE pool SET direct=1 WHERE tx=?",(identity,))
                        c.execute("COMMIT")
                    except BaseException:
                        c.execute("ROLLBACK")
                        raise
                    peer.sendall(identity)
                except (ValueError, OSError):
                    pass  # The peer receives EOF with no acknowledgement.


class Endpoint:
    def __init__(self,path,pool,direct):
        self.path=str(path)
        ctx=multiprocessing.get_context("spawn")
        ready=ctx.Event()
        self.p=ctx.Process(target=serve,args=(self.path,str(pool),direct,ready))
        self.p.start()
        need(ready.wait(15) and self.p.is_alive(),"ingress startup")

    def stop(self):
        if self.p.is_alive():
            self.p.terminate()
            self.p.join(10)
        need(not self.p.is_alive(),"endpoint stop")
        Path(self.path).unlink(missing_ok=True)


def upload(paths,packet):
    identity=hashlib.sha256(packet).digest()
    attempts=[]
    for path in paths:
        sent=0
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(5)
            try:
                s.connect(str(path))
                data=u32(len(packet))+packet
                while sent<len(data):
                    n=s.send(data[sent:])
                    need(n>0,"upload ended")
                    sent+=n
                ack=recvexact(s,32)
                need(ack==identity,"ingress acknowledgement")
                attempts.append(dict(endpoint=Path(path).name,out_bytes=sent,ack_bytes=32,accepted=True))
                return attempts
            except (OSError, ValueError):
                attempts.append(dict(endpoint=Path(path).name,out_bytes=sent,ack_bytes=0,accepted=False))
    raise RuntimeError("all payment endpoints unavailable")


def admit_queue(pool,node,builders,nonce):
    """One local producer opportunity. A direct endpoint can use the singleton verifier autonomously."""
    c=db(pool)
    try:
        while True:
            rows=list(c.execute("SELECT seq,packet,arrival,direct FROM pool ORDER BY seq LIMIT ?",(CAPACITY,)))
            need(rows,"empty offer queue")
            if len(rows)>=4 or rows[0][3] or time.monotonic_ns()-rows[0][2]>=int(BATCH_WAIT*1e9):
                break
            time.sleep(POLL)
        selected,seen_nf,seen_cm=[],set(),set()
        rejected=[]
        for seq,raw,arrival,direct in rows:
            if selected and (selected[0][3] or direct):
                break
            try:
                slots=node.inspect(raw)
                need(len(slots)==1, "singleton")
                s=slots[0]
                need(not seen_nf.intersection(s.nfs) and not seen_cm.intersection(s.cms),"pool conflict")
            except ValueError as error:
                # Only semantic invalidity is evicted. Worker/transport faults leave pending bytes for retry.
                if str(error) not in {"cryptographic payment rejection","anchor expired or future","anchor branch",
                                      "spent nullifier","previous commitment","pool conflict","intra-block conflict or fees"}:
                    raise
                c.execute("DELETE FROM pool WHERE seq=?",(seq,))
                rejected.append(str(error))
                continue
            selected.append((seq,raw,arrival,direct))
            seen_nf.update(s.nfs)
            seen_cm.update(s.cms)
            if direct or len(selected)==4:
                break
        if not selected:
            return None,dict(rejected=rejected,count=0)
        k=len(selected)
        begin=time.monotonic()
        if k==1:
            packet=selected[0][1]
        else:
            packet=builders[k].call(*(x[1] for x in selected))
            need(packet_width(packet)==k, "aggregate constructor")
        built=time.monotonic()
        block=node.produce(packet,nonce)
        end=time.monotonic()
        c.executemany("DELETE FROM pool WHERE seq=?",((x[0],) for x in selected))
        return block,dict(count=k,rejected=rejected,packet_B=len(packet),block_B=len(block),
                          wallet_packet_B=[len(r[1]) for r in selected],builder_call_s=built-begin,
                          state_admission_s=end-built,oldest_accepted_to_commit_s=end-selected[0][2]/1e9,
                          queue_delay_to_builder_s=begin-selected[0][2]/1e9)
    finally:
        c.close()
