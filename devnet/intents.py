"""Crash-safe sender outbox. All authorizations for one intent consume the same real inputs."""
import hashlib
import json
import os
import stat
from pathlib import Path
import re
import sqlite3
import struct
import time

FEE=3
MAX_VALUE=(1<<62)-1
MAX_ATTEMPTS_PER_CALL=8


def identifier(value):
    if not isinstance(value,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}",value):
        raise ValueError("intent identifier must be 1..80 letters, digits, dots, hyphens or underscores")
    return value


def default_id(address,amount):
    if type(amount) is not int or not 0<amount<=MAX_VALUE:
        raise ValueError("amount outside wallet range")
    return "pay-"+hashlib.sha256(b"PQDEV1/local-intent/v1\0"+address+struct.pack("<Q",amount)).hexdigest()[:32]


class Outbox:
    def __init__(self,private):
        path=Path(private)/"intents.sqlite"
        fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:
                raise ValueError("unsafe private outbox")
        finally:
            os.close(fd)
        self.db=sqlite3.connect(path,timeout=30)
        self.db.row_factory=sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA synchronous=FULL")
        with self.db:
            self.db.execute("""CREATE TABLE IF NOT EXISTS intents(
                id TEXT PRIMARY KEY, address BLOB NOT NULL, amount INTEGER NOT NULL,
                pinned TEXT, disposition TEXT NOT NULL DEFAULT 'new')""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS attempts(
                tx TEXT PRIMARY KEY, intent TEXT NOT NULL REFERENCES intents(id), height INTEGER NOT NULL,
                anchor TEXT NOT NULL, packet BLOB, accounting TEXT NOT NULL, prove_s REAL NOT NULL)""")
            self.db.execute("CREATE INDEX IF NOT EXISTS attempts_intent ON attempts(intent)")
            if not self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='reservations'").fetchone():
                self.db.execute("BEGIN IMMEDIATE")
                self.db.execute("CREATE TABLE reservations(cm TEXT PRIMARY KEY, intent TEXT NOT NULL REFERENCES intents(id))")
                for old in self.db.execute("SELECT id,pinned FROM intents WHERE pinned IS NOT NULL"):
                    self.db.executemany("INSERT INTO reservations VALUES(?,?)",((cm,old["id"]) for cm in json.loads(old["pinned"])))
    def __enter__(self):
        return self
    def __exit__(self,*_):
        self.db.close()

    def get(self,ident):
        r=self.db.execute("SELECT * FROM intents WHERE id=?",(identifier(ident),)).fetchone()
        if not r:
            raise ValueError("unknown intent "+ident)
        return r

    def register(self,ident,address,amount):
        if type(amount) is not int or not 0<amount<=MAX_VALUE or len(address)!=1601:
            raise ValueError("invalid intent amount/address")
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO intents(id,address,amount) VALUES(?,?,?)",
                            (identifier(ident),address,amount))
        r=self.get(ident)
        if r["address"]!=address or r["amount"]!=amount:
            raise ValueError("intent already binds a different recipient or amount")

    def attempts(self,ident):
        return self.db.execute("SELECT tx,height FROM attempts WHERE intent=? ORDER BY rowid",(ident,)).fetchall()

    def packet(self,tx):
        return self.db.execute("SELECT * FROM attempts WHERE tx=?",(tx,)).fetchone()

    def set_status(self,ident,status):
        with self.db:
            self.db.execute("UPDATE intents SET disposition=? WHERE id=?",(status,ident))

    def reserved(self,cm,ident):
        return self.db.execute("SELECT 1 FROM reservations WHERE cm=? AND intent<>?",(cm,ident)).fetchone() is not None

    def reserve(self,ident,cms):
        cms=list(cms)
        if not 1<=len(cms)<=2 or len(set(cms))!=len(cms) or any(len(bytes.fromhex(cm))!=32 for cm in cms):
            raise ValueError("invalid real inputs")
        with self.db:
            updated=self.db.execute("UPDATE intents SET pinned=? WHERE id=? AND pinned IS NULL",(json.dumps(cms),ident))
            if updated.rowcount:
                self.db.executemany("INSERT INTO reservations VALUES(?,?)",((cm,ident) for cm in cms))
        if json.loads(self.get(ident)["pinned"])!=cms:
            raise ValueError("existing reservation differs")

    def prepare(self,ident,raw,state,payment,wall):
        tx=hashlib.sha256(raw).hexdigest()
        account={k:payment[k] for k in ("amount","fee","change","input_total","real_inputs")}
        account["encoded_bytes"]=len(raw)
        intent=self.get(ident)
        if (list(payment["input_commitments"])!=json.loads(intent["pinned"]) or account["amount"]!=intent["amount"] or account["fee"]!=FEE or account["change"]<0
                or account["input_total"]!=account["amount"]+FEE+account["change"]
                or account["real_inputs"]!=len(json.loads(intent["pinned"]))):
            raise ValueError("prover accounting differs from persisted intent")
        with self.db:
            self.db.execute("UPDATE attempts SET packet=NULL WHERE intent=?",(ident,))
            self.db.execute("INSERT INTO attempts VALUES(?,?,?,?,?,?,?)",
                (tx,ident,state.height,state.tip.hex(),raw,json.dumps(account),wall))
            self.db.execute("UPDATE intents SET disposition='prepared' WHERE id=?",(ident,))
        return self.packet(tx)

    def summary(self,ident):
        r=self.get(ident)
        return dict(intent=ident,amount=r["amount"],last_observed=r["disposition"],
                    attempts=[x["tx"] for x in self.attempts(ident)])

    def drive(self,lab,node,state,ident,syncs,wait_seconds):
        """The node may have accepted a packet even if the connection reported an error."""
        from chain import WINDOW
        row=self.get(ident)
        until=time.monotonic()+wait_seconds
        frames=[]
        refreshed=False
        created=0
        last_ack=None
        last_rejection=None
        force_new=False
        def result(attempt,status):
            self.set_status(ident,status)
            info=self.summary(ident)
            account=json.loads(attempt["accounting"])
            encoded_bytes=account.pop("encoded_bytes",len(attempt["packet"]) if attempt["packet"] is not None else None)
            return dict(info,status=status,tx=attempt["tx"],anchor_height=attempt["height"],
                packet_B=encoded_bytes,
                proving_wall_s=attempt["prove_s"],submission_frame=frames[-1] if frames else {},
                submission_frames=frames,last_rejection=last_rejection,**account)
        while True:
            if refreshed:
                update=state.synchronize(lab,node)
                syncs.append(update)
                if update["rewound_blocks"] or update["branch_changes"]:
                    last_ack=None
            refreshed=True
            attempts=self.attempts(ident)
            included=[a["tx"] for a in attempts if state.has_payment(bytes.fromhex(a["tx"]))]
            if len(included)>1:
                raise RuntimeError("multiple authorized attempts included for the same intent")
            if included:
                return result(self.packet(included[0]),"confirmed")
            if row["pinned"] is None:
                self.reserve(ident,state.select(row["amount"],exclude=lambda cm:self.reserved(cm,ident)))
                row=self.get(ident)
            pins=tuple(json.loads(row["pinned"]))
            if any(v!="unspent" for v in state.input_status(pins).values()):
                self.set_status(ident,"input-unavailable")
                raise ValueError("reserved real input unavailable on selected branch; resume intent "+ident+" after reconciliation")
            attempt=self.packet(attempts[-1]["tx"]) if attempts else None
            if attempt is None or force_new or state.height-attempt["height"]>=WINDOW:
                if created>=MAX_ATTEMPTS_PER_CALL or (wait_seconds and created and time.monotonic()>=until):
                    raise ValueError("no eligible inclusion observed; resume saved intent "+ident)
                t=time.monotonic()
                raw=state.pay(row["amount"],row["address"],pins)
                attempt=self.prepare(ident,raw,state,state.last_payment,time.monotonic()-t)
                created+=1
                force_new=False
                last_ack=None
            if last_ack!=attempt["tx"]:
                meter={}
                try:
                    reply,_=lab.request(node,"submit",attempt["packet"],meter=meter)
                except OSError as e:
                    self.set_status(ident,"uncertain")
                    raise ConnectionError("submission reply unavailable; resume saved intent "+ident) from e
                except ValueError as e:
                    reason=str(e)
                    if reason not in {"anchor age","anchor branch","spent nullifier","previous commitment","pool conflict","pool full"}:
                        raise
                    frames.append(dict(meter,outcome=reason))
                    last_rejection=reason
                    last_ack=None
                    # Recheck canonical effects before building another authorization.
                    if reason in {"anchor age","anchor branch"}:
                        force_new=True
                        continue
                    if reason in {"spent nullifier","previous commitment"}:
                        syncs.append(state.synchronize(lab,node))
                        for old in self.attempts(ident):
                            if state.has_payment(bytes.fromhex(old["tx"])):
                                return result(self.packet(old["tx"]),"confirmed")
                    if not wait_seconds or time.monotonic()>=until:
                        raise ValueError(reason+"; resume saved intent "+ident) from e
                else:
                    if reply.get("id")!=attempt["tx"]:
                        raise ValueError("submission identity mismatch; resume saved intent "+ident)
                    frames.append(dict(meter,outcome="accepted",duplicate=bool(reply["duplicate"])))
                    last_ack=attempt["tx"]
                    if not wait_seconds:
                        return result(attempt,"submitted")
                self.set_status(ident,"submitted" if last_ack else "pending")
            if time.monotonic()>=until:
                return result(attempt,"submitted" if last_ack else "pending")
            time.sleep(min(.7,max(0,until-time.monotonic())))
