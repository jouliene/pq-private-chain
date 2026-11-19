"""Content-addressed retained PoW cores, independently checked proof sources, and crash-atomic compaction."""
from contextlib import contextmanager
from hashlib import sha256
import os
from pathlib import Path
import sqlite3
import struct
import sys
from block_format import COMPACT, EFFECT_SIZE, MAGIC, core, effects, identity

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/"crypto"))


class MissingEvidence(ValueError):
    pass


def decode_core(raw, network):
    if (len(raw)<222 or raw[:8]!=MAGIC or raw[8:40]!=network or raw[213]>4
        or len(raw)!=222+32*raw[213]):
        raise ValueError("invalid archival core")
    return tuple(raw[i:i+32] for i in range(214,len(raw)-8,32))


def hydrate(raw, attachments):
    if len(attachments)!=raw[213]:
        raise ValueError("incomplete attachment set")
    return raw[:214]+b"".join(struct.pack("<I",len(p))+p for p in attachments)+raw[-8:]


def serialized(slot):
    return (slot.anchor+struct.pack("<I",slot.height)+b"".join((*slot.nfs,*slot.cms))
            +struct.pack("<Q",slot.fee)+b"".join(slot.cts))


class Store:
    def __init__(self,path):
        self.db=sqlite3.connect(path,isolation_level=None)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA secure_delete=ON")
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS cores(seq INTEGER PRIMARY KEY,id BLOB UNIQUE NOT NULL, body BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS proofs(id BLOB PRIMARY KEY, body BLOB NOT NULL) WITHOUT ROWID;
          CREATE TABLE IF NOT EXISTS links(sid BLOB PRIMARY KEY,id BLOB NOT NULL REFERENCES proofs(id)) WITHOUT ROWID;
        """)

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def link(self,sid):
        row=self.db.execute("SELECT id FROM links WHERE sid=?",(sid,)).fetchone()
        if row is None:
            raise MissingEvidence(sid.hex())
        return row[0]

    def body(self,table,key):
        if table not in ("cores","proofs"):
            raise ValueError("unknown evidence type")
        row=self.db.execute("SELECT body FROM "+table+" WHERE id=?",(key,)).fetchone()
        if row is None:
            raise MissingEvidence(key.hex())
        return row[0]

    def inventory(self,start,limit):
        if type(start)!=int or type(limit)!=int or start<0 or not 1<=limit<=64:
            raise ValueError("inventory bounds")
        return [r[0].hex() for r in self.db.execute("SELECT id FROM cores WHERE seq>? ORDER BY seq LIMIT ?",(start,limit))]

    def put_core(self,bid,body):
        self.db.execute("INSERT OR IGNORE INTO cores(id,body) VALUES(?,?)",(bid,body))
        if self.body("cores",bid)!=body:
            raise ValueError("conflicting PoW core")

    def add(self,body,checked,compact=False,interrupt=False):
        # 'checked' is a process-local verifier service. No caller supplies a verdict or effect list.
        rows=checked.read(body)
        cid=sha256(body).digest()
        with self.transaction():
            self.db.execute("INSERT OR IGNORE INTO proofs VALUES(?,?)",(cid,body))
            if self.body("proofs",cid)!=body:
                raise ValueError("evidence digest conflict")
            for sid in rows:
                if compact:
                    current=self.link(sid)
                    old=checked.read(self.body("proofs",current))
                    if rows[sid]!=old[sid]:
                        raise ValueError("replacement effect mismatch")
                    self.db.execute("UPDATE links SET id=? WHERE sid=?",(cid,sid))
                else:
                    self.db.execute("INSERT OR IGNORE INTO links VALUES(?,?)",(sid,cid))
            self.db.execute("DELETE FROM proofs WHERE NOT EXISTS (SELECT 1 FROM links WHERE links.id=proofs.id)")
            if interrupt:
                os._exit(73)  # Test fault after replacements and deletes, before SQLite COMMIT.
        return cid

    def counts(self):
        def aggregate(table):
            return list(self.db.execute("SELECT count(*),coalesce(sum(length(body)),0) FROM "+table).fetchone())
        shapes=self.db.execute("SELECT substr(body,1,4),count(*),sum(length(body)) FROM proofs GROUP BY 1")
        links=self.db.execute("SELECT count(*) FROM links").fetchone()[0]
        cores,proofs=aggregate("cores"),aggregate("proofs")
        # Self-describing interchange: 8-byte magic, 2 u32 counts; each record type
        # is determined by its section. CIDs and SID->source routing derive from verified contents.
        wire=16+4*(cores[0]+proofs[0])+cores[1]+proofs[1]
        return dict(cores=cores,sources=proofs,linked_sids=links,by_source={r[0].decode():list(r[1:]) for r in shapes},
                    interchange_B=wire,sqlite_B=self.db.execute("PRAGMA page_count").fetchone()[0]*self.db.execute("PRAGMA page_size").fetchone()[0])

    def export(self,path):
        with Path(path).open("xb") as f:
            c=self.counts()
            f.write(b"D8ARCH01"+struct.pack("<II",c["cores"][0],c["sources"][0]))
            for table,order in (("cores","seq"),("proofs","id")):
                for body, in self.db.execute("SELECT body FROM "+table+" ORDER BY "+order):
                    f.write(struct.pack("<I",len(body)));f.write(body)
        if Path(path).stat().st_size!=c["interchange_B"]:
            raise ValueError("archive length mismatch")


class Checks:
    def __init__(self,net,runtime):
        import chain
        from run import Resources
        from runtime import config
        from certrole import CertificateVerifier
        self.network=chain.NETWORK
        self.direct=Resources(config(net/"runtime"))
        self.outer=CertificateVerifier(runtime/"native",(runtime/"approval.sha256").read_text().strip(),runtime/"keys")
        self.outer.__enter__()
        self.memo={}
        self.calls={"outer":0,"direct":0}

    def read(self,body):
        key=sha256(body).digest()
        if key in self.memo:
            return self.memo[key]
        if body[:4]==b"D8C1":
            values=self.outer.verify(body)
            self.calls["outer"]+=1
        elif body[:4]==b"DLF1":
            slot,=self.direct.backend.verify(body)
            value=serialized(slot)
            if effects(body)!=value:
                raise ValueError("direct identity decoder disagrees with registered verifier")
            values=[value]
            self.calls["direct"]+=1
        else:
            raise ValueError("unrecognized proof source")
        rows={}
        for value in values:
            if len(value)!=EFFECT_SIZE:
                raise ValueError("malformed verified slot")
            sid=identity(self.network,COMPACT+value)
            if sid in rows:
                raise ValueError("ambiguous source")
            rows[sid]=value
        if len(self.memo)>=32:
            self.memo.pop(next(iter(self.memo)))
        self.memo[key]=rows
        return rows

    def close(self):
        self.direct.close()
        self.outer.__exit__(None,None,None)


class ColdBackend:
    def __init__(self,store,checks):
        self.store,self.checks=store,checks
        self.direct=checks.direct.backend
        self.hashes,self.profile_id=self.direct.hashes,self.direct.profile_id
        self.header_id=self.direct.header_id

    def verify(self,packet):
        if packet[:4]!=COMPACT:
            return self.direct.verify(packet)
        from state import Slot
        sid=identity(self.checks.network,packet)
        body=self.store.body("proofs",self.store.link(sid))
        value=self.checks.read(body).get(sid)
        if value is None or packet!=COMPACT+value:
            raise ValueError("missing or unverified historical authorization")
        return [Slot(value[:32],int.from_bytes(value[32:36],"little"),(value[36:68],value[68:100]),
                     (value[100:132],value[132:164]),int.from_bytes(value[164:172],"little"),
                     (value[172:1964],value[1964:]))]


def enable_cold_chain():
    """Accept internal effect attachments only with ColdBackend. Ordinary network admission stays DLF1."""
    import chain
    direct_width=chain.packet_width
    def width(packet):
        if packet[:4]==COMPACT and len(packet)==4+EFFECT_SIZE:
            return 1
        return direct_width(packet)
    chain.packet_width=width
    class ColdChain(chain.Chain):
        def offer(self,packet):
            direct_width(packet)
            return super().offer(packet)
        def _refresh(self,detached,included):
            return super()._refresh((p for p in detached if p[:4]!=COMPACT),included)
    return ColdChain
