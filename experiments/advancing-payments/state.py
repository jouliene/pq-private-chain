"""Branch-local authenticated payment state. All remote input is genesis or a complete canonical block."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import sqlite3
import struct

from wire import CT, LIMIT, ZERO, canonical, check_genesis, digest, header_parts, need, packet_width, pieces, sha, split_block, u32, u64

WINDOW = 8
UNDO = 8
MAX_NOTES = 4**20
MAX_FEE_TOTAL = 2**63-1


class Frontier:
    """Completed base-four siblings. The count fixes the number of digests in every level."""
    def __init__(self, count, raw, hash_role):
        need(0 <= count <= MAX_NOTES, "tree capacity")
        nodes = pieces(raw, 32)
        need(all(canonical(n) for n in nodes), "frontier canonicality")
        self.count, self.levels, self.hash = count, [], hash_role
        end, digits = 0, count
        while digits:
            k = digits % 4
            self.levels.append(nodes[end:end+k])
            end += k
            digits //= 4
        need(end == len(nodes), "frontier width")

    def combine(self, children):
        r = self.hash.call(b"N"+b"".join(children))
        need(canonical(r), "node digest")
        return r

    def append(self, leaf):
        need(canonical(leaf) and leaf != ZERO and self.count < MAX_NOTES, "funded leaf/capacity")
        for i in range(21):
            if i == len(self.levels):
                self.levels.append([])
            row = self.levels[i]
            row.append(leaf)
            if len(row) < 4:
                break
            leaf = self.combine(row)
            row.clear()
        self.count += 1

    def root(self):
        if not self.count:
            return ZERO
        depth = max(1, ((self.count-1).bit_length()+1)//2)
        carry = None
        for row in self.levels[:depth]:
            active = row + ([carry] if carry is not None else [])
            if active:
                carry = self.combine(active + [ZERO]*(4-len(active)))
        if carry is None:
            return self.levels[depth][0]
        return carry

    def encode(self):
        return b"".join(n for row in self.levels for n in row)


@dataclass(frozen=True)
class Slot:
    anchor: bytes
    height: int
    nfs: tuple
    cms: tuple
    fee: int
    cts: tuple

    def transition(self):
        return b"".join((*self.nfs,*self.cms,u64(self.fee)))


class PublicBackend:
    """Node-owned processes. The node always verifies the submitted proof bytes afresh."""
    def __init__(self, hashes, verifier, profile_id):
        self.profile_id=bytes.fromhex(profile_id)
        need(len(self.profile_id)==32,"profile identity")
        self.hashes=hashes
        self.verifier=verifier

    def header_id(self, raw):
        header_parts(raw)
        h=self.hashes.call(b"H"+raw)
        need(canonical(h), "registered header hash")
        return h

    def verify(self, packet):
        count=packet_width(packet)
        reply=self.verifier.call(packet)
        stride=32+4+64+64+8+2*CT
        need(len(reply)==1+count*stride and reply[:1]==b"1", "cryptographic payment rejection")
        slots=[]
        for row in pieces(reply[1:],stride):
            height,=struct.unpack_from("<I",row,32)
            fee,=struct.unpack_from("<Q",row,164)
            slot=Slot(row[:32],height,tuple(pieces(row[36:100],32)),tuple(pieces(row[100:164],32)),fee,
                      tuple(pieces(row[172:],CT)))
            need(canonical(slot.anchor) and all(canonical(w) for w in (*slot.nfs,*slot.cms)), "verified effect encoding")
            need(all(w!=ZERO for w in slot.cms) and 0<fee<2**62, "verified effect bounds")
            slots.append(slot)
        need(b"".join(ct for slot in slots for ct in slot.cts)==packet[-2*CT*count:], "ordered receipt sidecars")
        return slots


class Ledger:
    def __init__(self,path,backend,genesis,approved,create=False,prune=False):
        self.backend=backend
        self.path=Path(path)
        if create:
            with self.path.open("xb"): pass
        self.db=sqlite3.connect(self.path.resolve().as_uri()+"?mode=rw",uri=True,isolation_level=None,timeout=30)
        self.db.row_factory=sqlite3.Row
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=DELETE")
        leaves=check_genesis(genesis,approved)
        if create:
            self.db.executescript("""
              CREATE TABLE config (id INTEGER PRIMARY KEY CHECK (id=1), genesis TEXT, profile BLOB, prune INTEGER, floor INTEGER);
              CREATE TABLE blocks (h INTEGER PRIMARY KEY,id BLOB UNIQUE NOT NULL,header BLOB NOT NULL,fees INTEGER NOT NULL,n INTEGER NOT NULL,frontier BLOB,body BLOB);
              CREATE TABLE outs (pos INTEGER PRIMARY KEY,cm BLOB UNIQUE NOT NULL,h INTEGER REFERENCES blocks(h) ON DELETE CASCADE);
              CREATE INDEX outs_h ON outs(h);
              CREATE TABLE spent (nf BLOB PRIMARY KEY,h INTEGER REFERENCES blocks(h) ON DELETE CASCADE) WITHOUT ROWID;
              CREATE INDEX spent_h ON spent(h);
            """)
            frontier=Frontier(0,b"",backend.hashes)
            for leaf in leaves:
                frontier.append(leaf)
            header=ZERO+u32(0)+digest(b"genesis-state",backend.profile_id,genesis)+digest(b"genesis-data",genesis)+frontier.root()
            with self.transaction():
                self.db.execute("INSERT INTO config VALUES (1,?,?,?,0)",(approved,backend.profile_id,int(prune)))
                self.db.execute("INSERT INTO blocks VALUES (0,?,?,0,?,?,NULL)",(backend.header_id(header),header,len(leaves),frontier.encode()))
                self.db.executemany("INSERT INTO outs VALUES (?,?,0)",enumerate(leaves))
        row=self.db.execute("SELECT genesis,profile,prune FROM config WHERE id=1").fetchone()
        need(row is not None and row["genesis"]==approved and row["profile"]==backend.profile_id,"database chain identity")
        self.prune=bool(row["prune"])

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def head(self):
        return self.db.execute("SELECT h,id,header,n,fees,frontier FROM blocks ORDER BY h DESC LIMIT 1").fetchone()

    def leaves(self):
        return b"".join(r[0] for r in self.db.execute("SELECT cm FROM outs ORDER BY pos"))

    def nfs(self):
        return b"".join(r[0] for r in self.db.execute("SELECT nf FROM spent ORDER BY nf"))

    def _effects(self,packet,parent):
        H=parent["h"]+1
        need(H<=2**32-1 and len(packet)<=LIMIT,"block bounds")
        slots=self.backend.verify(packet) if packet else []
        nfs,cms=[],[]
        fees=parent["fees"]
        for slot in slots:
            need(1<=H-slot.height<=WINDOW,"anchor expired or future")
            anchor=self.db.execute("SELECT id FROM blocks WHERE h=?",(slot.height,)).fetchone()
            need(anchor is not None and anchor[0]==slot.anchor,"anchor branch")
            nfs.extend(slot.nfs)
            cms.extend(slot.cms)
            fees+=slot.fee
        need(fees<=MAX_FEE_TOTAL and len(set(nfs))==len(nfs) and len(set(cms))==len(cms),"intra-block conflict or fees")
        for nf in nfs:
            need(not self.db.execute("SELECT 1 FROM spent WHERE nf=?",(nf,)).fetchone(),"spent nullifier")
        for cm in cms:
            need(not self.db.execute("SELECT 1 FROM outs WHERE cm=?",(cm,)).fetchone(),"previous commitment")
        return slots,nfs,cms,fees

    def inspect(self,packet):
        # Intake may race a later branch change. Admission always repeats these checks.
        slots,_,_,_=self._effects(packet,self.head())
        return slots

    def _step(self,packet,nonce,expected_header=None):
        parent=self.head()
        H=parent["h"]+1
        slots,nfs,cms,fees=self._effects(packet,parent)
        frontier=Frontier(parent["n"],parent["frontier"],self.backend.hashes)
        for cm in cms:
            frontier.append(cm)
        state=digest(b"state",parent["header"][36:68],u64(frontier.count),u64(fees),b"".join(s.transition() for s in slots))
        header=parent["id"]+u32(H)+state+digest(b"block-data",u64(nonce),packet)+frontier.root()
        if expected_header is not None:
            need(header==expected_header,"incoming block header or ancestry")
        bid=self.backend.header_id(header)
        block=b"APBLOCK1"+header+u64(nonce)+u32(len(packet))+packet
        self.db.execute("INSERT INTO blocks VALUES (?,?,?,?,?,?,?)",(H,bid,header,fees,frontier.count,frontier.encode(),block))
        self.db.executemany("INSERT INTO outs VALUES (?,?,?)",((parent["n"]+i,cm,H) for i,cm in enumerate(cms)))
        self.db.executemany("INSERT INTO spent VALUES (?,?)",((nf,H) for nf in nfs))
        self.db.execute("UPDATE config SET floor=max(floor,?) WHERE id=1",(max(0,H-UNDO),))
        if self.prune:
            self.db.execute("UPDATE blocks SET body=NULL,frontier=NULL WHERE h=?",(H-UNDO-1,))
        return block

    def produce(self,packet,nonce):
        with self.transaction():
            return self._step(packet,nonce)

    def accept(self,block):
        hdr,nonce,packet=split_block(block)
        with self.transaction():
            return self._step(packet,nonce,hdr)

    def switch(self,base_id,blocks):
        """Locally selected fork. Failure of any replacement undoes the entire attempted switch."""
        with self.transaction():
            tip=self.head()
            base=self.db.execute("SELECT h,frontier FROM blocks WHERE id=?",(base_id,)).fetchone()
            need(base is not None and base['frontier'] is not None and tip['h']-base['h']<=UNDO
                 and base["h"]>=self.db.execute("SELECT floor FROM config WHERE id=1").fetchone()[0],"rollback horizon")
            self.db.execute("DELETE FROM blocks WHERE h>?",(base['h'],))
            for block in blocks:
                hdr,nonce,packet=split_block(block)
                self._step(packet,nonce,hdr)

    def close(self):
        self.db.close()
