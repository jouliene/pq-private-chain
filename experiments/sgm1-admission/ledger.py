"""Durable isolated selected-branch ledger. The coordinator orders blocks; this is not PoW consensus."""
import contextlib
import sqlite3
import subprocess
import sys
from packets import (ANCHOR_WINDOW, HERE, anchor, check_signatures, digest, funded, parse, need)
from relation import DEPTH, h, leaf, parent, le
from fixtures_public import read_prefix

SCHEMA = """
CREATE TABLE config(pin BLOB PRIMARY KEY, chain BLOB NOT NULL);
CREATE TABLE blocks(height INTEGER PRIMARY KEY, id BLOB NOT NULL UNIQUE, root BLOB NOT NULL,
                    count INTEGER NOT NULL, anchor BLOB NOT NULL UNIQUE, fees INTEGER NOT NULL, wire BLOB);
CREATE TABLE nodes(level INTEGER NOT NULL, pos INTEGER NOT NULL, val BLOB NOT NULL,
                   PRIMARY KEY(level,pos)) WITHOUT ROWID;
CREATE TABLE undo(height INTEGER NOT NULL, level INTEGER NOT NULL, pos INTEGER NOT NULL, old BLOB,
                  PRIMARY KEY(height,level,pos)) WITHOUT ROWID;
CREATE TABLE spends(nf BLOB PRIMARY KEY, height INTEGER NOT NULL) WITHOUT ROWID;
CREATE INDEX spends_height ON spends(height);
CREATE TABLE outputs(pos INTEGER PRIMARY KEY, occ BLOB NOT NULL UNIQUE, cm BLOB NOT NULL, height INTEGER NOT NULL);
"""

class Ledger:
    def __init__(self, path, public, expected_pin):
        self.db = sqlite3.connect(path,isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.empty = [h("empty")]
        for l in range(DEPTH):
            self.empty.append(parent(l,self.empty[-1],self.empty[-1]))
        if not self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='config'").fetchone():
            pin,chain,rows = read_prefix(public)
            need(pin == expected_pin,"wrong funding pin")
            self.pin,self.chain=pin,chain
            # DDL and initial funding publish in the same commit.
            self.db.executescript("BEGIN IMMEDIATE;"+SCHEMA)
            try:
                self.db.execute("INSERT INTO config VALUES(?,?)",(pin,chain))
                root=self.append_outputs(0,0,rows)
                ident=digest(b"SGM1/isolated-genesis/v1"+pin+chain+root)
                self.insert_block(0,ident,root,len(rows),0,None)
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
        else:
            self.pin,self.chain=self.db.execute("SELECT pin,chain FROM config").fetchone()
            need(self.pin==expected_pin,"database registered to another genesis")

    @contextlib.contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def close(self):
        self.db.close()

    def insert_block(self,height,ident,root,count,fees,wire):
        a=anchor(self.pin.hex(),self.chain,root,count)
        self.db.execute("INSERT INTO blocks VALUES(?,?,?,?,?,?,?)",(height,ident,root,count,a,fees,wire))

    def tip(self):
        return self.db.execute("SELECT height,id,root,count,fees FROM blocks ORDER BY height DESC LIMIT 1").fetchone()

    def append_outputs(self,height,start,rows):
        need(start+len(rows)<=1<<DEPTH,"tree capacity")
        changed={}
        for i,(occ,cm) in enumerate(rows,start):
            self.db.execute("INSERT INTO outputs VALUES(?,?,?,?)",(i,occ,cm,height))
            changed[i]=leaf(occ,cm)
        for level in range(DEPTH+1):
            for pos,val in changed.items():
                old=self.db.execute("SELECT val FROM nodes WHERE level=? AND pos=?",(level,pos)).fetchone()
                if height:
                    self.db.execute("INSERT INTO undo VALUES(?,?,?,?)",(height,level,pos,old[0] if old else None))
                self.db.execute("INSERT OR REPLACE INTO nodes VALUES(?,?,?)",(level,pos,val))
            if level==DEPTH:
                return changed[0]
            def child(pos):
                if pos in changed:
                    return changed[pos]
                old=self.db.execute("SELECT val FROM nodes WHERE level=? AND pos=?",(level,pos)).fetchone()
                return old[0] if old else self.empty[level]
            changed={i:parent(level,child(2*i),child(2*i+1)) for i in {j>>1 for j in changed}}

    def select(self,legs):
        height=self.tip()[0]
        statements=[]
        for leg in legs:
            b=leg.body
            row=self.db.execute("SELECT root,count FROM blocks WHERE anchor=? AND height>=?",
                                (b.anchor,max(0,height+1-ANCHOR_WINDOW))).fetchone()
            need(row is not None,"ineligible branch anchor")
            need(not b.role or height+1<=b.expiry,"swap expired")
            for nf in b.nfs:
                need(not self.db.execute("SELECT 1 FROM spends WHERE nf=?",(nf,)).fetchone(),"already spent")
            statements.append(leg.statement(self.chain,*row).encode())
        return tuple(statements)

    def prepare(self,wire,backend="native"):
        """Only the ordered writer selects statements; only successful checks yield a commit."""
        legs=parse(wire)
        statements=self.select(legs)
        def verify():
            verify_operation(self.pin,self.chain,legs,statements,backend)
            def apply():
                self._apply_verified(wire,legs,statements)
            return apply
        return len(legs),verify

    def _apply_verified(self,wire,legs,statements):
        # Internal continuation of the verification call. It is never a transport input.
        # This ordered writer rechecks the current branch and spentness under its write lock.
        need(self.select(legs)==statements,"branch changed during verification")
        height,prev,_,count,fees=self.tip()
        height+=1
        effects=[]
        for leg in legs:
            self.db.executemany("INSERT INTO spends VALUES(?,?)",[(nf,height) for nf in leg.body.nfs])
            effects.extend(leg.rows(self.chain))
        root=self.append_outputs(height,count,effects)
        fee=sum(l.body.fee for l in legs)
        need(fees+fee <= (1<<63)-1,"research fee counter range")
        self.insert_block(height,digest(b"SGM1/isolated-block/v1"+prev+le(height,8)+digest(wire)),
                          root,count+len(effects),fees+fee,wire)

    def admit(self,wire,backend="native"):
        _,verify=self.prepare(wire,backend)
        apply=verify()
        with self.transaction():
            apply()

    def replace_suffix(self,keep,wires):
        with self.transaction():
            tip=self.tip()[0]
            need(0<=keep<=tip,"unknown fork point")
            for height in range(tip,keep,-1):
                for level,pos,old in self.db.execute("SELECT level,pos,old FROM undo WHERE height=?",(height,)):
                    if old is None:
                        self.db.execute("DELETE FROM nodes WHERE level=? AND pos=?",(level,pos))
                    else:
                        self.db.execute("UPDATE nodes SET val=? WHERE level=? AND pos=?",(old,level,pos))
            for table in ("undo","spends","outputs","blocks"):
                self.db.execute(f"DELETE FROM {table} WHERE height>?",(keep,))
            for wire in wires:
                _,verify=self.prepare(wire)
                apply=verify()
                apply()

def verify_operation(pin,chain,legs,statements,backend):
    need(len(legs)==len(statements),"statement cardinality")
    for leg,st in zip(legs,statements,strict=True):
        if backend=="reference":
            r=subprocess.run([sys.executable,"-B",HERE/"reference.py","verify",pin.hex()],
                             input=st+leg.proof,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            if r.returncode==3:
                raise ValueError("reference proof rejected")
            if r.returncode:
                raise RuntimeError(f"reference verifier failed with exit {r.returncode}")
        elif backend=="native":
            from native.verify import verify
            verify(pin,st,leg.proof)
        else:
            raise ValueError("unregistered verifier")
    check_signatures(legs,chain)
