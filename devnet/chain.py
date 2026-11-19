"""PQDEV1 local proof-of-work chain, persistent fork choice and direct APV2 admissions."""

from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import sqlite3
import struct
import sys
import threading

import history

AP = Path(__file__).resolve().parents[1]/"experiments/advancing-payments"
sys.path.insert(0, str(AP))
from state import Frontier
from wire import CT, ZERO, canonical, digest, need, packet_width, u32, u64

BITS = 22
WINDOW = 8
UNDO = 8
MAX_TX = 4
MAX_PENDING = 64
SUBSIDY = 100
FEE = 3
WORK = 1 << BITS
TARGET = (1 << (256-BITS))-1
MAX_PACKET = 256 * 1024
MAX_BLOCK = 214 + MAX_TX*(4+MAX_PACKET) + 8
MAX_PAGE = 128
PROFILE = bytes.fromhex("af88a0ac0caa5f0aa27d38d687b6cc39495a0aa2659ed4a7e5e74653724cc1b1")
NETWORK = sha256(b"PQDEV1/network\0"+PROFILE+struct.pack("<BBBIQ", BITS, WINDOW, MAX_TX, UNDO, SUBSIDY)).digest()
GENESIS = sha256(b"PQDEV1/genesis\0"+NETWORK).digest()
MAGIC = b"PQDEVBL1"


def packet_vector(packets):
    need(len(packets) <= MAX_TX, "block capacity")
    for p in packets:
        need(0 < len(p) <= MAX_PACKET and packet_width(p) == 1, "direct singleton required")
    return bytes([len(packets)]) + b"".join(u32(len(p))+p for p in packets)


def reward_context(parent, height, pk, vector):
    return sha256(b"PQDEV1/reward-context\0"+NETWORK+parent+u32(height)+pk+sha256(vector).digest()).digest()


def seed(template):
    return sha256(b"PQDEV1/template\0"+template).digest()


def block_id(raw):
    need(222 <= len(raw) <= MAX_BLOCK, "block size")
    return sha256(b"PQDEV1/work\0"+seed(raw[:-8])+raw[-8:]).digest()


def mine(template, start=0, attempts=None):
    """Return a sealed block, or None if a caller-specified nonce interval is exhausted."""
    decode_block(template+bytes(8))
    need(0 <= start < 2**64 and (attempts is None or 0 <= attempts <= 2**64), "nonce interval")
    prefix = b"PQDEV1/work\0"+seed(template)
    end = 2**64 if attempts is None else min(2**64, start+attempts)
    threshold = TARGET.to_bytes(32,"big")
    for n in range(start,end):
        encoded = struct.pack("<Q",n)
        if sha256(prefix+encoded).digest() <= threshold:
            return template+encoded
    return None


@dataclass(frozen=True)
class Block:
    parent: bytes
    height: int
    pk: bytes
    amount: int
    reward_cm: bytes
    state: bytes
    root: bytes
    packets: tuple
    nonce: int


def decode_block(raw):
    need(222 <= len(raw) <= MAX_BLOCK, "block size")
    need(raw[:8] == MAGIC and raw[8:40] == NETWORK and raw[40] == BITS, "block domain or difficulty")
    count = raw[213]
    need(count <= MAX_TX, "block capacity")
    i, end = 214, len(raw)-8
    packets = []
    for _ in range(count):
        need(i+4 <= end, "truncated packet size")
        size = int.from_bytes(raw[i:i+4], "little")
        i += 4
        need(0 < size <= MAX_PACKET and i+size <= end, "truncated or oversized packet")
        p = raw[i:i+size]
        need(packet_width(p) == 1, "direct singleton required")
        packets.append(p)
        i += size
    need(i == end, "trailing block bytes")
    pk = raw[77:109]
    need(canonical(pk) and pk != ZERO, "miner spend key")
    need(all(canonical(raw[i:i+32]) for i in (117,149,181)), "block field encoding")
    return Block(raw[41:73], int.from_bytes(raw[73:77],"little"), pk,
                 int.from_bytes(raw[109:117],"little"), raw[117:149], raw[149:181], raw[181:213],
                 tuple(packets), int.from_bytes(raw[-8:],"little"))


# Only these public content/state errors evict a queued offer; an unavailable worker aborts the update.
INELIGIBLE = {"cryptographic payment rejection", "anchor age", "anchor branch", "spent nullifier",
              "previous commitment", "duplicate public effect", "pool conflict", "pool full", "invalid fee"}


class Chain:
    def __init__(self, path, backend):
        need(backend.profile_id == PROFILE, "approved APV2 profile")
        self.backend = backend
        self._spent_summary = None
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, isolation_level=None, timeout=30, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("PRAGMA foreign_keys=ON")
        genesis_header = ZERO+u32(0)+digest(b"dev-genesis-state",NETWORK)+digest(b"dev-genesis-body",NETWORK)+ZERO
        try:
            with self._transaction(True):
                self.db.execute("CREATE TABLE IF NOT EXISTS config (id INTEGER PRIMARY KEY, network BLOB NOT NULL)")
                self.db.execute("CREATE TABLE IF NOT EXISTS metrics (id INTEGER PRIMARY KEY,deep_replays INTEGER NOT NULL)")
                self.db.execute("INSERT OR IGNORE INTO metrics VALUES (1,0)")
                record = self.db.execute("SELECT network FROM config WHERE id=1").fetchone()
                if record is None:
                    schema = (
                        "CREATE TABLE blocks (id BLOB PRIMARY KEY,parent BLOB,h INTEGER NOT NULL,work INTEGER NOT NULL,ap BLOB NOT NULL,header BLOB NOT NULL,fees INTEGER NOT NULL,n INTEGER NOT NULL,front BLOB NOT NULL,raw BLOB NOT NULL) WITHOUT ROWID",
                        "CREATE TABLE sel (h INTEGER PRIMARY KEY,id BLOB UNIQUE NOT NULL REFERENCES blocks(id))",
                        "CREATE TABLE outs (pos INTEGER PRIMARY KEY, cm BLOB UNIQUE NOT NULL,h INTEGER NOT NULL,ct BLOB,reward BLOB)",
                        "CREATE INDEX outs_h ON outs(h)",
                        "CREATE TABLE spent (nf BLOB PRIMARY KEY,h INTEGER NOT NULL) WITHOUT ROWID",
                        "CREATE INDEX spent_h ON spent(h)",
                        "CREATE TABLE pool (seq INTEGER PRIMARY KEY,tx BLOB UNIQUE NOT NULL,packet BLOB NOT NULL, nf0 BLOB NOT NULL,nf1 BLOB NOT NULL,cm0 BLOB NOT NULL,cm1 BLOB NOT NULL)",
                        "CREATE TABLE txloc (tx BLOB NOT NULL,bid BLOB NOT NULL REFERENCES blocks(id),idx INTEGER NOT NULL,PRIMARY KEY(tx,bid)) WITHOUT ROWID",
                    )
                    for sql in schema:
                        self.db.execute(sql)
                    self.db.execute("INSERT INTO config VALUES (1,?)",(NETWORK,))
                    self.db.execute("INSERT INTO blocks VALUES (?,?,?,?,?,?,?,?,?,?)",
                                    (GENESIS,None,0,0,backend.header_id(genesis_header),genesis_header,0,0,b"",b""))
                    self.db.execute("INSERT INTO sel VALUES (0,?)",(GENESIS,))
                else:
                    need(record[0] == NETWORK, "database network mismatch")
                    row = self._row(GENESIS)
                    need(row and row["header"] == genesis_header and row["ap"] == backend.header_id(genesis_header),
                         "database genesis mismatch")
                self.history = history.PublicHistory(self.db,NETWORK,PROFILE,GENESIS,genesis_header)
                if self.history.new:
                    self._backfill_wallet_history()
        except BaseException:
            self.db.close()
            raise

    def _backfill_wallet_history(self):
        # Older archives have no per-slot nullifier order in their selected spent index.
        # Recover authenticated order and ciphertexts from the stored, already admitted blocks once.
        stats = self.history.startup
        for bid,height,header,raw in self.db.execute("SELECT id,h,header,raw FROM blocks WHERE h>0"):
            b = decode_block(raw)
            need(block_id(raw) == bid and height == b.height and header[32:36] == u32(height)
                 and header[100:] == b.root, "archived history identity")
            ctx = reward_context(b.parent,height,b.pk,packet_vector(b.packets))
            reward = ctx+b.pk+u64(b.amount)+b.reward_cm
            slots = []
            for packet in b.packets:
                slot, = self.backend.verify(packet)
                slots.append(slot)
            ids = [sha256(packet).digest() for packet in b.packets]
            blob = history.record(height,bid,b.parent,header,reward,ids,slots)
            self.history.put(bid,blob)
            stats["archive_blocks"] += 1
            stats["archive_metadata_B"] += 32+4+132
            stats["archive_bytes"] += len(raw)
            stats["verified_packets"] += len(ids)
            stats["written_payload_B"] += len(blob)

    def history_head(self,locator):
        with self._transaction():
            return self.history.head(locator)

    def history_range(self,target,start,base,limit):
        with self._transaction():
            return self.history.page(target,start,base,limit)

    def history_check(self,target):
        with self._transaction():
            return self.history.check(target)

    @contextmanager
    def _transaction(self, write=False):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            try:
                yield
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def close(self):
        with self.lock:
            self.db.close()

    def _row(self,bid):
        return self.db.execute("SELECT id,parent,h,work,ap,header,fees,n,front FROM blocks WHERE id=?",(bid,)).fetchone()

    def _head(self):
        bid = self.db.execute("SELECT id FROM sel ORDER BY h DESC LIMIT 1").fetchone()[0]
        return self._row(bid)

    def _status(self):
        head = self._head()
        if self._spent_summary is None or self._spent_summary[0] != head["id"]:
            hasher = sha256()
            count = 0
            for row in self.db.execute("SELECT nf FROM spent ORDER BY nf"):
                hasher.update(row[0])
                count += 1
            self._spent_summary = (head["id"],count,hasher.hexdigest())
        return dict(tip=head["id"].hex(), height=head["h"], work=head["work"], anchor=head["ap"].hex(),
                    header=head["header"].hex(), issued=head["h"]*SUBSIDY, fees=head["fees"], notes=head["n"],
                    spent=self._spent_summary[1], spent_set_sha256=self._spent_summary[2],
                    deep_replays=self.db.execute("SELECT deep_replays FROM metrics WHERE id=1").fetchone()[0],
                    mempool=self.db.execute("SELECT count(*) FROM pool").fetchone()[0],
                    network=NETWORK.hex(), genesis=GENESIS.hex())

    def status(self):
        with self._transaction():
            return self._status()

    def has(self,bid):
        with self._transaction():
            return self.db.execute("SELECT 1 FROM blocks WHERE id=?",(bid,)).fetchone() is not None

    def block(self,bid):
        with self._transaction():
            row = self.db.execute("SELECT raw FROM blocks WHERE id=?",(bid,)).fetchone()
            need(row is not None,"unknown block")
            return row[0]

    def tx(self,txid):
        with self._transaction():
            row = self.db.execute("SELECT packet FROM pool WHERE tx=?",(txid,)).fetchone()
            if row:
                return row[0]
            row = self.db.execute("SELECT raw,idx FROM txloc JOIN blocks ON blocks.id=bid JOIN sel ON sel.id=bid WHERE tx=? LIMIT 1",(txid,)).fetchone()
            return decode_block(row[0]).packets[row[1]] if row else None

    def selected(self,start,limit):
        need(0 <= start < 2**32+1 and 1 <= limit <= MAX_PAGE, "height page")
        with self._transaction():
            return [r[0].hex() for r in self.db.execute("SELECT id FROM sel WHERE h>=? ORDER BY h LIMIT ?",(start,limit))]

    def locator(self):
        with self._transaction():
            h = self._head()["h"]
            heights = []
            step = 1
            while h:
                heights.append(h)
                h = max(0,h-step)
                if len(heights) >= UNDO:
                    step *= 2
            return [self.db.execute("SELECT id FROM sel WHERE h=?",(i,)).fetchone()[0].hex() for i in (*heights,0)]

    def after(self,locator,limit):
        need(1 <= len(locator) <= MAX_PAGE and 1 <= limit <= MAX_PAGE,"locator bounds")
        with self._transaction():
            for entry in locator:
                bid = bytes.fromhex(entry) if isinstance(entry,str) else entry
                need(isinstance(bid,bytes) and len(bid) == 32,"locator identifier")
                row = self.db.execute("SELECT h FROM sel WHERE id=?",(bid,)).fetchone()
                if row:
                    return [r[0].hex() for r in self.db.execute(
                        "SELECT id FROM sel WHERE h>? ORDER BY h LIMIT ?",(row[0],limit))]
            raise ValueError("no selected locator")

    def page(self,kind,start,limit,tip_hex):
        tables = {"leaves": ("cm","outs","","pos"), "receipts": ("cm,ct","outs","WHERE ct IS NOT NULL","pos"),
                  "rewards": ("reward","outs","WHERE reward IS NOT NULL","pos"), "nfs": ("nf","spent","","nf")}
        need(kind in tables and 0 <= start <= 2**63-1 and 1 <= limit <= MAX_PAGE, "wallet page bounds")
        columns, table, where, order = tables[kind]
        with self._transaction():
            need(self._head()["id"].hex() == tip_hex, "wallet tip changed")
            rows = self.db.execute(f"SELECT {columns} FROM {table} {where} ORDER BY {order} LIMIT ? OFFSET ?",
                                   (limit+1,start)).fetchall()
            return b"".join(b"".join(row) for row in rows[:limit]), start+limit if len(rows)>limit else None

    def pending(self):
        with self._transaction():
            return [r[0].hex() for r in self.db.execute("SELECT tx FROM pool ORDER BY seq")]

    def _effects(self,packet,head):
        need(0 < len(packet) <= MAX_PACKET and packet_width(packet) == 1,"direct singleton required")
        slots = self.backend.verify(packet)
        need(len(slots) == 1, "direct singleton required")
        s = slots[0]
        need(s.fee == FEE, "invalid fee")
        need(1 <= head["h"]+1-s.height <= WINDOW, "anchor age")
        row = self.db.execute("SELECT ap FROM sel JOIN blocks USING(id) WHERE sel.h=?",(s.height,)).fetchone()
        need(row and row[0] == s.anchor, "anchor branch")
        need(len(set(s.nfs)) == 2 and len(set(s.cms)) == 2, "duplicate public effect")
        for nf in s.nfs:
            need(not self.db.execute("SELECT 1 FROM spent WHERE nf=?",(nf,)).fetchone(),"spent nullifier")
        for cm in s.cms:
            need(not self.db.execute("SELECT 1 FROM outs WHERE cm=?",(cm,)).fetchone(),"previous commitment")
        return s

    def _enqueue(self,packet,head):
        txid = sha256(packet).digest()
        if self.db.execute("SELECT 1 FROM pool WHERE tx=?",(txid,)).fetchone():
            return txid,True
        need(self.db.execute("SELECT count(*) FROM pool").fetchone()[0] < MAX_PENDING,"pool full")
        s = self._effects(packet,head)
        for col, values in (("nf",s.nfs),("cm",s.cms)):
            need(not self.db.execute(f"SELECT 1 FROM pool WHERE {col}0 IN (?,?) OR {col}1 IN (?,?)",values+values).fetchone(),
                 "pool conflict")
        self.db.execute("INSERT INTO pool(tx,packet,nf0,nf1,cm0,cm1) VALUES (?,?,?,?,?,?)",
                        (txid,packet,*s.nfs,*s.cms))
        return txid,False

    def offer(self,packet):
        with self._transaction(True):
            txid,duplicate = self._enqueue(packet,self._head())
            return dict(id=txid.hex(),duplicate=duplicate)

    def _candidate(self,head,pk,packets):
        h = head["h"]+1
        need(h < 2**32 and canonical(pk) and pk != ZERO,"height or miner spend key")
        vector = packet_vector(packets)
        slots = [self._effects(p,head) for p in packets]
        cms = [cm for s in slots for cm in s.cms]
        nfs = [nf for s in slots for nf in s.nfs]
        need(len(set(cms)) == len(cms) and len(set(nfs)) == len(nfs), "duplicate public effect")
        fees = sum(s.fee for s in slots)
        reward,total_fees = SUBSIDY+fees,head["fees"]+fees
        need(reward < 2**62 and total_fees+h*SUBSIDY < 2**63, "issuance bounds")
        ctx = reward_context(head["id"],h,pk,vector)
        cm = self.backend.hashes.call(b"C"+ctx+pk+u64(reward))
        need(canonical(cm) and cm != ZERO, "public reward commitment")
        need(cm not in cms and not self.db.execute("SELECT 1 FROM outs WHERE cm=?",(cm,)).fetchone(),"previous commitment")
        rec = ctx+pk+u64(reward)+cm
        frontier = Frontier(head["n"],head["front"],self.backend.hashes)
        for leaf in (*cms,cm):
            frontier.append(leaf)
        state = digest(b"dev-state",NETWORK,head["header"][36:68],u64(frontier.count),u64(h*SUBSIDY),
                       u64(total_fees),rec,b"".join(s.transition() for s in slots))
        root = frontier.root()
        template = MAGIC+NETWORK+bytes([BITS])+head["id"]+u32(h)+pk+u64(reward)+cm+state+root+vector
        return template, slots, rec, frontier, total_fees

    def template(self,pk,packets=None):
        with self._transaction():
            if packets is None:
                packets = tuple(r[0] for r in self.db.execute("SELECT packet FROM pool ORDER BY seq LIMIT ?",(MAX_TX,)))
            return self._candidate(self._head(),pk,packets)[0]

    def _persist(self,data,txids,wallet_record):
        self.db.execute("INSERT INTO blocks VALUES (?,?,?,?,?,?,?,?,?,?)",data)
        self.db.executemany("INSERT INTO txloc VALUES (?,?,?)",
                            ((txid,data[0],i) for i,txid in enumerate(txids)))
        self.history.put(data[0],wallet_record)

    def _attach(self,raw,parsed,bid,existing=False):
        head = self._head()
        need(head["id"] == parsed.parent and head["h"]+1 == parsed.height,"block ancestry or height")
        expected, slots, rec, frontier, fees = self._candidate(head,parsed.pk,parsed.packets)
        need(raw[:-8] == expected,"invalid reward or state commitment")
        header = head["ap"]+u32(parsed.height)+parsed.state+digest(b"dev-seal",NETWORK,bid)+parsed.root
        anchor = self.backend.header_id(header)
        data = (bid,head["id"],parsed.height,head["work"]+WORK,anchor,header,fees,frontier.count,frontier.encode(),raw)
        txids = tuple(sha256(p).digest() for p in parsed.packets)
        wallet_record = None
        if existing:
            need(tuple(self._row(bid)) == data[:-1],"stored branch metadata")
        else:
            wallet_record = history.record(parsed.height,bid,head["id"],header,rec,txids,slots)
            self._persist(data,txids,wallet_record)
        self.db.execute("INSERT INTO sel VALUES (?,?)",(parsed.height,bid))
        pos = head["n"]
        for slot in slots:
            self.db.executemany("INSERT INTO spent VALUES (?,?)",((nf,parsed.height) for nf in slot.nfs))
            for cm,ct in zip(slot.cms,slot.cts,strict=True):
                self.db.execute("INSERT INTO outs VALUES (?,?,?,?,NULL)",(pos,cm,parsed.height,ct))
                pos += 1
        self.db.execute("INSERT INTO outs VALUES (?,?,?,NULL,?)",(pos,parsed.reward_cm,parsed.height,rec))
        return data,txids,wallet_record

    def _fork_path(self,parent):
        row = self._row(parent)
        need(row is not None,"unknown parent")
        path = []
        while self.db.execute("SELECT id FROM sel WHERE h=? AND id=?",(row["h"],row["id"])).fetchone() is None:
            need(row["h"] > 0,"archive branch ancestry")
            path.append(row["id"])
            row = self._row(row["parent"])
        return row["h"], list(reversed(path))

    def _refresh(self,detached,included):
        offered = [r[0] for r in self.db.execute("SELECT packet FROM pool ORDER BY seq")]
        self.db.execute("DELETE FROM pool")
        head = self._head()
        requeued, rejected = [], []
        seen = set(included)
        for priority, packets in ((True,detached),(False,offered)):
            for packet in packets:
                txid = sha256(packet).digest()
                if txid in seen:
                    continue
                seen.add(txid)
                try:
                    self._enqueue(packet,head)
                except ValueError as e:
                    if str(e) not in INELIGIBLE:
                        raise
                    rejected.append(dict(id=txid.hex(),reason=str(e)))
                    continue
                if priority:
                    requeued.append(txid.hex())
        return requeued,rejected

    def accept(self,raw):
        parsed = decode_block(raw)
        bid = block_id(raw)
        need(int.from_bytes(bid,"big") <= TARGET,"insufficient proof of work")
        with self._transaction(True):
            old = self._head()
            result = dict(id=bid.hex(),selected=False,changed=False,tip=old["id"].hex(),height=old["h"],
                          detached=[],attached=[],deep_replay=False,requeued=[],rejected=[])
            known = self._row(bid)
            if known:
                need(self.db.execute("SELECT raw FROM blocks WHERE id=?",(bid,)).fetchone()[0] == raw,
                     "block identity collision")
                result["selected"] = bool(self.db.execute("SELECT 1 FROM sel WHERE id=?",(bid,)).fetchone())
                return result
            base, path = (old["h"],[]) if parsed.parent == old["id"] else self._fork_path(parsed.parent)
            deep = old["h"]-base > UNDO
            # Keep the true common-prefix identifiers before replacing the selected index.
            prefix = [r[0] for r in self.db.execute(
                "SELECT id FROM sel WHERE h BETWEEN 1 AND ? ORDER BY h",(base,))] if deep else []
            self.db.execute("SAVEPOINT candidate")
            old_ids = []
            if base != old["h"]:
                old_ids = [r[0] for r in self.db.execute("SELECT id FROM sel WHERE h>? ORDER BY h",(base,))]
                rewind = 0 if deep else base
                self.db.execute("DELETE FROM spent WHERE h>?",(rewind,))
                self.db.execute("DELETE FROM outs WHERE h>?",(rewind,))
                self.db.execute("DELETE FROM sel WHERE h>?",(rewind,))
            included = set()
            for side_id in (*prefix,*path):
                stored = self.db.execute("SELECT raw FROM blocks WHERE id=?",(side_id,)).fetchone()[0]
                side = decode_block(stored)
                need(block_id(stored) == side_id and int.from_bytes(side_id,"big") <= TARGET,"stored branch seal")
                _,side_txids,_ = self._attach(stored,side,side_id,True)
                included.update(side_txids)
            data,txids,wallet_record = self._attach(raw,parsed,bid)
            new_work = data[3]
            wins = new_work > old["work"] or (new_work == old["work"] and bid < old["id"])
            if not wins:
                self.db.execute("ROLLBACK TO candidate")
            self.db.execute("RELEASE candidate")
            if not wins:
                self._persist(data,txids,wallet_record)
                return result
            if deep:
                self.db.execute("UPDATE metrics SET deep_replays=deep_replays+1 WHERE id=1")
            included.update(txids)
            detached = (p for orphan in old_ids for p in decode_block(self.db.execute(
                "SELECT raw FROM blocks WHERE id=?",(orphan,)).fetchone()[0]).packets)
            requeued,rejected = self._refresh(detached,included)
            result.update(selected=True,changed=True,tip=bid.hex(),height=parsed.height,detached=[p.hex() for p in old_ids],
                          attached=[p.hex() for p in (*path,bid)],deep_replay=deep,requeued=requeued,rejected=rejected)
            return result


if __name__ == "__main__":
    import argparse

    cli = argparse.ArgumentParser(description="Seal a single binary PQDEV1 template from stdin to stdout.")
    cli.add_argument("mode",choices=("mine",))
    cli.add_argument("--start",type=int,default=0)
    cli.add_argument("--attempts",type=int)
    args = cli.parse_args()
    candidate = sys.stdin.buffer.read(MAX_BLOCK+1)
    solved = mine(candidate,args.start,args.attempts)
    if solved is None:
        sys.exit(2)
    sys.stdout.buffer.write(solved)
