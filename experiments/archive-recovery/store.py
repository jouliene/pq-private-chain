"""Pruned selected chain using the locally installed scheduled A/B verifier."""
from contextlib import contextmanager
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import struct

import chain
from swap_ledger import logical
from wire import need


# Explicit durable schema. The checksum detects at-rest damage across restarts.
# A local operator who can rewrite both state and checksum is trusted; a peer
# cannot provide either. Bootstrap and replacement always verify original bytes.
TABLES = {
    "config": "id", "metrics": "id", "blocks": "h,id", "sel": "h",
    "outs": "pos", "spent": "nf", "assets": "id,sequence", "pool": "seq",
    "txloc": "tx,bid", "swap_pool": "id", "swap_archive": "id,bid",
    "wallet_history_v2": "bid", "funded_upgrade_blocks": "id", "home_policy": "id",
}


def toggle(accumulator, table, *row):
    # Every durable table includes its immutable primary key in its row. XOR
    # permits adding/removing a row in O(changed bytes). This unkeyed local
    # checksum protects against accidental disk damage, not a malicious host.
    digest = sha256(b"funded-home-row/v1\x00" + table.encode() + b"\x00")
    for value in row:
        if value is None:
            digest.update(b"N")
        elif type(value) is int:
            digest.update(b"I" + struct.pack("<q", value))
        else:
            tag = b"B" if isinstance(value, bytes) else b"S"
            data = value if tag == b"B" else value.encode()
            digest.update(tag + struct.pack("<Q", len(data)))
            digest.update(data)
    return (int.from_bytes(accumulator, "little") ^ int.from_bytes(digest.digest(), "little")).to_bytes(32, "little")


def checksum(db):
    accumulator = bytes(32)
    for table in TABLES:
        for row in db.execute(f"SELECT * FROM {table}"):
            accumulator = toggle(accumulator, table, *row)
    return accumulator


def checksum_triggers(db):
    for table in TABLES:
        columns = [r[1] for r in db.execute(f"PRAGMA table_info({table})")]
        for action, sides in (("INSERT", ("NEW",)), ("DELETE", ("OLD",)), ("UPDATE", ("OLD", "NEW"))):
            value = "digest"
            for side in sides:
                arguments = ",".join(f'{side}."{c}"' for c in columns)
                value = f"home_toggle({value},'{table}',{arguments})"
            name = f"home_{table}_{action.lower()}"
            yield name, (f"CREATE TRIGGER {name} AFTER {action} ON {table} BEGIN "
                         f"UPDATE home_seal SET digest={value} WHERE id=1; END")


def prefers(work, ident, old_work, old_id):
    return work > old_work or (work == old_work and ident < old_id)


def new_progress():
    return dict(status="ready", target=None, first_missing_height=None, error=None)


class PrunedChain(chain.Chain):
    def __init__(self, path, backend, window):
        need(type(window) is int and window > 0, "invalid body window")
        self.window = window
        self.path = Path(path) if path else None
        durable = self.path is not None
        existing = durable and self.path.exists()
        if durable:
            # First connection sets the database layout before Chain creates tables.
            with sqlite3.connect(path) as inspect:
                if existing:
                    need(inspect.execute("PRAGMA quick_check").fetchone() == ("ok",),
                         "home database integrity check failed")
                    tables = {r[0] for r in inspect.execute(
                        "SELECT name FROM sqlite_schema WHERE type='table'")}
                    need(tables == set(TABLES) | {"home_seal"}, "unexpected home schema")
                    seal = inspect.execute("SELECT digest FROM home_seal WHERE id=1").fetchone()
                    need(seal and seal[0] == checksum(inspect), "local validation-state checksum mismatch")
                    triggers = dict(inspect.execute("SELECT name,sql FROM sqlite_schema WHERE type='trigger'"))
                    need(triggers == dict(checksum_triggers(inspect)), "local checksum triggers mismatch")
                    saved = inspect.execute("SELECT window FROM home_policy WHERE id=1").fetchone()
                    need(saved and saved[0] == window, "home window mismatch")
                else:
                    inspect.execute("PRAGMA auto_vacuum=FULL")
            inspect.close()
        self._registered = False
        super().__init__(str(path) if durable else "", backend)
        try:
            # An unnamed SQLite scratch database has no directory entry and is
            # automatically removed even when the process is killed.
            if not durable:
                self.db.execute("PRAGMA auto_vacuum=FULL")
                self.db.execute("VACUUM")
            self.db.execute("PRAGMA secure_delete=ON")
            with self._transaction(True):
                self.db.execute("CREATE TABLE IF NOT EXISTS home_policy(id INTEGER PRIMARY KEY, "
                                "window INTEGER NOT NULL, progress TEXT NOT NULL)")
                self.db.execute("CREATE TABLE IF NOT EXISTS home_seal(id INTEGER PRIMARY KEY, digest BLOB NOT NULL)")
                if not existing:
                    self.db.execute("INSERT INTO home_seal VALUES(1,?)", (checksum(self.db),))
                    for _, statement in checksum_triggers(self.db):
                        self.db.execute(statement)
                self.db.execute("INSERT OR IGNORE INTO home_policy VALUES(1,?,?)",
                                (window, json.dumps(new_progress())))
                height = self._head()["h"]
                body_count, = self.db.execute("SELECT count(*) FROM blocks WHERE length(raw)>0").fetchone()
                need(body_count == min(height, window), "home retention mismatch")
        except BaseException:
            self.close()
            raise

    @contextmanager
    def _transaction(self, write=False):
        if not self._registered:
            self.db.create_function("home_toggle", -1, toggle, deterministic=True)
            self._registered = True
        with super()._transaction(write):
            yield

    def accept(self, raw):
        block = chain.decode_block(raw)
        with self.lock:
            head = self._head()
            if block.parent != head["id"]:
                # Only direct extensions enter here. Fork recovery validates in
                # isolation. Never feed pruned parent material into Chain.accept.
                if self.db.execute("SELECT 1 FROM sel WHERE id=?", (chain.block_id(raw),)).fetchone():
                    need(self.block(chain.block_id(raw)) == raw, "block identity collision")
                    return super().accept(raw)
                raise ValueError("competing branch requires archive recovery")
            return super().accept(raw)

    def _persist(self, data, txids, wallet_record):
        super()._persist(data, txids, wallet_record)
        if data[2] > self.window:
            self.db.execute("UPDATE blocks SET raw=x'' WHERE id=(SELECT id FROM sel WHERE h=?)",
                            (data[2] - self.window,))

    def block(self, bid):
        raw = super().block(bid)
        need(raw or bid == chain.GENESIS, "block body pruned")
        return raw

    def tx(self, txid):
        with self.lock:
            for table, column in (("txloc", "tx"), ("swap_archive", "id")):
                row = self.db.execute(f"SELECT length(raw) FROM {table} JOIN blocks ON blocks.id=bid "
                                      f"WHERE {table}.{column}=?", (txid,)).fetchone()
                need(row is None or row[0] > 0, "transaction body pruned")
            return super().tx(txid)

    def progress(self):
        row = self.db.execute("SELECT progress FROM home_policy WHERE id=1").fetchone()
        return json.loads(row[0])

    def progress_update(self, progress):
        with self._transaction(True):
            self.db.execute("UPDATE home_policy SET progress=? WHERE id=1", (json.dumps(progress),))

    def storage(self):
        def query(sql):
            return self.db.execute(sql).fetchone()[0] or 0

        pages = query("PRAGMA page_count")
        page_size = query("PRAGMA page_size")
        return dict(window=self.window, body_rows=query("SELECT count(*) FROM blocks WHERE length(raw)>0"),
                    body_B=query("SELECT sum(length(raw)) FROM blocks"),
                    first_body_height=query("SELECT min(h) FROM blocks WHERE length(raw)>0") or None,
                    compact_history_B=query("SELECT sum(length(record)) FROM wallet_history_v2"),
                    output_receipt_index_B=query("SELECT sum(coalesce(length(ct),0)+coalesce(length(reward),0)) FROM outs"),
                    header_frontier_B=query("SELECT sum(length(ap)+length(header)+length(front)) FROM blocks"),
                    sqlite_B=pages*page_size, free_page_B=query("PRAGMA freelist_count")*page_size,
                    pool_packet_B=query("SELECT sum(length(packet)) FROM pool"),
                    disk_B=self.path.stat().st_size if self.path is not None else pages*page_size)

    def install(self, candidate, progress, common, deep):
        """Install only locally verified work in one SQLite backup transaction."""
        with self.lock, candidate.lock:
            old, new = self._head(), candidate._head()
            need(prefers(new["work"], new["id"], old["work"], old["id"]), "candidate did not win fork choice")
            need(new["id"].hex() == progress["target"], "verified target mismatch")
            # Keep all pending and locally available detached packets eligible
            # to be offered again. Ancient detached bodies require rebroadcast.
            with candidate._transaction(True):
                detached = (p for row in self.db.execute(
                    "SELECT raw FROM blocks WHERE h>? AND length(raw)>0 ORDER BY h", (common,))
                            for p in chain.decode_block(row[0]).packets)
                offered = (r[0] for r in self.db.execute("SELECT packet FROM pool ORDER BY seq"))
                for packet in (*logical(detached), *logical(offered)):
                    try:
                        candidate._enqueue(packet, new)
                    except ValueError as error:
                        if str(error) not in chain.INELIGIBLE:
                            raise
                prior_deep = self.db.execute("SELECT deep_replays FROM metrics WHERE id=1").fetchone()[0]
                candidate.db.execute("UPDATE metrics SET deep_replays=? WHERE id=1", (prior_deep + int(deep),))
                candidate.db.execute("UPDATE home_policy SET progress=? WHERE id=1", (json.dumps(progress),))
            candidate.db.backup(self.db)
            self._spent_summary = None
