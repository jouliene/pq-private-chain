"""Private maker inventory. Only the local validating-node adapter supplies selected-chain snapshots."""
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import stat

from terms import LIMIT, Terms, asset_id, need

FIRST_C = 25


def hexid(value, size=32):
    need(type(value) is str and len(value) == 2 * size and bytes.fromhex(value).hex() == value,
         "noncanonical local identifier")
    return value


def bounded(value, low, high):
    need(type(value) is int and low <= value <= high, "integer outside order bounds")
    return value


def encoded(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True, allow_nan=False)


@dataclass(frozen=True)
class Order:
    order_id: str
    network: str
    maker: str
    asset: str
    take: str
    total: int
    lot: int
    price: int
    fee: int = 3

    def __post_init__(self):
        hexid(self.order_id)
        hexid(self.network)
        hexid(self.maker, 1601)
        need(self.maker.startswith("01"), "invalid maker address")
        need(asset_id(hexid(self.asset)) != asset_id(hexid(self.take)), "identical settlement assets")
        bounded(self.total, 1, LIMIT)
        bounded(self.lot, 1, self.total)
        bounded(self.price, 1, LIMIT)
        bounded(self.fee, 3, 3)
        need(self.total % self.lot == 0 and self.total // self.lot * self.price <= LIMIT,
             "invalid total or lot consideration")


class Book:
    """Caller serializes node observation and peer/wallet actions. SQLite also serializes inventory writers."""

    def __init__(self, path):
        path = Path(path)
        parent = path.parent.stat()
        need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and not parent.st_mode & 0o077,
             "maker book requires a private wallet directory")
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
                 "unsafe private maker book")
        finally:
            os.close(fd)
        self.db = sqlite3.connect(path, isolation_level=None, timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS orders(
                id TEXT PRIMARY KEY, policy TEXT NOT NULL, closed INTEGER NOT NULL DEFAULT 0,
                tip TEXT, height INTEGER, view_hash TEXT
            );
            CREATE TABLE IF NOT EXISTS fills(
                order_id TEXT REFERENCES orders(id), request TEXT, request_hash TEXT NOT NULL,
                quantity INTEGER NOT NULL, expiry_height INTEGER NOT NULL, phase TEXT NOT NULL,
                terms_hash TEXT UNIQUE, joint TEXT, buyer_sig TEXT, pin_tip TEXT,
                signed_id TEXT UNIQUE, packet BLOB, block TEXT, block_height INTEGER, position INTEGER,
                PRIMARY KEY(order_id,request)
            );
        """)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.db.close()

    @contextmanager
    def _write(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def _order(self, order_id):
        row = self.db.execute("SELECT * FROM orders WHERE id=?", (hexid(order_id),)).fetchone()
        need(row is not None, "unknown private order")
        return row

    def _fill(self, order_id, request):
        row = self.db.execute("SELECT * FROM fills WHERE order_id=? AND request=?",
                              (hexid(order_id), hexid(request))).fetchone()
        need(row is not None, "unknown private reservation")
        return row

    @staticmethod
    def _guard(order, tip, expiry):
        need(order["tip"] == hexid(tip) and order["height"] is not None, "stale order branch evidence")
        need(FIRST_C <= order["height"] + 1 <= expiry, "current branch outside profile C or firm expiry")

    def create(self, order):
        need(isinstance(order, Order), "private order policy required")
        with self._write():
            policy = encoded(asdict(order))
            self.db.execute("INSERT OR IGNORE INTO orders(id,policy) VALUES(?,?)", (order.order_id, policy))
            need(self._order(order.order_id)["policy"] == policy, "order identity already bound to another policy")

    def sync(self, order_id, snapshot):
        """Rebuild all selected inclusions from the complete, locally validated branch, in one transaction."""
        need(isinstance(snapshot, dict) and set(snapshot) == {"network", "tip", "height", "bundles"},
             "incomplete selected-chain snapshot")
        tip = hexid(snapshot["tip"])
        height = bounded(snapshot["height"], 0, 2**32-1)
        bundles = snapshot["bundles"]
        need(isinstance(bundles, dict), "incomplete selected bundle inventory")
        positions = set()
        blocks = {}
        for ident, loc in bundles.items():
            hexid(ident)
            need(isinstance(loc, dict) and set(loc) == {"block", "height", "position"}, "invalid bundle location")
            block = hexid(loc["block"])
            h = bounded(loc["height"], FIRST_C, height)
            pos = bounded(loc["position"], 0, 2**32-2)
            need(blocks.setdefault(h, block) == block and (h != height or block == tip),
                 "conflicting selected block")
            for slot in (pos, pos + 1):
                need((h, slot) not in positions, "overlapping selected swap frames")
                positions.add((h, slot))
        view_hash = sha256(encoded(snapshot).encode()).hexdigest()
        with self._write():
            order = self._order(order_id)
            need(json.loads(order["policy"])["network"] == snapshot["network"], "wrong selected network")
            if tip == order["tip"]:
                need(view_hash == order["view_hash"], "inconsistent evidence for unchanged selected tip")
                return
            self.db.execute("UPDATE orders SET tip=?,height=?,view_hash=? WHERE id=?",
                            (tip, height, view_hash, order_id))
            self.db.execute("""UPDATE fills SET pin_tip=NULL,block=NULL,block_height=NULL,position=NULL
                               WHERE order_id=?""", (order_id,))
            # An unsigned expiry is final locally. The maker never authorized this request.
            self.db.execute("""UPDATE fills SET phase='expired' WHERE order_id=?
                               AND phase='reserved' AND expiry_height<=?""", (order_id, height))
            for row in self.db.execute("SELECT request,signed_id,expiry_height FROM fills WHERE order_id=? "
                                       "AND signed_id IS NOT NULL", (order_id,)).fetchall():
                loc = bundles.get(row["signed_id"])
                if loc:
                    need(loc["height"] <= row["expiry_height"], "selected swap beyond signed height")
                    self.db.execute("UPDATE fills SET block=?,block_height=?,position=? WHERE order_id=? AND request=?",
                                    (loc["block"], loc["height"], loc["position"], order_id, row["request"]))

    @staticmethod
    def _agreement(raw, policy, quantity, expiry_height):
        terms = Terms.decode(raw)
        buyer, maker = terms.parties
        need(terms.encode() == raw and terms.payer == 0 and
             (terms.network.hex(), terms.expiry, maker.address.hex(), maker.give.hex(), maker.qty,
              buyer.give.hex(), buyer.qty) ==
             (policy["network"], expiry_height, policy["maker"], policy["asset"], quantity,
              policy["take"], quantity // policy["lot"] * policy["price"]),
             "agreement differs from reserved economics")
        return terms

    def reserve(self, order_id, request, request_hash, quantity, expiry_height, tip, *, agreement):
        hexid(request)
        hexid(request_hash)
        bounded(quantity, 1, LIMIT)
        bounded(expiry_height, FIRST_C, 2**32-1)
        with self._write():
            order = self._order(order_id)
            self._guard(order, tip, expiry_height)
            policy = json.loads(order["policy"])
            need(not order["closed"] and quantity % policy["lot"] == 0, "closed order or invalid lot multiple")
            terms_hash = self._agreement(agreement, policy, quantity, expiry_height).commitment().hex()
            previous = self.db.execute("SELECT * FROM fills WHERE order_id=? AND request=?", (order_id, request)).fetchone()
            if previous:
                need((previous["phase"], previous["request_hash"], previous["quantity"], previous["expiry_height"], previous["terms_hash"])
                     == ("reserved", request_hash, quantity, expiry_height, terms_hash), "request already bound or retired")
            else:
                used = self.db.execute("SELECT coalesce(sum(quantity),0) FROM fills WHERE order_id=? "
                                       "AND phase IN ('reserved','pinned','signed')", (order_id,)).fetchone()[0]
                need(quantity <= policy["total"] - used, "insufficient available offer quantity")
                claimed = self.db.execute("SELECT 1 FROM fills WHERE terms_hash=?", (terms_hash,)).fetchone()
                need(claimed is None, "agreement already assigned")
                self.db.execute("INSERT INTO fills(order_id,request,request_hash,quantity,expiry_height,terms_hash,phase) "
                                "VALUES(?,?,?,?,?,?,'reserved')", (order_id, request, request_hash, quantity, expiry_height,
                                                                terms_hash))
            return self._record(self._fill(order_id, request), order)

    def pin(self, order_id, request, terms_hash, leg_a, leg_b, sig_a, payer, tip, *, agreement):
        """Call after local wallet checks the two legs and the buyer signature, before maker signing."""
        import swap_wire_c as c
        terms = Terms.decode(agreement)
        need(terms.encode() == agreement and terms.commitment() == terms_hash and type(payer) is int and
             payer == terms.payer == 0, "incorrect canonical agreement or payer")
        for leg in (leg_a, leg_b):
            c.leg_shape(leg)
            need(len(leg) <= c.LIMIT-c.HEADER-c.SIG, "oversized profile C leg")
        need(len(sig_a) == c.SIG, "invalid taker signature width")
        joint = c.digest(terms.network, terms_hash, terms.expiry, payer, (leg_a, leg_b)).hex()
        key = (terms_hash.hex(), joint, sha256(sig_a).hexdigest())
        with self._write():
            order = self._order(order_id)
            fill = self._fill(order_id, request)
            self._guard(order, tip, fill["expiry_height"])
            need(fill["terms_hash"] == key[0], "changed firm agreement or buyer")
            need(fill["phase"] in ("reserved", "pinned", "signed") and fill["block"] is None,
                 "retired or already settled reservation")
            if fill["phase"] == "reserved":
                need(not order["closed"], "closed order")
                self.db.execute("UPDATE fills SET phase='pinned', terms_hash=?, joint=?, buyer_sig=? "
                                "WHERE order_id=? AND request=?", (*key, order_id, request))
            else:
                need((fill["terms_hash"], fill["joint"], fill["buyer_sig"]) == key, "changed pinned authorization")
            self.db.execute("UPDATE fills SET pin_tip=? WHERE order_id=? AND request=?", (tip, order_id, request))

    def release(self, order_id, request, bundle, tip):
        """Persist exact fully assembled bytes before the caller releases the maker signature."""
        import swap_wire_c as c
        a, b = c.pair(c.split(bundle))
        joint = c.digest(a.network, a.terms, a.expiry, a.payer, (a.leg, b.leg)).hex()
        ident = sha256(bundle).hexdigest()
        with self._write():
            order = self._order(order_id)
            fill = self._fill(order_id, request)
            self._guard(order, tip, fill["expiry_height"])
            need(fill["phase"] in ("pinned", "signed") and fill["pin_tip"] == tip and fill["block"] is None,
                 "no current pre-release authorization")
            need((a.terms.hex(), joint, sha256(a.signature).hexdigest()) ==
                 (fill["terms_hash"], fill["joint"], fill["buyer_sig"]), "bundle differs from pinned authorization")
            if fill["signed_id"] is not None:
                need(fill["signed_id"] == ident and fill["packet"] == bundle, "changed released bundle")
            else:
                self.db.execute("UPDATE fills SET signed_id=?,packet=?,phase='signed' WHERE order_id=? AND request=?",
                                (ident, bundle, order_id, request))
        return ident

    def cancel(self, order_id, request):
        with self._write():
            fill = self._fill(order_id, request)
            need(fill["phase"] in ("reserved", "cancelled", "expired"), "maker authorization may exist")
            if fill["phase"] == "reserved":
                self.db.execute("UPDATE fills SET phase='cancelled' WHERE order_id=? AND request=?", (order_id, request))

    def close(self, order_id):
        with self._write():
            self._order(order_id)
            self.db.execute("UPDATE orders SET closed=1 WHERE id=?", (order_id,))
            self.db.execute("UPDATE fills SET phase='cancelled' WHERE order_id=? AND phase='reserved'", (order_id,))

    def packet(self, order_id, request):
        row = self._fill(order_id, request)
        need(row["packet"] is not None, "signed packet unavailable")
        return row["packet"]

    @staticmethod
    def _record(fill, order):
        state = fill["phase"]
        if fill["block"] is not None:
            state = "confirmed"
        elif state in ("signed", "pinned") and order["height"] >= fill["expiry_height"]:
            state = "expired_signed"
        result = {k: fill[k] for k in ("request", "request_hash", "quantity", "expiry_height", "signed_id",
                                        "block", "block_height", "position", "pin_tip", "terms_hash")}
        result["state"] = state
        return result

    def record(self, order_id, request):
        with self._write():
            return self._record(self._fill(order_id, request), self._order(order_id))

    def status(self, order_id):
        with self._write():
            order = self._order(order_id)
            p = json.loads(order["policy"])
            counts = dict(reserved=0, exposed=0, confirmed=0, expired_exposure=0,
                          pinned_uncertain=0, signed_unconfirmed=0)
            for fill in self.db.execute("SELECT * FROM fills WHERE order_id=?", (order_id,)):
                state = self._record(fill, order)["state"]
                if state in ("reserved", "confirmed"):
                    counts[state] += fill["quantity"]
                elif state in ("pinned", "signed", "expired_signed"):
                    counts["exposed"] += fill["quantity"]
                    kind = "signed_unconfirmed" if fill["signed_id"] else "pinned_uncertain"
                    counts[kind] += fill["quantity"]
                    if state == "expired_signed":
                        counts["expired_exposure"] += fill["quantity"]
            free = p["total"] - counts["confirmed"] - counts["reserved"] - counts["exposed"]
            need(free >= 0, "inconsistent maker inventory")
            return dict(order=p, tip=order["tip"], height=order["height"], closed=bool(order["closed"]),
                        available=0 if order["closed"] else free, remaining=p["total"]-counts["confirmed"],
                        overhang=0, **counts)
