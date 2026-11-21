"""Clear FS01 relation and weakly trusted wallet inputs. Never a proof or a verifier."""
from collections import Counter
from contextvars import ContextVar
from dataclasses import dataclass
import hashlib
import secrets

W = 64
ZERO = bytes(W)
DEPTH = 40
ACTIVE_TAGS = ContextVar("active_tags", default=None)
TAG = {
    name: bytes((0xf1, value))
    for value, name in enumerate((
        "ask", "kem_seed", "owner", "cm", "leaf", "empty", "parent",
        "nf", "dummy_nf", "auth", "intent", "occ", "credit_occ", "asset",
        "funding_id", "terms", "pair", "ad", "descriptor", "chain", "issue_body",
    ), start=1)
}


def need(condition, label):
    if not condition:
        raise ValueError(label)


def fixed(data, size):
    need(type(data) is bytes and len(data) == size, "wrong byte width")
    return data


def le(n, size):
    need(type(n) is int and 0 <= n < 1 << (8 * size), "integer outside encoding")
    return n.to_bytes(size, "little")


def h(domain, *fields):
    message = TAG[domain] + b"".join(fields)
    counts = ACTIVE_TAGS.get()
    if counts is not None:
        counts[(domain, len(message))] += 1
    return hashlib.shake_256(message).digest(W)


def funding_asset(chain, issuer_pk, nonce, cap):
    return h("asset", fixed(chain, W), b"\x01", fixed(issuer_pk, 64),
             fixed(nonce, 64), le(cap, 8))


def owner(ask):
    return h("owner", fixed(ask, W))


def spend_key(chain, seed):
    return h("ask", fixed(chain, W), fixed(seed, W))


@dataclass(frozen=True)
class Note:
    owner: bytes
    native: int
    asset: bytes
    qty: int
    salt: bytes

    def encode(self):
        return (fixed(self.owner, W) + le(self.native, 8) + fixed(self.asset, W)
                + le(self.qty, 8) + fixed(self.salt, W))

    def cm(self, chain):
        return h("cm", fixed(chain, W), self.encode())


def new_note(owner_key, native, asset, qty):
    return Note(owner_key, native, asset, qty, secrets.token_bytes(W))


def occurrence(chain, role, nfs, slot):
    need(role in (0, 1, 2) and slot in (0, 1) and len(nfs) == 2, "bad occurrence")
    a, b = sorted(fixed(nf, W) for nf in nfs)
    return h("occ", fixed(chain, W), le(role, 1), a, b, le(slot, 1))


def credit_occ(chain, funding_id, slot):
    need(slot in (0, 1), "bad funding slot")
    return h("credit_occ", fixed(chain, W), fixed(funding_id, W), le(slot, 1))


def leaf(occ, cm):
    return h("leaf", fixed(occ, W), fixed(cm, W))


def parent(level, left, right):
    need(0 <= level < DEPTH, "tree level")
    return h("parent", le(level, 1), fixed(left, W), fixed(right, W))


class FundedTree:
    """Sparse ordered reference tree for an authenticated append-only branch."""
    def __init__(self, entries):
        need(len(entries) <= 1 << DEPTH, "tree full")
        need(len({occ for occ, _ in entries}) == len(entries), "duplicate occurrence")
        self.count = len(entries)
        self.empty = [h("empty")]
        self.layers = [{i: leaf(occ, cm) for i, (occ, cm) in enumerate(entries)}]
        for level in range(DEPTH):
            prev, empty = self.layers[-1], self.empty[-1]
            self.empty.append(parent(level, empty, empty))
            self.layers.append({i: parent(level, prev.get(2*i, empty), prev.get(2*i+1, empty))
                                for i in {j >> 1 for j in prev}})
        self.root = self.layers[-1].get(0, self.empty[-1])

    def path(self, index):
        need(0 <= index < self.count, "not funded")
        return tuple(self.layers[i].get((index >> i) ^ 1, self.empty[i]) for i in range(DEPTH))


@dataclass(frozen=True)
class Input:
    ask: bytes
    native: int
    asset: bytes
    qty: int
    salt: bytes
    occ: bytes
    index: int
    path: tuple

    def fields(self):
        return (fixed(self.ask, W) + le(self.native, 8) + fixed(self.asset, W)
                + le(self.qty, 8) + fixed(self.salt, W) + fixed(self.occ, W)
                + le(self.index, 5))

    def encode(self):
        need(len(self.path) == DEPTH, "path length")
        return self.fields() + b"".join(fixed(x, W) for x in self.path)

    def note(self):
        return Note(owner(self.ask), self.native, self.asset, self.qty, self.salt)


@dataclass(frozen=True)
class Witness:
    inputs: tuple
    outputs: tuple
    active: int
    asset: bytes

    def encode(self):
        need(len(self.inputs) == len(self.outputs) == 2 and self.active in (0, 1), "shape")
        return (b"".join(x.encode() for x in self.inputs) + b"".join(x.encode() for x in self.outputs)
                + le(self.active, 1) + fixed(self.asset, W))


@dataclass(frozen=True)
class Statement:
    chain: bytes
    root: bytes
    count: int
    fee: int
    nfs: tuple
    cms: tuple
    intent: bytes
    auth: bytes

    def encode(self):
        need(0 < self.count <= 1 << DEPTH and len(self.nfs) == len(self.cms) == 2, "statement")
        return (fixed(self.chain, W) + fixed(self.root, W) + le(self.count, 6) + le(self.fee, 8)
                + b"".join(fixed(x, W) for x in (*self.nfs, *self.cms, self.intent, self.auth)))


def evaluate(s, w):
    s.encode()
    w.encode()
    counts = Counter()
    token = ACTIVE_TAGS.set(counts)
    try:
        i0, i1 = w.inputs
        need(i0.index != i1.index if w.active else i0.fields() == i1.fields(), "input slots")
        need(s.nfs[0] != s.nfs[1], "duplicate nullifier")
        notes = []
        for slot, x in enumerate(w.inputs):
            n = x.note()
            notes.append(n)
            need(n.native > 0 or n.qty > 0, "empty real input")
            need(x.index < s.count, "position outside anchor")
            cur = leaf(x.occ, n.cm(s.chain))
            for level, sibling in enumerate(x.path):
                bit = (x.index >> level) & 1
                cur = parent(level, sibling, cur) if bit else parent(level, cur, sibling)
            need(cur == s.root, "membership")
            nf_mode = "dummy_nf" if slot == 1 and not w.active else "nf"
            need(h(nf_mode, x.ask, x.occ) == s.nfs[slot], "nullifier")
        notes.extend(w.outputs)
        need((w.asset != ZERO) == any(n.qty > 0 for n in notes), "common asset")
        for n in notes:
            need(n.asset == (w.asset if n.qty else ZERO), "note type")
        dst0, dst1 = w.outputs
        need(i0.native + w.active * i1.native == dst0.native + dst1.native + s.fee, "native")
        need(i0.qty + w.active * i1.qty == dst0.qty + dst1.qty, "token")
        for slot, n in enumerate(w.outputs):
            need(n.cm(s.chain) == s.cms[slot], "output commitment")
        need(h("auth", i0.ask, s.intent) == s.auth, "spend intent")
    finally:
        ACTIVE_TAGS.reset(token)
    return counts
