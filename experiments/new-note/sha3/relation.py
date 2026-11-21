"""Executable clear relation and counted Boolean straight-line implementation."""
import hashlib
import secrets
from collections import Counter
from dataclasses import dataclass, replace

SUITE = b"N3R1"
DEPTH = 40
DIGEST = 48


def h(tag, *parts):
    return hashlib.sha3_384(SUITE + bytes([tag]) + b"".join(parts)).digest()


def le(n, size):
    return n.to_bytes(size, "little")


def authority(net, secret):
    return h(1, net, secret)


@dataclass(frozen=True)
class Note:
    owner: bytes
    asset: bytes
    salt: bytes
    native: int
    token: int

    def payload(self):
        assert len(self.owner) == len(self.salt) == 48 and len(self.asset) == 32
        return self.owner + self.asset + self.salt + le(self.native, 8) + le(self.token, 8)

    def cm(self, net):
        return h(2, net, self.payload())


def occurrence(net, kind, nfs, slot):
    return h(8, net, bytes([kind]), *sorted(nfs), bytes([slot]))


def credit_occurrence(net, credit_id, slot):
    return h(9, net, credit_id, bytes([slot]))


def parent(level, left, right):
    return h(3, bytes([level]), left, right)


def top_and_paths(entries, indices):
    default = h(4)
    nodes = {i: h(5, occ, cm) for i, (occ, cm) in enumerate(entries)}
    paths = [[] for _ in indices]
    for level in range(DEPTH):
        for j, i in enumerate(indices):
            paths[j].append(nodes.get((i >> level) ^ 1, default))
        nodes = {p: parent(level, nodes.get(2*p, default), nodes.get(2*p+1, default))
                 for p in {i >> 1 for i in nodes}}
        default = parent(level, default, default)
    return nodes.get(0, default), paths


def anchor(net, count, top):
    return h(6, net, le(count, 8), top)


def nf(net, secret, occ, cm):
    return h(7, net, secret, occ, cm)


class Circuit:
    """XOR and NOT free. Each counted vector operation includes all its bits."""

    def __init__(self):
        self.groups = Counter()
        self.perms = Counter()
        self.valid = True

    def hash(self, label, tag, *parts):
        self.perms[label] += 1 + (5 + sum(map(len, parts))) // 104
        return h(tag, *parts)

    def require_equal(self, left, right, width):
        self.groups["equalities accumulated into output bit"] += width
        self.valid &= left == right

    def nonzero(self, value, width):
        self.groups["nonzero OR reductions"] += width - 1
        return bool(value)

    def add(self, left, right):
        self.groups["66-bit ripple additions"] += 66 * 2
        return (left + right) % 2**66

    def note(self, net, owner, asset, salt, native, token):
        assert 0 <= native < 2**64 and 0 <= token < 2**64
        token_used = self.nonzero(token, 64)
        native_used = self.nonzero(native, 64)
        self.groups["OR of native/token nonzero bits"] += 1
        self.require_equal(native_used or token_used, True, 1)
        self.groups["select canonical private asset tag"] += 256
        n = Note(owner, asset if token_used else bytes(32), salt, native, token)
        return self.hash("note", 2, net, n.payload()), token_used


@dataclass(frozen=True)
class Input:
    salt: bytes
    native: int
    token: int
    occurrence: bytes
    index: int
    path: tuple


def eval_relation(net, count, root, nfs, cms, fee, secret, asset, inputs, outputs):
    assert len(net) == len(secret) == 48 and len(asset) == 32
    assert 0 < count <= 2**DEPTH and 0 <= fee < 2**64
    assert len(inputs) == len(outputs) == len(nfs) == len(cms) == 2
    c = Circuit()
    owner = c.hash("authority", 1, net, secret)
    activity = []
    for inp, expected_nf in zip(inputs, nfs):
        assert len(inp.path) == DEPTH and 0 <= inp.index < 2**DEPTH
        assert len(inp.occurrence) == 48
        cm, used = c.note(net, owner, asset, inp.salt, inp.native, inp.token)
        activity.append(used)
        value = c.hash("leaf", 5, inp.occurrence, cm)
        c.groups["41-bit unsigned borrow comparator"] += 2 * 41
        c.require_equal(inp.index < count, True, 1)
        for level, sibling in enumerate(inp.path):
            assert len(sibling) == 48
            c.groups["order path children using conditional swap"] += 384
            left, right = (sibling, value) if (inp.index >> level) & 1 else (value, sibling)
            value = c.hash("parent", 3, bytes([level]), left, right)
        c.require_equal(c.hash("anchor", 6, net, le(count, 8), value), root, 384)
        c.require_equal(c.hash("nullifier", 7, net, secret, inp.occurrence, cm), expected_nf, 384)
    for (desc, salt, native, token), expected_cm in zip(outputs, cms):
        cm, used = c.note(net, desc, asset, salt, native, token)
        activity.append(used)
        c.require_equal(cm, expected_cm, 384)
    c.groups["OR of four token activity bits"] += 3
    c.require_equal(c.nonzero(int.from_bytes(asset, "little"), 256), any(activity), 1)
    for i, field in enumerate(("native", "token")):
        incoming = c.add(getattr(inputs[0], field), getattr(inputs[1], field))
        outgoing = c.add(outputs[0][i+2], outputs[1][i+2])
        if field == "native":
            outgoing = c.add(outgoing, fee)
        c.require_equal(incoming, outgoing, 66)
    return c


def example():
    # Fresh disposable input material. Only aggregate circuit counts are returned.
    net, asset = bytes(48), bytes([5])*32
    sec = secrets.token_bytes(48)
    owner = authority(net, sec)
    notes = [Note(owner, asset, secrets.token_bytes(48), v, t) for v, t in [(5, 11), (7, 23)]]
    notes_out = [Note(secrets.token_bytes(48), asset, secrets.token_bytes(48), 4, 13),
                 Note(owner, asset, secrets.token_bytes(48), 5, 21)]
    cid = secrets.token_bytes(48)
    entries = [(credit_occurrence(net, cid, i), n.cm(net)) for i, n in enumerate(notes)]
    top, paths = top_and_paths(entries, [0, 1])
    ins = [Input(n.salt, n.native, n.token, entries[i][0], i, tuple(paths[i]))
           for i, n in enumerate(notes)]
    outs = [(n.owner, n.salt, n.native, n.token) for n in notes_out]
    args = [net, 2, anchor(net, 2, top), [nf(net, sec, occ, cm) for occ, cm in entries],
            [n.cm(net) for n in notes_out], 3, sec, asset, ins, outs]
    c = eval_relation(*args)
    assert c.valid
    for index, replacement in [(1, 1), (2, bytes(48)), (3, args[3][::-1]),
                               (4, args[4][::-1]), (5, 2), (6, bytes(48)), (7, bytes(32)),
                               (8, [ins[0], replace(ins[1], index=0)]),
                               (8, [replace(ins[0], occurrence=ins[1].occurrence), ins[1]]),
                               (9, [outs[0], (owner, notes_out[1].salt, 5, 20)])]:
        bad = args.copy()
        bad[index] = replacement
        assert not eval_relation(*bad).valid
    # Order, duplicate commitment and stable occurrence behavior.
    extra = (occurrence(net, 0, args[3], 0), entries[0][1])
    assert extra[0] == occurrence(net, 0, args[3][::-1], 0)
    assert extra[0] != occurrence(net, 0, args[3], 1)
    assert nf(net, sec, *extra) != nf(net, sec, *entries[0])
    shifted, _ = top_and_paths([extra] + entries, [1, 2])
    assert shifted != top
    return c
