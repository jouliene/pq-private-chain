"""Independent funded membership/authority/one-spend specification. No prover or verifier imports."""
from dataclasses import dataclass
import json
from pathlib import Path
import struct

P = 2**64 - 2**32 + 1
ZERO = bytes(32)
MAX_LEAVES = 4**20
AK, PK, NOTE, CM, NF, RHO, NF_DUMMY = range(0x716E0001, 0x716E0008)
OPEN = 0x415354310001
SWAP_OPEN = 0x534C47310001
PARAMS = {name: tuple(int(k, 16) for k in row)
          for name, row in json.loads(Path(__file__).with_name("reference_constants.json").read_bytes()).items()}


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def uint(value, bits):
    need(type(value) is int and 0 <= value < 2**bits, f"unsigned {bits}-bit integer required")
    return value


def words(data):
    need(type(data) is bytes and len(data) == 32, "digest length")
    result = struct.unpack("<4Q", data)
    need(all(v < P for v in result), "noncanonical field digest")
    return result


def external(state):
    mixed = []
    for i in (0, 4, 8):
        a, b, c, d = state[i:i+4]
        mixed.extend((2*a+3*b+c+d, a+2*b+3*c+d, a+b+2*c+3*d, 3*a+b+c+2*d))
    column = [sum(mixed[j::4]) for j in range(4)]
    return [(v + column[i % 4]) % P for i, v in enumerate(mixed)]


def full_rounds(state, constants):
    for start in range(0, len(constants), 12):
        state = external([pow(x+k, 7, P) for x,k in zip(state, constants[start:start+12], strict=True)])
    return state


def hash_fields(message):
    fields = list(message)
    need(all(type(v) is int and 0 <= v < P for v in fields), "noncanonical hash input")
    fields.append(1)
    fields.extend([0] * (-len(fields) % 8))
    state = [0] * 12
    for block in range(0, len(fields), 8):
        for i in range(8):
            state[i] = (state[i] + fields[block+i]) % P
        state = full_rounds(external(state), PARAMS["INITIAL_EXTERNAL_CONSTANTS"])
        for key in PARAMS["INTERNAL_CONSTANTS"]:
            state[0] = pow(state[0]+key, 7, P)
            total = sum(state)
            state = [(total+x*d) % P for x,d in zip(state, PARAMS["MATRIX_DIAG"], strict=True)]
        state = full_rounds(state, PARAMS["TERMINAL_EXTERNAL_CONSTANTS"])
    return struct.pack("<4Q", *state[:4])


def hash_bytes(data):
    terminated = data + b"\x01"
    padded = terminated + bytes(-len(terminated) % 4)
    return hash_fields(i for (i,) in struct.iter_unpack("<I", padded))


def tagged(tag, *parts):
    message = [tag]
    for item in parts:
        if type(item) is bytes:
            message.extend(words(item))
        else:
            message.append(item)
    return hash_fields(message)


def parent(children):
    need(len(children) == 4, "exactly four children required")
    return hash_fields(v for child in sorted(children) for v in words(child))


def tree_depth(count):
    uint(count, 64)
    need(count <= MAX_LEAVES, "tree capacity")
    return max(1, ((count-1).bit_length()+1)//2) if count else 0


@dataclass(frozen=True)
class Step:
    siblings: tuple
    sorted_position: int


@dataclass(frozen=True, init=False)
class Tree:
    """Selected anchor's authenticated append history; indices are private oracle inputs."""
    levels: tuple
    root: bytes
    count: int

    def __init__(self, leaves):
        row = tuple(leaves)
        count = len(row)
        depth = tree_depth(count)
        for leaf in row:
            words(leaf)
            need(leaf != ZERO, "zero funding commitment")
        need(len(set(row)) == count, "duplicate funding commitment")
        levels = []
        for _ in range(depth):
            levels.append(row)
            padded = row + (ZERO,) * (-len(row) % 4)
            row = tuple(parent(padded[i:i+4]) for i in range(0, len(padded), 4))
        object.__setattr__(self, "levels", tuple(levels))
        object.__setattr__(self, "root", row[0] if count else ZERO)
        object.__setattr__(self, "count", count)

    def path(self, index):
        need(type(index) is int and 0 <= index < self.count, "funding index outside selected history")
        steps = []
        for row in self.levels:
            start = index - index % 4
            group = row[start:start+4]
            children = sorted(group + (ZERO,) * (4-len(group)))
            pos = children.index(row[index])
            steps.append(Step(tuple(children[:pos]+children[pos+1:]), pos))
            index //= 4
        return tuple(steps)


def path_root(leaf, path, count):
    words(leaf)
    need(leaf != ZERO and count > 0 and len(path) == tree_depth(count), "funded path depth or leaf")
    current = leaf
    for step in path:
        pos = step.sorted_position
        need(type(pos) is int and 0 <= pos < 4 and len(step.siblings) == 3, "path step shape")
        row = list(step.siblings)
        row.insert(pos, current)
        need(row == sorted(row), "path children out of canonical order")
        need(pos == row.index(current), "noncanonical equal-child position")
        current = parent(row)
    return current


@dataclass(frozen=True)
class Authority:
    ask: bytes
    nk: bytes

    @property
    def pk(self):
        return tagged(PK, tagged(AK, self.ask), self.nk)


@dataclass(frozen=True)
class Note:
    pk: bytes
    native: int
    token: int
    asset: bytes
    rho: bytes
    raw: bytes

    @property
    def typed(self):
        uint(self.native, 62)
        uint(self.token, 62)
        need(all(v < 2**63 for v in words(self.asset)), "asset limb range")
        need((self.token == 0) == (self.asset == ZERO), "asset quantity and ID disagree")
        return tagged(OPEN, self.asset, self.token, self.raw)

    @property
    def commitment(self):
        return tagged(CM, tagged(NOTE, self.pk, self.rho, self.typed), self.native)

    def nullifier(self, nk, dummy=False):
        return tagged(NF_DUMMY if dummy else NF, nk, self.rho, self.typed)


def reward(context, pk, value):
    need(type(context) is bytes and len(context) == 32, "reward context length")
    words(pk)
    body = context + pk + struct.pack("<QQ", uint(value, 62), 0)
    return Note(pk, value, 0, ZERO, hash_bytes(b"AST1/reward/rho" + body), hash_bytes(b"AST1/reward/raw" + body))


def swap_output_raw(authorization_key, raw):
    need(type(authorization_key) is bytes and len(authorization_key) == 32, "swap authorization key length")
    return tagged(SWAP_OPEN, *struct.unpack("<8I", authorization_key), raw)


@dataclass(frozen=True)
class Input:
    authority: Authority
    note: Note
    nullifier: bytes
    index: int | None
    path: tuple


def check_input(tree, witness, spent):
    n = witness.note
    dummy = witness.index is None
    need(n.pk == witness.authority.pk, "spend authority mismatch")
    need(n.nullifier(witness.authority.nk, dummy) == witness.nullifier, "published nullifier mismatch")
    need(witness.nullifier not in spent, "nullifier unavailable")
    if dummy:
        need(n.native == n.token == 0 and witness.path == (), "dummy carries value or occurrence")
    else:
        expected = tree.path(witness.index)
        cm = n.commitment
        need(tree.levels[0][witness.index] == cm, "opening differs from selected funding")
        need(witness.path == expected, "path differs from selected funding")
        need(path_root(cm, witness.path, tree.count) == tree.root, "wrong funded root")
    return witness.nullifier


def accept_inputs(tree, witnesses, spent, *, swap_leg=False):
    """Return a new immutable spent set after the entire two-slot subrelation succeeds."""
    need(len(witnesses) == 2 and any(w.index is not None for w in witnesses), "two slots and real funding required")
    need(not swap_leg or witnesses[0].index is not None, "swap first input must be real")
    added = [check_input(tree, w, spent) for w in witnesses]
    need(len(set(added)) == 2, "duplicate nullifier within transaction")
    return frozenset(spent).union(added)


@dataclass(frozen=True)
class Anchor:
    identifier: bytes
    height: int
    tree: Tree


def selected_inputs(history, head_height, anchor_id, anchor_height, witnesses, spent, *, swap_leg=False):
    """history and spent are supplied by the independently validated current branch."""
    uint(head_height, 32)
    uint(anchor_height, 32)
    need(1 <= head_height + 1 - anchor_height <= 8, "anchor outside spend window")
    anchor = history.get(anchor_height)
    need(anchor is not None and anchor.height == anchor_height and anchor.identifier == anchor_id,
         "anchor absent from selected branch")
    return accept_inputs(anchor.tree, witnesses, spent, swap_leg=swap_leg)
