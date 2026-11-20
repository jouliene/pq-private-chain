"""Lower the funded MNG1 transfer or SLG1 leg into fixed Goldilocks rank-one constraints."""
import argparse
from array import array
from contextlib import contextmanager
import copy
import json
import os
import stat
from pathlib import Path
import struct
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "spend-proof-decision"))
from whir_port import ONE, P, add, constants, permute

MAGIC = b"FWHRCS01"
PUBLIC = {"MNG1": 31, "SLG1": 34}
DEPTH = 20
ZERO = {}
OPEN = 0x415354310001
SWAP_OPEN = 0x534c47310001
AK, PK, NOTE, CM, NF, RHO, NF_DUMMY = range(0x716e0001, 0x716e0008)
U32 = struct.Struct("<I")
PAIR = struct.Struct("<IQ")


def sub(a, b):
    return add((a, 1), (b, -1))


def total(items):
    return add(*[(v, 1) for v in items])


def literal(value):
    return {0: value} if value else ZERO


def vector(value, n):
    if not isinstance(value, list) or len(value) != n:
        raise ValueError("wrong witness vector length")
    return value


def words_as_bytes(words):
    if sys.byteorder == "little":
        return words.tobytes()
    result = words[:]
    result.byteswap()
    return result.tobytes()


class Circuit:
    def __init__(self, pub, parameters, output=None):
        self.z = array("Q", [1])
        self.public = [self.wire(v) for v in pub]
        self.parameters = parameters
        self.output = output
        self.rows = 0
        self.terms = [0, 0, 0]
        self.permutations = 0
        self.label = "public"
        self.failures = set()

    def wire(self, value):
        if type(value) is not int or not 0 <= value < P:
            raise ValueError("noncanonical witness field")
        idx = len(self.z)
        self.z.append(value)
        return {idx: 1}

    def wires(self, values, n):
        return [self.wire(value) for value in vector(values, n)]

    def val(self, expr):
        return sum(self.z[col] * v for col, v in expr.items()) % P

    def row(self, a, b, c):
        self.rows += 1
        for i, terms in enumerate((a, b, c)):
            self.terms[i] += len(terms)
            if self.output is not None:
                self.output.write(U32.pack(len(terms)))
                for col, coeff in sorted(terms.items()):
                    self.output.write(PAIR.pack(col, coeff))

    def constrain(self, a, b, c):
        self.row(a, b, c)
        if self.val(a) * self.val(b) % P != self.val(c):
            self.failures.add(self.label)

    def assign(self, a, b):
        c = self.wire(self.val(a) * self.val(b) % P)
        self.row(a, b, c)
        return c

    def sbox(self, x):
        x2 = self.assign(x, x)
        x4 = self.assign(x2, x2)
        return self.assign(self.assign(x4, x2), x)

    def eq(self, a, b):
        self.constrain(a, ONE, b)

    def equal4(self, a, b):
        for left, right in zip(a, b, strict=True):
            self.eq(left, right)

    def bit(self, x):
        self.constrain(x, sub(x, ONE), ZERO)
        return x

    def range(self, v, n):
        value = self.val(v)
        bits = [self.bit(self.wire((value >> i) & 1)) for i in range(n)]
        self.eq(v, add(*[(b, 1 << i) for i, b in enumerate(bits)]))

    def iszero(self, x):
        value = self.val(x)
        z = self.wire(int(value == 0))
        inv = self.wire(pow(value, -1, P) if value else 0)
        self.constrain(x, inv, sub(ONE, z))
        self.constrain(x, z, ZERO)
        return z

    def allzero(self, items):
        z = ONE
        for x in items:
            z = self.assign(z, self.iszero(x))
        return z

    def select(self, flag, yes, no):
        return add((no, 1), (self.assign(flag, sub(yes, no)), 1))

    def sponge(self, *parts):
        message = [word for part in parts for word in part] + [ONE]
        message.extend([ZERO] * (-len(message) % 8))
        state = [ZERO] * 12
        for start in range(0, len(message), 8):
            state[:8] = [add((a, 1), (b, 1)) for a, b in zip(state[:8], message[start:start+8])]
            state = permute(self, state, self.parameters)
            self.permutations += 1
        return state[:4]

    def tagged(self, tag, *parts):
        return self.sponge([literal(tag)], *parts)

    def opening(self, asset, note, key=None):
        self.label = "note ranges"
        native, token = self.wire(note["value"]), self.wire(note["token"])
        self.range(native, 62)
        self.range(token, 62)
        raw = self.wires(note["raw"], 4)
        if key is not None:
            raw = self.tagged(SWAP_OPEN, key, raw)
        nonempty = sub(ONE, self.iszero(token))
        tag = [self.assign(nonempty, limb) for limb in asset]
        return native, token, self.tagged(OPEN, tag, [token], raw)

    def path(self, cm, note, active):
        siblings, positions = note["siblings"], note["positions"]
        if not isinstance(siblings, list) or not isinstance(positions, list) or len(siblings) != len(positions) or len(siblings) > DEPTH:
            raise ValueError("invalid path encoding")
        for i in range(DEPTH):
            current = [self.val(x) for x in cm]
            level = vector(siblings[i], 3) if i < len(siblings) else [[0]*4]*3
            position = positions[i] if i < len(positions) else 0
            if type(position) is not int:
                raise ValueError("invalid path position encoding")
            # The native relation takes three siblings and a secret insertion position.
            # Equivalently witness the four ordered children and prove exactly one is
            # the running commitment. Only the funded root can authenticate this order.
            children = list(level)
            children.insert(position if 0 <= position < 4 else 0, current)
            positions4 = [self.bit(self.wire(int(position == j))) for j in range(4)]
            self.eq(total(positions4), ONE)
            slots = [self.wires(child, 4) for child in children]
            for flag, slot in zip(positions4, slots):
                for x, y in zip(slot, cm):
                    self.constrain(flag, sub(x, y), ZERO)
            parent = self.sponge(*slots)
            cm = [self.select(active[i], x, y) for x, y in zip(parent, cm)]
        return cm


def blank(profile):
    input_note = dict(ask=[0]*4, nk=[0]*4, value=0, rho=[0]*4, raw=[0]*4,
                      token=0, dummy=False, siblings=[], positions=[])
    output = dict(pk=[0]*4, value=0, raw=[0]*4, token=0)
    return dict(suite=profile, public=[0]*PUBLIC[profile], header=[0]*45, depth=0,
                inputs=[copy.deepcopy(input_note) for _ in range(2)], outputs=[copy.deepcopy(output) for _ in range(2)],
                asset_id=[0]*4, fee=0, delta=0, auth_key=[0]*8, ct_digest=[0]*4)


def compile_relation(profile, params, w, output=None):
    if w["suite"] != profile:
        raise ValueError("private witness suite mismatch")
    c = Circuit(vector(w["public"], PUBLIC[profile]), params, output)
    pub = c.public
    c.label = "header"
    header = c.wires(w["header"], 45)
    c.range(pub[4], 32)
    c.eq(header[4], pub[4])
    c.equal4(c.sponge(header), pub[:4])
    depth = c.wire(w["depth"])
    active = []
    c.label = "shared depth"
    for j in range(DEPTH):
        bit = c.bit(c.wire(int(j < w["depth"])))
        if j:
            c.constrain(bit, sub(ONE, active[-1]), ZERO)
        active.append(bit)
    c.eq(total(active), depth)

    c.label = "asset and policy"
    asset = c.wires(w["asset_id"], 4)
    for x in asset:
        c.range(x, 63)
    c.eq(c.wire(w["delta"]), ZERO)
    c.eq(c.wire(w["fee"]), pub[21])
    c.equal4(c.wires(w["ct_digest"], 4), pub[22:26])
    key = None
    if profile == "MNG1":
        c.eq(pub[21], literal(3))
        for x in pub[26:31]:
            c.eq(x, ZERO)
    else:
        c.constrain(pub[21], sub(pub[21], literal(3)), ZERO)
        key = pub[26:34]
        for x, copied in zip(key, c.wires(w["auth_key"], 8)):
            c.range(x, 32)
            c.eq(x, copied)

    nfs = [pub[5:9], pub[9:13]]
    cms = [pub[13:17], pub[17:21]]
    dummy, amounts, tokens = [], [], []
    for i, note in enumerate(vector(w["inputs"], 2)):
        if type(note["dummy"]) not in (bool, int):
            raise ValueError("invalid dummy encoding")
        c.label = "dummy flag"
        flag = c.bit(c.wire(int(note["dummy"])))
        dummy.append(flag)
        native, token, opening = c.opening(asset, note)
        amounts.append(native)
        tokens.append(token)
        c.label = "dummy balances"
        c.constrain(flag, native, ZERO)
        c.constrain(flag, token, ZERO)
        ask, nk, rho = (c.wires(note[k], 4) for k in ("ask", "nk", "rho"))
        pk = c.tagged(PK, c.tagged(AK, ask), nk)
        cm = c.tagged(CM, c.tagged(NOTE, pk, rho, opening), [native])
        c.label = "path position or membership"
        root = c.path(cm, note, active)
        for x, y in zip(root, header[13:17]):
            c.constrain(sub(ONE, flag), sub(x, y), ZERO)
        c.label = "published nullifier"
        nf_tag = add((literal(NF), 1), (flag, NF_DUMMY - NF))
        c.equal4(c.sponge([nf_tag], nk, rho, opening), nfs[i])

    c.label = "funded input and distinct nullifiers"
    c.constrain(dummy[0], dummy[1], ZERO)
    if profile == "SLG1":
        c.eq(dummy[0], ZERO)
    c.eq(c.allzero([sub(a, b) for a, b in zip(*nfs)]), ZERO)

    for i, note in enumerate(vector(w["outputs"], 2)):
        native, token, opening = c.opening(asset, note, key)
        amounts.append(native)
        tokens.append(token)
        rho = c.tagged(RHO, *nfs, [literal(i)])
        result = c.tagged(CM, c.tagged(NOTE, c.wires(note["pk"], 4), rho, opening), [native])
        c.label = "published output"
        c.equal4(result, cms[i])

    c.label = "native conservation"
    c.eq(total(amounts[:2]), total([*amounts[2:], pub[21]]))
    c.label = "token conservation"
    incoming = total(tokens[:2])
    c.eq(incoming, total(tokens[2:]))
    c.label = "zero token tag"
    c.eq(c.iszero(incoming), c.allzero(asset))
    return c


def assign(profile, constants_path, witness):
    """Return private canonical field words beginning with 1 and the complete public input vector."""
    c = compile_relation(profile, constants(constants_path), witness)
    if c.failures:
        raise ValueError("unsatisfied " + ", ".join(sorted(c.failures)))
    return c.z


def register(profile, source, path):
    # Publish only a complete matrix. Hard linking keeps accidental replacement and
    # concurrent registration from changing an operator's existing registration.
    with tempfile.NamedTemporaryFile(dir=path.parent) as matrix:
        matrix.write(MAGIC + bytes(12))
        c = compile_relation(profile, constants(source), blank(profile), matrix)
        matrix.seek(8)
        matrix.write(struct.pack("<III", PUBLIC[profile], len(c.z), c.rows))
        matrix.seek(0)
        import hashlib
        digest = hashlib.file_digest(matrix, "sha256").hexdigest()
        os.fchmod(matrix.fileno(), 0o644)
        os.link(matrix.name, path)
    return dict(profile=profile, public=PUBLIC[profile], columns=len(c.z), rows=c.rows,
                private_columns=len(c.z)-1-PUBLIC[profile], nnz=c.terms, permutations=c.permutations,
                matrix_sha256=digest, matrix_bytes=path.stat().st_size)


@contextmanager
def private_stream(name, mode):
    if name == "-":
        original = sys.stdin.buffer if mode == "rb" else sys.stdout.buffer
        fd = os.dup(original.fileno())
    else:
        path = Path(name)
        if path.parent != Path("/proc/self/fd") or not path.name.isdecimal():
            raise ValueError("use a pipe or inherited private memfd")
        fd = os.dup(int(path.name))
    with os.fdopen(fd, mode) as stream:
        target = os.readlink("/proc/self/fd/" + str(fd))
        mode_bits = os.fstat(fd).st_mode
        if not (stat.S_ISFIFO(mode_bits) or stat.S_ISSOCK(mode_bits) or target.startswith("/memfd:")):
            raise ValueError("private witness and assignment must stay in pipes or anonymous memory")
        yield stream


def main():
    args = argparse.ArgumentParser(description=__doc__)
    subs = args.add_subparsers(dest="mode", required=True)
    for mode in ("register", "assign"):
        p = subs.add_parser(mode)
        p.add_argument("profile", choices=PUBLIC)
        p.add_argument("constants", type=Path)
        if mode == "assign":
            p.add_argument("witness")
        p.add_argument("output")
    a = args.parse_args()
    if a.mode == "register":
        print(json.dumps(register(a.profile, a.constants, Path(a.output)), sort_keys=True))
        return
    with private_stream(a.witness, "rb") as source:
        witness = json.load(source)
    assigned = assign(a.profile, a.constants, witness)
    with private_stream(a.output, "wb") as output:
        output.write(words_as_bytes(assigned))


if __name__ == "__main__":
    main()
