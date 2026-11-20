"""Read two registered keys and optionally replay real public Fiat-Shamir transcripts."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import struct

HERE = Path(__file__).resolve().parent
EXP = HERE.parent.parent
for folder in ("token-profile", "atomic-swap", "managed-assets", "spend-proof-decision/candidate"):
    sys.path.insert(0, str(EXP / folder))
from parameters import read_key
from direct_wire import P, Wire
from managed_ops import parse
from swap_wire import split, pair
from packet import decode as decode_candidate

KEYS = {"MNG1": "managed-assets/native/registry/managed.vk",
        "SLG1": "atomic-swap/native/registry/swap.vk"}


def geometry():
    profiles = {}
    for suite, key_path in KEYS.items():
        key = read_key((EXP / key_path).read_bytes())
        registration = json.loads((EXP / key_path).parents[1].joinpath("REGISTER.json").read_bytes())
        assert registration["suite"] == suite
        assert registration["public_inputs"] == key["common"]["pi"]
        assert 1 << registration["degree_bits"] == key["trace_rows"]
        assert registration["folds"] == key["folds_bits"]
        key["gates_before_blinding"] = registration["gates_before_blinding"]
        profiles[suite] = key
    return profiles


class Poseidon:
    """Unoptimized reference permutation using the fork's original constants."""
    def __init__(self, source):
        text = (source / "src/poseidon.rs").read_text()
        table = text.split("pub const ALL_ROUND_CONSTANTS:", 1)[1].split("= [", 1)[1].split("];", 1)[0]
        self.round_constants = [int(x, 16) for x in re.findall(r"0x[0-9a-f]+", re.sub(r"//[^\n]*", "", table))]
        assert len(self.round_constants) == 360
        assert self.permute([0] * 12)[0] == 0x3c18a9786cb0b359

    def permute(self, state):
        circ = (17, 15, 41, 16, 2, 28, 13, 13, 39, 18, 34, 20)
        for r in range(30):
            row = [(s + c) % P for s, c in zip(state, self.round_constants[12*r:12*r+12])]
            for j in range(12 if r < 4 or r >= 26 else 1):
                row[j] = pow(row[j], 7, P)
            state = [(sum(c * row[(i+j) % 12] for j, c in enumerate(circ))
                      + (8*row[0] if i == 0 else 0)) % P for i in range(12)]
        return state

    def hash(self, words, leaf=False):
        state = [0] * 12
        if leaf:
            state[8] = len(words) + 1
        for i in range(0, len(words), 8):
            chunk = words[i:i+8]
            state[:len(chunk)] = chunk
            state = self.permute(state)
        return state[:4]


class Challenger:
    def __init__(self, permutation, width):
        self.permutation = permutation
        self.state = [0] * width
        self.pending = []
        self.outputs = []

    def duplex(self):
        self.state[:len(self.pending)] = self.pending
        self.state = self.permutation(self.state)
        self.outputs = self.state[:8]
        self.pending.clear()

    def observe(self, words):
        for w in words:
            self.outputs.clear()
            self.pending.append(w)
            if len(self.pending) == 8:
                self.duplex()

    def draw(self, count):
        result = []
        for _ in range(count):
            if self.pending or not self.outputs:
                self.duplex()
            result.append(self.outputs.pop())
        return result


class OriginalOracle:
    width = 12

    def __init__(self, poseidon):
        self.permute = poseidon.permute
        self.poseidon = poseidon

    def read_digest(self, rd):
        return rd.words(4)

    def observe_digest(self, raw):
        return raw

    def leaf(self, words):
        return self.poseidon.hash(words, leaf=True)

    def node(self, left, right):
        return self.poseidon.hash(list(left) + list(right))


class WideOracle:
    width = 16

    def permute(self, words):
        xof = hashlib.shake_256(b"K384/FS/v1\0" + struct.pack("<16Q", *words))
        size = 16 * 8
        while True:
            accepted = [v for (v,) in struct.iter_unpack("<Q", xof.digest(size)) if v < P]
            if len(accepted) >= 16:
                return accepted[:16]
            size += 32

    def read_digest(self, rd):
        return rd.take(48)

    def observe_digest(self, raw):
        return [int.from_bytes(raw[i:i+7], "little") for i in range(0, 48, 7)]

    def leaf(self, words):
        return hashlib.sha3_384(b"K384/LEAF/v1\0" + struct.pack("<Q", len(words))
                                + struct.pack(f"<{len(words)}Q", *words)).digest()

    def node(self, left, right):
        return hashlib.sha3_384(b"K384/NODE/v1\0" + left + right).digest()


def transcript(leg, key_path, common, poseidon, oracle):
    suite = leg[:4].decode("ascii")
    degree_bits = common["degree_bits"]
    q = common["queries"]
    folds = common["folds"]
    n = 1 << (degree_bits + 5)
    vk = Wire(key_path.read_bytes())
    assert vk.integer() == 4
    fixed_cap = [oracle.read_digest(vk) for _ in range(16)]
    circuit_digest = oracle.read_digest(vk)
    size = int.from_bytes(leg[5:9], "little")
    assert leg[4] == 1 and len(leg) == 9 + size + 3584
    rd = Wire(leg[9:9+size])

    def cap():
        return [v for _ in range(16) for v in oracle.observe_digest(oracle.read_digest(rd))]

    caps = [cap() for _ in range(3)]
    # Wire serialization places the next-point Z opening immediately after Z.
    c, s, w, z, z_next, partial, quotient = (rd.words(2*n) for n in [4, 60, 135, 2, 2, 14, 16])
    fri_caps = [cap() for _ in folds]
    initial_paths = []
    for _ in range(q):
        depth = degree_bits + 5 - 4
        for idx, width in enumerate((64, 139, 20, 20)):
            leaf = rd.words(width)
            assert rd.integer(1) == depth
            siblings = [oracle.read_digest(rd) for _ in range(depth)]
            if idx == 0:
                initial_paths.append((leaf, siblings))
        for step in folds:
            depth -= step
            rd.words(2 << step)
            assert rd.integer(1) == depth
            for _ in range(depth):
                oracle.read_digest(rd)
    terminal = rd.words(8)
    nonce = rd.words(1)
    pi_length = rd.integer()
    assert pi_length == common["pi"]
    pi = rd.words(pi_length)
    assert not rd.read()
    fs = Challenger(oracle.permute, oracle.width)
    fs.observe([5, 4, 0, 1, 2, 3, q, 1, degree_bits, *folds])
    fs.observe(oracle.observe_digest(circuit_digest))
    fs.observe(poseidon.hash(pi))
    fs.observe(caps[0])
    out = {"betas": fs.draw(2), "gammas": fs.draw(2)}
    fs.observe(caps[1])
    out["alphas"] = fs.draw(2)
    fs.observe(caps[2])
    out["zeta"] = fs.draw(2)
    fs.observe(c + s + w + z + partial + quotient + z_next)
    out["fri_alpha"] = fs.draw(2)
    out["fri_betas"] = []
    for cap in fri_caps:
        fs.observe(cap)
        out["fri_betas"].append(fs.draw(2))
    fs.observe(terminal + nonce)
    out["pow_response"] = fs.draw(1)[0]
    indices = [x % n for x in fs.draw(q)]
    for idx, (leaf, path) in zip(indices, initial_paths):
        h = oracle.leaf(leaf)
        for sibling in path:
            left, right = (sibling, h) if idx & 1 else (h, sibling)
            h = oracle.node(left, right)
            idx >>= 1
        if list(h) != list(fixed_cap[idx]):
            raise ValueError("derived query failed to authenticate against registered fixed cap")
    return dict(suite=suite, inner_sha256=hashlib.sha256(leg).hexdigest(), proof_bytes=size,
                fee=pi[21], terminal_extension_coefficients=len(terminal)//2,
                checked_initial_paths=len(initial_paths), challenges=out, indices=indices)


def extract(public, core, profiles):
    ordinary = parse((public / "ordinary.bin").read_bytes())
    if ordinary.operation != "transfer":
        raise ValueError("expected a managed-format ordinary payment")
    a, b = pair(split((public / "swap.bin").read_bytes()))
    poseidon = Poseidon(core)
    runs = []
    for packet in (ordinary.inner, a.leg, b.leg):
        suite = packet[:4].decode()
        key = profiles[suite]
        common = dict(degree_bits=key["trace_rows"].bit_length()-1, queries=key["config"]["fri"]["queries"],
                      folds=key["folds_bits"], pi=key["common"]["pi"])
        runs.append(transcript(packet, EXP / KEYS[suite], common, poseidon, OriginalOracle(poseidon)))
    return runs


def extract_candidate(public, core):
    wrap = (public / "ordinary.bin").read_bytes()
    assert wrap.startswith(b"K3P1\x01\x00K3M1\x01")
    legs = decode_candidate((public / "swap.bin").read_bytes())[0]
    profiles = EXP / "spend-proof-decision/candidate/registry"
    poseidon = Poseidon(core)
    runs = []
    for packet, role, key in [(wrap[6:], "ordinary", "managed.vk"), (legs[0], "leg", "swap.vk"),
                              (legs[1], "leg", "swap.vk")]:
        spec = json.loads((profiles / (role + "-REGISTER.json")).read_bytes())
        assert spec["suite"] == packet[:4].decode()
        common = dict(degree_bits=spec["degree_bits"], queries=64, folds=spec["folds"], pi=spec["public_inputs"])
        runs.append(transcript(packet, profiles / key, common, poseidon, WideOracle()))
    return runs


if __name__ == "__main__":
    if not __debug__:
        raise SystemExit("Run without -O to keep binary parser assertions enabled")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--public", type=Path)
    ap.add_argument("--candidate", type=Path, help="public candidate ordinary.bin and swap.bin directory")
    ap.add_argument("--core", type=Path, help="path to pinned qp-plonky2-core 1.5.5 source")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    if (bool(args.public) + bool(args.candidate)) != bool(args.core):
        ap.error("select one public capture and supply --core, or neither")
    if args.public:
        result, expected = extract(args.public, args.core, geometry()), "TRANSCRIPTS.json"
    elif args.candidate:
        result, expected = extract_candidate(args.candidate, args.core), "CANDIDATE-TRANSCRIPTS.json"
    else:
        result, expected = geometry(), "KEYS.json"
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.check:
        if encoded != (HERE / expected).read_text():
            raise SystemExit("Decoded data differs from " + expected)
        print(expected, "matched")
    else:
        sys.stdout.write(encoded)
