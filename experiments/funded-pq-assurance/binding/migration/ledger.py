"""Atomic fresh-C-spend to N7 bridge admission.

The C packet is the spend authorization. Its inputs consume funded C notes;
its outputs exist only as private conservation witnesses for the equality
proof and are never inserted into either funded tree.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_384
import json
import sqlite3
import struct
import subprocess

from bundle import BridgeBundle


P = 2**64 - 2**32 + 1
ZERO4 = (0, 0, 0, 0)
CT = 1792


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def fields(raw, width):
    need(len(raw) == 8 * width, "field digest width")
    result = struct.unpack("<" + "Q" * width, raw)
    need(all(word < P for word in result), "noncanonical field digest")
    return result


def packed(words):
    need(all(type(word) is int and 0 <= word < P for word in words), "field words")
    return struct.pack("<" + "Q" * len(words), *words)


@dataclass(frozen=True)
class CEffect:
    anchor: bytes
    height: int
    nullifiers: tuple[tuple[int, ...], tuple[int, ...]]
    outputs: tuple[tuple[int, ...], tuple[int, ...]]
    fee: int
    receipts: tuple[bytes, bytes]
    depth: int


@dataclass(frozen=True)
class BranchContext:
    """Verifier-owned selected-branch view at the candidate height."""

    network: bytes
    parent_tip: bytes
    parent_height: int
    candidate_height: int
    # Ordered triples: (anchor identifier, anchor height, funded-tree depth).
    eligible_anchors: tuple[tuple[bytes, int, int], ...]

    def check(self, effect):
        need(
            len(self.network) == len(self.parent_tip) == 32
            and self.parent_height > 0
            and self.candidate_height == self.parent_height + 1,
            "branch context",
        )
        matches = [
            row
            for row in self.eligible_anchors
            if row == (effect.anchor, effect.height, effect.depth)
        ]
        need(len(matches) == 1, "C anchor absent, ineligible, or wrong depth")
        need(1 <= self.candidate_height - effect.height <= 8, "C anchor age")


class FramedRole:
    def __init__(self, executable, args):
        self.proc = subprocess.Popen(
            [str(executable), *map(str, args)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def call(self, message):
        self.proc.stdin.write(struct.pack("<I", len(message)) + message)
        self.proc.stdin.flush()
        header = self.proc.stdout.read(4)
        need(len(header) == 4, "C verifier frame")
        size, = struct.unpack("<I", header)
        need(size < 1 << 20, "C verifier reply bound")
        reply = self.proc.stdout.read(size)
        need(len(reply) == size, "C verifier reply")
        return reply

    def close(self):
        if self.proc.poll() is None:
            self.proc.stdin.write(struct.pack("<I", 0))
            self.proc.stdin.flush()
        self.proc.stdin.close()
        self.proc.wait(timeout=30)
        errors = self.proc.stderr.read()
        self.proc.stdout.close()
        self.proc.stderr.close()
        need(self.proc.returncode == 0, "C verifier exit")
        return errors

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def c_inner(packet):
    need(len(packet) > 15 and packet[:6] == b"MSP3\x01\x00", "C transfer envelope")
    inner = packet[6:]
    need(inner[:5] == b"MNG3\x01", "C inner suite")
    proof_size = int.from_bytes(inner[5:9], "little")
    need(proof_size > 0 and len(inner) == 9 + proof_size + 2 * CT, "C inner length")
    return inner


def verify_c(executable, key_directory, packet):
    with FramedRole(executable, ["verify", key_directory]) as role:
        reply = role.call(c_inner(packet))
    need(reply[:1] == b"1" and len(reply) == 1 + 172 + 2 * CT + 40 + 1, "invalid C proof")
    row = reply[1:]
    anchor = row[:32]
    height = int.from_bytes(row[32:36], "little")
    nfs = (fields(row[36:68], 4), fields(row[68:100], 4))
    cms = (fields(row[100:132], 4), fields(row[132:164], 4))
    fee = int.from_bytes(row[164:172], "little")
    receipts = (row[172:172 + CT], row[172 + CT:172 + 2 * CT])
    issue_id = fields(row[-41:-9], 4)
    supply = int.from_bytes(row[-9:-1], "little")
    depth = row[-1]
    need(fee == 3 and issue_id == ZERO4 and supply == 0 and 1 <= depth <= 20, "C transfer effect")
    return CEffect(anchor, height, nfs, cms, fee, receipts, depth)


def verify_bridge(executable, statement_path, proof_path):
    run = subprocess.run(
        [str(executable), "verify", str(statement_path), str(proof_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    need(run.returncode == 0, "invalid bridge proof")
    result = json.loads(run.stdout)
    need(result.get("accepted") is True, "bridge verifier verdict")
    return result


def bridge_context(branch, c_packet, effect, successor_outputs, successor_receipts):
    need(len(successor_outputs) == len(successor_receipts) == 2, "bridge context shape")
    h = sha3_384()
    h.update(b"C2N7/bridge-context/v3\0")
    h.update(branch.network)
    h.update(branch.parent_tip)
    h.update(struct.pack("<II", branch.parent_height, branch.candidate_height))
    h.update(sha3_384(c_packet).digest())
    h.update(effect.anchor)
    h.update(struct.pack("<IBQ", effect.height, effect.depth, effect.fee))
    for digest in (*effect.nullifiers, *effect.outputs, *successor_outputs):
        h.update(packed(digest))
    for receipt in (*effect.receipts, *successor_receipts):
        h.update(sha3_384(receipt).digest())
    return struct.unpack("<12I", h.digest())


class Ledger:
    def __init__(self, activation_height=26):
        need(activation_height > 0, "activation height")
        self.activation_height = activation_height
        self.db = sqlite3.connect(":memory:", isolation_level=None)
        self.db.executescript("""
            PRAGMA foreign_keys=ON;
            CREATE TABLE blocks(
                height INTEGER PRIMARY KEY,
                bridge INTEGER NOT NULL CHECK(bridge IN (0,1)),
                fee INTEGER NOT NULL,
                bundle BLOB NOT NULL,
                c_packet_id BLOB NOT NULL UNIQUE
            );
            CREATE TABLE legacy_spent(nf BLOB PRIMARY KEY, height INTEGER NOT NULL REFERENCES blocks(height));
            CREATE TABLE successor_outputs(cm BLOB PRIMARY KEY, height INTEGER NOT NULL REFERENCES blocks(height));
        """)

    def snapshot(self):
        blocks, bridges, fees = self.db.execute(
            "SELECT count(*),coalesce(sum(bridge),0),coalesce(sum(fee),0) FROM blocks"
        ).fetchone()
        return {
            "blocks": blocks,
            "fees": fees,
            "legacy_spent": self.db.execute("SELECT count(*) FROM legacy_spent").fetchone()[0],
            "successor_outputs": self.db.execute("SELECT count(*) FROM successor_outputs").fetchone()[0],
            "c_packets": bridges,
            "equality_proofs": bridges,
            "embedded_c_receipts": 2 * bridges,
            "successor_receipts": 2 * bridges,
        }

    def artifact_sizes(self, height):
        row = self.db.execute(
            "SELECT bundle FROM blocks WHERE height=? AND bridge=1",
            (height,),
        ).fetchone()
        need(row is not None, "missing bridge artifacts")
        return BridgeBundle.decode(row[0]).component_sizes()

    def admit(self, branch, bundle, verify_c_packet, verify_equality, c_nullifier_is_spent):
        before = self.snapshot()
        try:
            self.db.execute("BEGIN IMMEDIATE")
            encoded_bundle = bundle.encode()
            statement = bundle.statement
            need(branch.candidate_height >= self.activation_height, "bridge inactive")
            effect = verify_c_packet(bundle.c_packet)
            need(effect.fee == 3, "exact C fee")
            branch.check(effect)
            need(
                tuple(map(tuple, statement["c_input_nullifiers"])) == effect.nullifiers,
                "C input nullifier binding",
            )
            # This callback is a verifier-owned view of the selected C branch,
            # not producer data and not this prototype's private bridge table.
            # The latter catches bridge replays; this check also catches a
            # canonical ordinary C spend that happened before the bridge.
            need(
                all(not c_nullifier_is_spent(nf) for nf in effect.nullifiers),
                "C input already spent on selected branch",
            )
            need(
                tuple(map(tuple, statement["transient_c_outputs"])) == effect.outputs,
                "transient C output binding",
            )
            successors = tuple(map(tuple, statement["successor_outputs"]))
            need(len(successors) == len(set(successors)) == 2, "successor output uniqueness")
            expected = bridge_context(
                branch,
                bundle.c_packet,
                effect,
                successors,
                bundle.successor_receipts,
            )
            need(tuple(statement["bridge_context"]) == expected, "verifier-owned bridge context")
            verify_equality(statement, bundle.equality_proof)
            self.db.execute(
                "INSERT INTO blocks VALUES (?,?,?,?,?)",
                (
                    branch.candidate_height,
                    1,
                    effect.fee,
                    encoded_bundle,
                    sha3_384(bundle.c_packet).digest(),
                ),
            )
            self.db.executemany(
                "INSERT INTO legacy_spent VALUES (?,?)",
                ((packed(nf), branch.candidate_height) for nf in effect.nullifiers),
            )
            self.db.executemany(
                "INSERT INTO successor_outputs VALUES (?,?)",
                ((packed(cm), branch.candidate_height) for cm in successors),
            )
            self.db.execute("COMMIT")
            return effect
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            need(self.snapshot() == before, "non-atomic bridge rejection")
            raise

    def ordinary_c_spend(self, height, nullifiers, fee=3):
        before = self.snapshot()
        try:
            self.db.execute("BEGIN IMMEDIATE")
            need(height < self.activation_height, "standalone C retired at bridge activation")
            need(fee == 3, "exact C fee")
            self.db.execute(
                "INSERT INTO blocks VALUES (?,?,?,?,?)",
                (
                    height,
                    0,
                    fee,
                    b"ordinary-C",
                    sha3_384(b"ordinary-C-" + struct.pack("<I", height)).digest(),
                ),
            )
            self.db.executemany(
                "INSERT INTO legacy_spent VALUES (?,?)",
                ((packed(tuple(nf)), height) for nf in nullifiers),
            )
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            need(self.snapshot() == before, "non-atomic ordinary rejection")
            raise

    def rollback(self, height):
        with self.db:
            self.db.execute("DELETE FROM legacy_spent WHERE height=?", (height,))
            self.db.execute("DELETE FROM successor_outputs WHERE height=?", (height,))
            self.db.execute("DELETE FROM blocks WHERE height=?", (height,))

    def contains_transient_c_output(self, commitment):
        return self.db.execute(
            "SELECT 1 FROM successor_outputs WHERE cm=?", (packed(tuple(commitment)),)
        ).fetchone() is not None
