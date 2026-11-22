"""Isolated SGM1 registration. Every proof statement is derived from an eligible local anchor."""
from pathlib import Path
import hashlib
import os
import subprocess
import sys
from dataclasses import dataclass

HERE = Path(__file__).resolve().parent
EX = HERE.parent
BINDING = EX / "fresh-spend" / "binding"
sys.path[:0] = [str(BINDING), str(EX / "structured-keccak" / "harness"),
                str(EX / "hidden-membership" / "paths")]
from envelope import Body, RECEIPT, SIGNATURE, pair_frame, pair_message
from payment_codec import anchor
from relation import Statement, le, need, occurrence
from funding_fixture import ledger as replay_funding

LEG_BOUND = 262144
PAIR_BOUND = 20 + 2 * LEG_BOUND
ANCHOR_WINDOW = 64

def helper(program, op, data):
    return subprocess.run([os.environ["FS_RECEIPT_NODE"], BINDING / program, op],
                          input=data, stdout=subprocess.PIPE, check=True).stdout

def digest(data):
    return hashlib.sha256(data).digest()

class Leg(Body):
    def prefix(self):
        need(self.backend == 1, "unregistered suite")
        return b"SGM1" + super().prefix()[4:]

@dataclass(frozen=True)
class Parsed:
    body: Leg
    auth: bytes
    proof: bytes
    core: bytes
    signature: bytes
    def statement(self, chain, root, count):
        b = self.body
        return Statement(chain, root, count, b.fee, b.nfs, b.cms,
                         b.intent(chain, root, count), self.auth)
    def rows(self, chain):
        return [(occurrence(chain, self.body.role, self.body.nfs, i), cm)
                for i, cm in enumerate(self.body.cms)]

def parse_leg(wire, role):
    tail = 136 if role else 0
    signed = SIGNATURE if role else 0
    off = 398 + 2 * RECEIPT
    start = off + tail + 8
    need(start + signed < len(wire) <= LEG_BOUND and wire[:6] == b"SGM1" + bytes((1,role)), "leg framing")
    u64 = lambda start: int.from_bytes(wire[start:start+8], "little")
    size = u64(start - 8)
    need(start + size + signed == len(wire), "proof framing")
    b = Leg(1, role, wire[6:70], u64(70), (wire[78:142],wire[142:206]),
            (wire[206:270],wire[270:334]), (wire[398:398+RECEIPT],wire[398+RECEIPT:off]),
            wire[off:off+64] if role else b"", wire[off+64:off+128] if role else b"",
            u64(off+128) if role else 0)
    end = start + size
    return Parsed(b, wire[334:398], wire[start:end], wire[:end], wire[end:])

def parse(wire):
    if wire[:4] == b"SGM1":
        legs = (parse_leg(wire, 0),)
    else:
        need(wire[:4] == b"FSW1" and 20 < len(wire) <= PAIR_BOUND, "bundle framing")
        a, b = (int.from_bytes(wire[i:i+8],"little") for i in (4,12))
        need(a <= LEG_BOUND and b <= LEG_BOUND and 20+a+b == len(wire), "bundle lengths")
        legs = (parse_leg(wire[20:20+a],1), parse_leg(wire[20+a:],2))
        left, right = (l.body for l in legs)
        need(left.terms == right.terms and left.expiry == right.expiry
             and left.ephemeral != right.ephemeral and left.fee > 0 and right.fee == 0,
             "inconsistent swap terms, keys, expiry or payer")
    nfs = [nf for l in legs for nf in l.body.nfs]
    need(len(set(nfs)) == len(nfs), "duplicate nullifier in operation")
    return legs

def check_signatures(legs, chain):
    if len(legs) == 2:
        message = pair_message(chain, *(leg.core for leg in legs))
        for leg in legs:
            need(helper("approval.mjs", "verify", message + leg.body.ephemeral + leg.signature) == b"\1",
                 "invalid pair approval")

def funded(prefix, pin):
    raw = replay_funding(Path(prefix), pin.hex())
    count = int.from_bytes(raw[68:72], "little")
    need(raw[:4] == b"HMF1" and len(raw) == 72 + count*128, "invalid initial funding")
    return raw[4:68], [(raw[i:i+64],raw[i+64:i+128]) for i in range(72,len(raw),128)]
