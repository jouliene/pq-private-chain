"""Length-delimited local wire format and domain-separated Fiat–Shamir transcript."""
import hashlib
from field import BYTES, WIDE, encode, decode

STATE_BYTES = 64 if WIDE else 32


def hash_bytes(label, *chunks):
    h = hashlib.shake_256(b"FS01-SmallWoodPlus-C1-R1CS-research-v1\0")
    for part in (label, *chunks):
        h.update(len(part).to_bytes(8,"little"))
        h.update(part)
    return h


class Transcript:
    def __init__(self, statement, packet=None):
        self.state = hash_bytes(b"statement", statement).digest(STATE_BYTES)
        self.producing = packet is None
        self.packet = bytearray() if self.producing else memoryview(packet)
        self.pos = 0

    def message(self, label, length, value=None):
        if self.producing:
            if value is None or len(value) != length:
                raise ValueError("wrong prover message length")
            self.packet.extend(value)
        else:
            value = self.packet[self.pos:self.pos+length]
            if len(value) != length:
                raise ValueError("truncated proof")
            self.pos += length
        self.state = hash_bytes(b"message", self.state, label, value).digest(STATE_BYTES)
        return value

    def fields(self, label, n, values=None):
        raw = None if values is None else encode(values)
        return decode(self.message(label, BYTES*n, raw))

    def challenge(self, label, n):
        out = hash_bytes(b"challenge", self.state, label, n.to_bytes(8, "little")).digest(BYTES*n)
        self.state = hash_bytes(b"continue", self.state, label, out).digest(STATE_BYTES)
        return decode(out)
