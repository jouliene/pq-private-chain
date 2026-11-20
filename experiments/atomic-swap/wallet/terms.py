"""Canonical private agreement for two token-only outputs in the local SWP1 negotiation."""
from dataclasses import dataclass
from hashlib import sha256
import secrets
import struct

ZERO = bytes(32)
LIMIT = (1 << 62) - 1
MAGIC = b"SWPTER01"
SIZE = 8 + 32 + 32 + 4 + 2*(1601 + 32 + 8)


def need(ok, message):
    if not ok:
        raise ValueError(message)


def side_num(side):
    need(side in ("a", "b"), "swap side must be a or b")
    return 0 if side == "a" else 1


def asset_id(text):
    need(isinstance(text, str) and len(text) == 64, "expected 32-byte lowercase asset ID")
    raw = bytes.fromhex(text)
    need(raw.hex() == text and raw != ZERO and all(x < 128 for x in raw[7::8]), "invalid swap asset ID")
    return raw


@dataclass(frozen=True)
class Party:
    address: bytes
    give: bytes
    qty: int

    def __post_init__(self):
        need(len(self.address) == 1601 and self.address[0] == 1, "invalid private negotiation address")
        need(len(self.give) == 32 and self.give != ZERO and all(x < 128 for x in self.give[7::8]),
             "invalid private negotiation asset")
        need(type(self.qty) == int and 1 <= self.qty <= LIMIT, "invalid swap amount")


@dataclass(frozen=True)
class Terms:
    network: bytes
    blind: bytes
    expiry: int
    parties: tuple

    def __post_init__(self):
        need(len(self.network) == len(self.blind) == 32 and self.blind != ZERO and
             type(self.expiry) == int and 0 < self.expiry < 2**32, "invalid private negotiation header")
        need(len(self.parties) == 2 and self.parties[0].give != self.parties[1].give and
             self.parties[0].address[1:33] != self.parties[1].address[1:33], "expected distinct owners and assets")

    @classmethod
    def fresh(cls, network, expiry, parties):
        return cls(network, secrets.token_bytes(32), expiry, tuple(parties))

    def encode(self):
        return MAGIC+self.network+self.blind+struct.pack("<I", self.expiry)+b"".join(
            p.address+p.give+struct.pack("<Q", p.qty) for p in self.parties)

    @classmethod
    def decode(cls, raw):
        need(len(raw) == SIZE and raw.startswith(MAGIC), "invalid private agreement framing")
        parties = []
        offset = 76
        for _ in range(2):
            parties.append(Party(raw[offset:offset+1601], raw[offset+1601:offset+1633],
                                 int.from_bytes(raw[offset+1633:offset+1641], "little")))
            offset += 1641
        return cls(raw[8:40], raw[40:72], int.from_bytes(raw[72:76], "little"), tuple(parties))

    def commitment(self):
        return sha256(b"SWP1/private-terms/v1\0"+self.encode()).digest()

    def confirm(self, side, address, give, qty, take, expected):
        own, other = self.parties[side], self.parties[1-side]
        need((own.address, own.give, own.qty, other.give, other.qty) == (address, give, qty, take, expected),
             "negotiated economics or address differ from this wallet's instructions")
