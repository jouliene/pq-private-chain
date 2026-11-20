"""Canonical private SWP1 agreement for an exchange of two distinct currencies."""
from dataclasses import dataclass
from hashlib import sha256
import secrets
import struct

ZERO = bytes(32)
LIMIT = (1 << 62) - 1
MAGIC = b"SWPTER01"
MAGIC_V2 = b"SWPTER02"
SIZE = 8 + 32 + 32 + 4 + 2*(1601 + 32 + 8)
SIZE_V2 = SIZE + 3  # Fee-payer side plus one currency tag per party.


def need(ok, message):
    if not ok:
        raise ValueError(message)


def side_num(side):
    need(side in ("a", "b"), "swap side must be a or b")
    return 0 if side == "a" else 1


def asset_id(text):
    if text == "native":
        return ZERO
    need(isinstance(text, str) and len(text) == 64, "expected native or a 32-byte lowercase asset ID")
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
        need(len(self.give) == 32 and all(x < 128 for x in self.give[7::8]), "invalid private negotiation asset")
        need(type(self.qty) == int and 1 <= self.qty <= LIMIT, "invalid swap amount")

    @property
    def native(self):
        return self.qty if self.give == ZERO else 0

    @property
    def token(self):
        return self.qty if self.give != ZERO else 0


@dataclass(frozen=True)
class Terms:
    network: bytes
    blind: bytes
    expiry: int
    parties: tuple
    payer: int = 0

    def __post_init__(self):
        need(len(self.network) == len(self.blind) == 32 and self.blind != ZERO and
             type(self.expiry) == int and 0 < self.expiry < 2**32, "invalid private negotiation header")
        need(type(self.payer) == int and self.payer in (0, 1), "invalid swap fee payer")
        need(len(self.parties) == 2 and self.parties[0].give != self.parties[1].give and
             self.parties[0].address[1:33] != self.parties[1].address[1:33], "expected distinct owners and assets")

    @classmethod
    def fresh(cls, network, expiry, parties, payer=None):
        parties = tuple(parties)
        if payer is None:
            payer = next((i for i, p in enumerate(parties) if p.give == ZERO), 0)
        return cls(network, secrets.token_bytes(32), expiry, parties, payer)

    @property
    def legacy(self):
        return self.payer == 0 and all(p.give != ZERO for p in self.parties)

    def fee(self, side):
        return 3 if side == self.payer else 0

    def encode(self):
        raw = bytearray((MAGIC if self.legacy else MAGIC_V2) + self.network + self.blind + struct.pack("<I", self.expiry))
        if not self.legacy:
            raw.append(self.payer)
        for party in self.parties:
            if not self.legacy:
                raw.append(int(party.give != ZERO))
            raw.extend(party.address + party.give + struct.pack("<Q", party.qty))
        return bytes(raw)

    @classmethod
    def decode(cls, raw):
        legacy = len(raw) == SIZE and raw.startswith(MAGIC)
        need(legacy or len(raw) == SIZE_V2 and raw.startswith(MAGIC_V2), "invalid private agreement framing")
        parties = []
        payer = 0 if legacy else raw[76]
        offset = 76 if legacy else 77
        for _ in range(2):
            kind = 1 if legacy else raw[offset]
            if not legacy:
                offset += 1
            party = Party(raw[offset:offset+1601], raw[offset+1601:offset+1633],
                          int.from_bytes(raw[offset+1633:offset+1641], "little"))
            need(kind == int(party.give != ZERO), "agreement currency tag disagrees with asset ID")
            parties.append(party)
            offset += 1641
        terms = cls(raw[8:40], raw[40:72], int.from_bytes(raw[72:76], "little"), tuple(parties), payer)
        need(terms.legacy == legacy, "noncanonical private terms version")
        return terms

    def commitment(self):
        domain = b"SWP1/private-terms/v1\0" if self.legacy else b"SWP1/private-terms/v2\0"
        return sha256(domain + self.encode()).digest()

    def confirm(self, side, address, give, qty, take, expected):
        own, other = self.parties[side], self.parties[1-side]
        need((own.address, own.give, own.qty, other.give, other.qty) == (address, give, qty, take, expected),
             "negotiated economics or address differ from this wallet's instructions")
