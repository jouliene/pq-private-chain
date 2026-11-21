"""Canonical public C-to-N7 bridge bundle codec."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_384
import json
import struct


MAGIC = b"C2N7B1\0\0"
HEADER = struct.Struct("<8s5I")
N7_RECEIPT_BYTES = 1744
MAX_STATEMENT_BYTES = 64 * 1024
MAX_C_PACKET_BYTES = 262_144
MAX_EQUALITY_PROOF_BYTES = 1024 * 1024
STATEMENT_KEYS = {
    "bridge_context",
    "c_input_nullifiers",
    "transient_c_outputs",
    "successor_outputs",
}


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def statement_bytes(statement):
    need(type(statement) is dict and set(statement) == STATEMENT_KEYS, "bridge statement keys")
    return json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def parse_statement(raw):
    need(0 < len(raw) <= MAX_STATEMENT_BYTES, "bridge statement length")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("bridge statement encoding") from error
    need(statement_bytes(value) == raw, "noncanonical bridge statement")
    return value


@dataclass(frozen=True)
class BridgeBundle:
    statement: dict
    c_packet: bytes
    equality_proof: bytes
    successor_receipts: tuple[bytes, bytes]

    def encode(self):
        public = statement_bytes(self.statement)
        need(0 < len(public) <= MAX_STATEMENT_BYTES, "bridge statement length")
        need(0 < len(self.c_packet) <= MAX_C_PACKET_BYTES, "C packet length")
        need(0 < len(self.equality_proof) <= MAX_EQUALITY_PROOF_BYTES, "equality proof length")
        need(
            len(self.successor_receipts) == 2
            and all(len(receipt) == N7_RECEIPT_BYTES for receipt in self.successor_receipts),
            "N7 receipt length",
        )
        pieces = (public, self.c_packet, self.equality_proof, *self.successor_receipts)
        return HEADER.pack(MAGIC, *(len(piece) for piece in pieces)) + b"".join(pieces)

    def identity(self):
        return sha3_384(b"C2N7/bundle-id/v1\0" + self.encode()).digest()

    def component_sizes(self):
        public = statement_bytes(self.statement)
        return {
            "framing": HEADER.size,
            "statement": len(public),
            "c_packet_including_c_receipts": len(self.c_packet),
            "equality_proof": len(self.equality_proof),
            "successor_receipts": sum(map(len, self.successor_receipts)),
            "canonical_bundle": len(self.encode()),
            # Two (offset,length) u32 pairs suffice as a derived C-receipt index.
            "derived_c_receipt_index": 16,
        }

    @classmethod
    def decode(cls, raw):
        need(type(raw) is bytes and len(raw) >= HEADER.size, "bridge bundle length")
        magic, *sizes = HEADER.unpack_from(raw)
        need(magic == MAGIC, "bridge bundle magic")
        need(sum(sizes) == len(raw) - HEADER.size, "bridge bundle framing")
        offset = HEADER.size
        pieces = []
        for size in sizes:
            pieces.append(raw[offset:offset + size])
            offset += size
        value = cls(parse_statement(pieces[0]), pieces[1], pieces[2], (pieces[3], pieces[4]))
        need(value.encode() == raw, "noncanonical bridge bundle")
        return value
