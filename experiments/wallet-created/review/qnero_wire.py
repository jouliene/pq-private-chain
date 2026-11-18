"""Independent accounting of the pinned Qnero wallet's public SCALE submission."""

import argparse
import hashlib
import json
import struct
from pathlib import Path


FIELD = 2**64 - 2**32 + 1
LEAF_WORDS = 21
BATCH_WORDS = 5 + 6 * LEAF_WORDS
PADDING_HEADER = (0x2A7010A968E4B434, 0x2EEDA5104A12C6E5, 0xBBA8FA909E36EA2E, 0x6992931530E84452)


class Cursor:
    def __init__(self, data):
        self.raw = data
        self.index = 0

    def take(self, count):
        end = self.index + count
        if end > len(self.raw):
            raise ValueError("truncated SCALE data")
        data = self.raw[self.index:end]
        self.index = end
        return data

    def compact(self):
        first = self.take(1)[0]
        mode = first & 3
        if mode == 3:
            raise ValueError("oversized length in reviewed submission")
        width = 1 << mode
        value = int.from_bytes(bytes((first,)) + self.take(width - 1), "little") >> 2
        if (mode == 1 and value < 64) or (mode == 2 and value < 16384):
            raise ValueError("noncanonical SCALE compact length")
        return value


def proof_slots(proof, private):
    size = BATCH_WORDS if private else 4 + 53 * BATCH_WORDS
    tail = proof[-8 * (1 + size):]
    if len(tail) != 8 * (1 + size) or int.from_bytes(tail[:8], "little") != size:
        raise ValueError("unexpected public-input vector width")
    inputs = struct.unpack(f"<{size}Q", tail[8:])
    if any(x >= FIELD for x in inputs):
        raise ValueError("noncanonical public field element")
    slots = []
    start = 0 if private else 4
    for j in range(1 if private else 53):
        base = start + j * BATCH_WORDS
        if inputs[base:base + 4] == PADDING_HEADER:
            continue
        for k in range(6):
            head = base + 5 + k * LEAF_WORDS
            slot = inputs[head:head + LEAF_WORDS]
            if any(slot[8:16]):
                slots.append((j, k, slot))
    return slots


def parse(raw):
    cur = Cursor(raw)
    body_length = cur.compact()
    if body_length != len(raw) - cur.index or cur.take(2) != bytes([4, 24]):
        raise ValueError("unexpected bare Qnero extrinsic")
    call = cur.take(1)[0]
    if call not in (0, 1):
        raise ValueError("unsupported call")
    proof = cur.take(cur.compact())
    slots = proof_slots(proof, call == 0)
    if cur.compact() != len(slots):
        raise ValueError("proof slot and ciphertext-pair count disagree")
    cts = []
    for _ in slots:
        pair = [cur.take(cur.compact()) for _ in range(2)]
        if any(len(c) != 1792 for c in pair):
            raise ValueError("expected two suite-1 settled ciphertexts")
        cts.append(pair)
    if cur.index != len(raw):
        raise ValueError("trailing extrinsic bytes")
    payload = sum(len(c) for pair in cts for c in pair)
    return {
        "call": "submit_private_batch" if call == 0 else "submit_public_batch",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "extrinsic_bytes": len(raw),
        "serialized_proof_bytes": len(proof),
        "public_input_felts_in_proof": BATCH_WORDS if call == 0 else 4 + 53 * BATCH_WORDS,
        "real_slots": [[j, k] for j, k, _ in slots],
        "public_fees_steps": [slot[16] for _, _, slot in slots],
        "ciphertext_bytes": payload,
        "scale_framing_bytes": len(raw) - len(proof) - payload,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("public_extrinsic", type=Path)
    args = parser.parse_args()
    print(json.dumps(parse(args.public_extrinsic.read_bytes()), indent=2, sort_keys=True))
