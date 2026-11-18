"""Compare wallet-created native public submissions to their retained pair packet."""

from pathlib import Path
import argparse
import hashlib
import json
import struct


FIELD = 2**64 - 2**32 + 1
CIPHERTEXT = 1792


def split(path, paired):
    raw = path.read_bytes()
    magic = b"NPA1" if paired else b"NPC1"
    if raw[:4] != magic:
        raise ValueError(f"expected {magic!r}")
    size, = struct.unpack("<I", raw[4:8])
    count = 4 if paired else 2
    if size == 0 or len(raw) != 8 + size + count * CIPHERTEXT:
        raise ValueError("invalid proof or ciphertext framing")
    proof = raw[8:8 + size]
    vector_width = 53 if paired else 26
    suffix = proof[-8 * (vector_width + 1):]
    width, *words = struct.unpack(f"<{vector_width + 1}Q", suffix)
    if width != vector_width or any(v >= FIELD for v in words):
        raise ValueError("invalid public-input suffix")
    return words, raw[8 + size:], {
        "sha256": hashlib.sha256(raw).hexdigest(), "packet_bytes": len(raw),
        "proof_bytes": size, "ciphertext_bytes": count * CIPHERTEXT, "framing_bytes": 8,
    }


def inspect(first, second, outer):
    a, cta, ea = split(first, False)
    b, ctb, eb = split(second, False)
    p, ctp, ep = split(outer, True)
    if p != [0x4e4154503031] + a + b or a[:5] != b[:5]:
        raise ValueError("retained pair public inputs differ from distinct wallet inputs")
    if ctp != cta + ctb:
        raise ValueError("retained ciphertext sidecar differs")
    for offset in (5, 13):
        items = [tuple(row[i:i + 4]) for row in (a, b) for i in (offset, offset + 4)]
        if len(set(items)) != 4 or (0,) * 4 in items:
            raise ValueError("duplicated or zero nullifiers/commitments")
    return {"singles": [ea, eb], "pair": ep, "public_fees": [a[21], b[21]],
            "all_52_inner_public_felts_preserved_in_order": True,
            "all_four_ciphertexts_preserved_in_order": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("wallet_a", "wallet_b", "pair"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.wallet_a, args.wallet_b, args.pair), indent=2))
