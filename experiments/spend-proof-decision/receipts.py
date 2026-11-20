"""Inspect public receipts and field equality in an independently verified, funded swap and respend."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "atomic-swap"))
sys.path.insert(0, str(HERE.parent / "managed-assets"))
import managed_ops
import swap_wire


def expect(condition, description):
    if not condition:
        raise ValueError(description)


def fields(data, magic, width):
    expect(data[:5] == magic, "unrecognized inner profile")
    size, = struct.unpack_from("<I", data, 5)
    end = 9 + size
    expect(len(data) == end + 3584 and size >= 8 * (width + 1), "invalid packet shape")
    count, *words = struct.unpack_from(f"<{width+1}Q", data, end - 8 * (width + 1))
    expect(count == width and all(x < (1 << 64) - (1 << 32) + 1 for x in words), "invalid statement")
    return {
        "anchor": tuple(words[:5]),
        "nf": {tuple(words[start:start+4]) for start in (5, 9)},
        "cm": {tuple(words[start:start+4]) for start in (13, 17)},
        "fee": words[21],
        "receipts": [data[end:end+1792], data[end+1792:]],
        "extra": words[26:],
    }


def receipt(raw):
    header = struct.unpack_from("<BHI", raw)
    offset = 7
    parts = []
    for expected in (1568, 128, 77):
        size, = struct.unpack_from("<I", raw, offset)
        expect(size == expected, "unexpected ciphertext field")
        offset += 4
        parts.append(raw[offset:offset+size])
        offset += size
    expect(offset == len(raw), "receipt size")
    return header, parts


def inspect(ordinary, swap):
    transfer = managed_ops.parse(ordinary)
    expect(transfer.operation == "transfer", "expected ordinary transfer")
    payment = fields(transfer.inner, b"MNG1\x01", 31)
    frames = swap_wire.pair(swap_wire.split(swap))
    legs = [fields(frame.leg, b"SLG1\x01", 34) for frame in frames]
    expect(payment["extra"] == [0] * 5 and sorted(l["fee"] for l in legs) == [0, 3],
           "unexpected economic statements")
    items = [r for statement in [payment, *legs] for r in statement["receipts"]]
    observations = [receipt(r) for r in items]
    cms = legs[0]["cm"] | legs[1]["cm"]
    nfs = legs[0]["nf"] | legs[1]["nf"]
    return {
        "source_sha256": [sha256(body).hexdigest() for body in (ordinary, swap)],
        "ordinary_proof_public_words": 31,
        "ordinary_public_supply_delta_and_id_all_zero": True,
        "swap_leg_public_words_each": 34,
        "swap_public_leg_fees": [leg["fee"] for leg in legs],
        "swap_shared_public_terms_digest": frames[0].terms == frames[1].terms,
        "swap_distinct_public_authorization_keys": legs[0]["extra"] != legs[1]["extra"],
        "swap_visible_positions": ["side 0 counterparty then change", "side 1 counterparty then change"],
        "receipt_count": len(items),
        "distinct_complete_receipts": len(set(items)),
        "distinct_public_version_suite_diversifier": sorted({h for h, _ in observations}),
        "serialized_field_widths_B": [1568, 128, 77],
        "distinct_kem_note_memo_fields": [len({parts[i] for _, parts in observations}) for i in range(3)],
        "ordinary_nullifiers_matching_swap_commitments_by_equality": len(payment["nf"] & cms),
        "ordinary_nullifiers_matching_swap_input_nullifiers_by_equality": len(payment["nf"] & nfs),
        "swap_anchors_equal": legs[0]["anchor"] == legs[1]["anchor"],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("public_directory", type=Path)
    args = parser.parse_args()
    path = args.public_directory
    print(json.dumps(inspect((path/"ordinary.bin").read_bytes(), (path/"swap.bin").read_bytes()),
                     indent=2, sort_keys=True))
