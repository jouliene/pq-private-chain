"""Count hash work in the public reference verifier's binary opening trees."""

import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = {
    "payer2x2": "8907fff56f7b6418c0752c8160cdbae13e10a0ddb19de884d89e99f924a5abe9",
    "nf-alternate": "c3d2e1df725c809a9c984dd56d1a83e7b1a5631e66a0d6b6b4de4b1463cd9ff3",
}
QUERIES = 160


def sha3_permutations(tag, payload_bytes):
    """SHA3-512 rate is 72 bytes. The length field precedes sponge padding."""
    return (len(tag) + payload_bytes + 8) // 72 + 1


def read_trees(raw):
    offset = 20 + 528 + 2 * 2164
    assert raw[:8] == b"CPBODY03" and raw[offset:offset + 8] == b"CPFRI003"
    assert len(raw) - offset == struct.unpack_from("<I", raw, 12)[0]
    assert len(raw) - offset - 206 == struct.unpack_from("<I", raw, offset + 202)[0]
    offset += 206
    # Roots, standard OOD openings, helper openings and fold commitments.
    ood_scalars = 2 * (579 + 114) + (8 + 1) * 5 + (1 + 2 + 8) * 5
    offset += 4 + 3 * 64 + ood_scalars * 40 + 8 + 10 * (64 + 8)

    # (tree name, transmitted base words, salt words, actual leaf data words).
    # Quotient chunks have equal height. Each FRI leaf holds both EF5 children,
    # one computed and one transmitted. Distinct salts suffice to certify a
    # lower bound on positions even if distinct positions shared a salt.
    layout = [("random", 10, 8, 10), ("trace", 584, 8, 584),
              ("quotient", 80, 64, 80), ("fixed", 114, 8, 114)]
    layout.extend((f"fold{i}", 5, 8, 10) for i in range(10))
    node_work = sha3_permutations(b"PQPC/CP-FRI/01/NODE\x00", 128)
    for name, wire_words, salt_words, leaf_words in layout:
        offset += QUERIES * wire_words * 8
        stride = salt_words * 8
        salt_end = offset + QUERIES * stride
        leaves = len({raw[i:i + stride] for i in range(offset, salt_end, stride)})
        frontier, = struct.unpack_from("<I", raw, salt_end)
        offset = salt_end + 4 + frontier * 64
        # A full binary reconstruction tree with L + S inputs has L + S - 1
        # binary nodes. The verifier shares parents of repeated query paths.
        leaf_work = sha3_permutations(b"PQPC/CP-FRI/01/LEAF\x00", (leaf_words + salt_words) * 8)
        yield name, leaves * leaf_work + (leaves + frontier - 1) * node_work

    assert offset + 40 + 2 * 8 == len(raw)


if __name__ == "__main__":
    print("fixture random trace quotient folds fixed nonfixed all")
    for name, expected_hash in FIXTURES.items():
        data = (ROOT / "fixtures" / "cp03-reference" / f"{name}.body").read_bytes()
        assert hashlib.sha256(data).hexdigest() == expected_hash
        counts = dict(read_trees(data))
        fold_total = sum(v for k, v in counts.items() if k.startswith("fold"))
        total = sum(counts.values())
        print(name, counts["random"], counts["trace"], counts["quotient"], fold_total,
              counts["fixed"], total - counts["fixed"], total)
