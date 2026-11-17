"""Report byte allocation in the immutable public CP03 2x2 reference body."""
import hashlib
import json
import struct
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[3]
    raw = (root / "fixtures/cp03-reference/payer2x2.body").read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != "8907fff56f7b6418c0752c8160cdbae13e10a0ddb19de884d89e99f924a5abe9":
        raise ValueError("unexpected public reference")

    magic, version, statement, envelope, authorization, reserved = struct.unpack_from(
        "<8sHHIHH", raw
    )
    if (magic, version, statement, authorization, reserved) != (b"CPBODY03", 3, 528, 0, 0):
        raise ValueError("unexpected body header")

    prefix = 20 + statement + 2 * 2164
    if raw[prefix:prefix + 8] != b"CPFRI003" or len(raw) != prefix + envelope:
        raise ValueError("unexpected proof boundary")
    inner = raw[prefix + 206:]
    if len(inner) != int.from_bytes(raw[prefix + 202:prefix + 206], "little"):
        raise ValueError("incorrect proof length")

    # codec::decode, with trusted profile B16/Q160, EF5, 8 chunks, 10 folds.
    # Degree, commitments, OOD claims, helper evaluations, PoW and fold commitments.
    ood_extension_fields = 2 * (579 + 114) + 8 * 5 + 5 + (1 + 2 + 8) * 5
    prelude = 4 + 3 * 64 + 40 * ood_extension_fields + 8 + 10 * (64 + 8)
    offset = prelude
    batches = [("random", 10, 8), ("trace", 584, 8), ("quotient", 80, 64),
               ("fixed", 114, 8)] + [(f"fold_{i}", 5, 8) for i in range(10)]
    sections = {}
    for name, value_words, salt_words in batches:
        start = offset
        values = 160 * value_words * 8
        salts = 160 * salt_words * 8
        offset += values + salts
        sibling_bytes = 64 * struct.unpack_from("<I", inner, offset)[0]
        offset += 4 + sibling_bytes
        sections[name] = dict(bytes=offset - start, values=values, salts=salts,
                              count=4, siblings=sibling_bytes)
    tail = 40 + 2 * 8
    if offset + tail != len(inner):
        raise ValueError("sections do not partition the actual proof")
    print(json.dumps(dict(fixture_sha256=digest, body=len(raw), body_prefix=prefix,
                          envelope=envelope, envelope_header=206, prelude=prelude,
                          sections=sections, tail=tail), indent=2))


if __name__ == "__main__":
    main()
