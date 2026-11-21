"""Dispatch funded transfer envelopes by their exact registered outer and inner tags."""
from managed_ops_a import (BURN, Envelope, INNER, LIMIT, MAGIC, OPERATIONS, SIGNED, ZERO,
                           authorization_digest, managed_id, require, tag)
import managed_ops_a as legacy

B_MAGIC = b"MSP2\x01"
B_INNER = b"MNG2\x01"


def check_b(inner):
    require(inner.startswith(B_INNER) and len(inner) <= 262144 - 6, "B transfer encoding")
    size = int.from_bytes(inner[5:9], "little")
    require(size > 0 and len(inner) == 9 + size + 3584, "B transfer size")


def check_inner(inner):
    if inner.startswith(B_INNER):
        check_b(inner)
    else:
        legacy.check_inner(inner)


def wrap(inner, operation, network, *, public_key=b"", sequence=0, previous=ZERO, sign=None):
    if inner.startswith(B_INNER):
        check_b(inner)
        require(operation == "transfer" and not public_key and sequence == 0 and previous == ZERO
                and sign is None, "B is transfer only")
        return B_MAGIC + b"\0" + inner
    return legacy.wrap(inner, operation, network, public_key=public_key, sequence=sequence,
                       previous=previous, sign=sign)


def parse(raw):
    if raw.startswith(B_MAGIC):
        require(raw[5:6] == b"\0", "B is transfer only")
        check_b(raw[6:])
        return Envelope("transfer", b"", 0, ZERO, b"", raw[6:])
    return legacy.parse(raw)


def packet_width(raw):
    if raw.startswith(B_MAGIC):
        parse(raw)
        return 1
    return legacy.packet_width(raw)
