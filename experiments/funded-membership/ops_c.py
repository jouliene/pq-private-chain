"""Dispatch admitted managed envelopes and issuer messages by exact registered version."""
import managed_ops_ab as ab
import managed_ops_c as c
from managed_ops_ab import (B_MAGIC, B_INNER, BURN, Envelope, INNER, LIMIT, MAGIC,
                            OPERATIONS, SIGNED, ZERO, managed_id, require, tag)


def authorization_digest(inner, operation, network, public_key, sequence, previous):
    rules = c if inner.startswith(c.INNER) else ab
    return rules.authorization_digest(inner, operation, network, public_key, sequence, previous)


def wrap(inner, operation, network, **authority):
    return (c if inner.startswith(c.INNER) else ab).wrap(inner, operation, network, **authority)


def parse(raw):
    return (c if raw.startswith(c.MAGIC) else ab).parse(raw)


def check_inner(inner):
    (c if inner.startswith(c.INNER) else ab).check_inner(inner)


def packet_width(raw):
    return (c if raw.startswith(c.MAGIC) else ab).packet_width(raw)
