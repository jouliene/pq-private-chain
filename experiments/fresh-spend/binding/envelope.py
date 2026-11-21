"""Canonical reference encoders. Admission must verify proofs under a registered backend."""
from dataclasses import dataclass
from relation import fixed, h, le, need

RECEIPT = 1792
SIGNATURE = 29792


@dataclass(frozen=True)
class Body:
    backend: int
    role: int
    anchor: bytes
    fee: int
    nfs: tuple
    cms: tuple
    receipts: tuple
    terms: bytes = b""
    ephemeral: bytes = b""
    expiry: int = 0

    def prefix(self):
        need(self.backend in (1, 2) and self.role in (0, 1, 2), "unregistered body")
        need(len(self.nfs) == len(self.cms) == len(self.receipts) == 2, "fixed arity")
        return (b"FS01" + le(self.backend, 1) + le(self.role, 1) + fixed(self.anchor, 64)
                + le(self.fee, 8) + b"".join(fixed(x, 64) for x in (*self.nfs, *self.cms)))

    def extension(self):
        if self.role == 0:
            need((self.terms, self.ephemeral, self.expiry) == (b"", b"", 0), "ordinary extension")
            return b""
        return fixed(self.terms, 64) + fixed(self.ephemeral, 64) + le(self.expiry, 8)

    def tails(self):
        return b"".join(fixed(x, RECEIPT) for x in self.receipts) + self.extension()

    def intent(self, chain, root, count):
        return h("intent", fixed(chain, 64), fixed(root, 64), le(count, 6), self.prefix(), self.tails())

    def core(self, auth, proof):
        need(type(proof) is bytes and len(proof) > 0, "empty proof field")
        return self.prefix() + fixed(auth, 64) + self.tails() + le(len(proof), 8) + proof


def pair_message(chain, core0, core1):
    return h("pair", fixed(chain, 64), le(len(core0), 8), core0, le(len(core1), 8), core1)


def pair_frame(core0, sig0, core1, sig1):
    leg0, leg1 = core0 + fixed(sig0, SIGNATURE), core1 + fixed(sig1, SIGNATURE)
    return b"FSW1" + le(len(leg0), 8) + le(len(leg1), 8) + leg0 + leg1
