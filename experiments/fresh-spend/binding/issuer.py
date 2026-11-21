"""Public fixed-supply registration encoding, validator-side consistency checks before signature."""
from dataclasses import dataclass
from relation import Note, ZERO, credit_occ, fixed, funding_asset, h, le, need


@dataclass(frozen=True)
class Issue:
    issuer_pk: bytes
    nonce: bytes
    cap: int
    note: Note
    receipt: bytes

    def public_fields(self, chain):
        aid = funding_asset(chain, self.issuer_pk, self.nonce, self.cap)
        need(aid != ZERO and self.cap > 0, "fixed supply")
        need(self.note.native == 0 and self.note.asset == aid and self.note.qty == self.cap,
             "public issue opening")
        core = (b"FSI1" + fixed(self.issuer_pk,64) + fixed(self.nonce,64) + le(self.cap,8)
                + self.note.encode() + fixed(self.receipt,1792))
        message = h("issue_body", fixed(chain,64), core)
        fid = h("funding_id", chain, b"\x01", aid)
        return aid, message, credit_occ(chain,fid,0), self.note.cm(chain)


class Funding:
    """Genesis-and-fixed-issue state prefix, with a pinned SLH-DSA public verifier."""
    def __init__(self, chain, genesis):
        self.chain = fixed(chain,64)
        self.supplies = {}
        self.entries = []
        self.native = 0
        for serial, note in enumerate(genesis):
            need(note.qty == 0 and note.asset == ZERO and note.native > 0, "native genesis")
            fid = h("funding_id", chain, b"\x00", le(serial,8))
            self.entries.append((credit_occ(chain,fid,0),note.cm(chain)))
            self.native += note.native
        need(self.native < 1 << 128, "native supply")

    def register(self, issue, sig):
        import os
        from pathlib import Path
        import subprocess
        aid, message, occ, cm = issue.public_fields(self.chain)
        need(aid not in self.supplies, "already registered")
        result = subprocess.run([os.environ.get("FS_RECEIPT_NODE","node"),Path(__file__).with_name("approval.mjs"),
                                 "verify"],input=message+issue.issuer_pk+fixed(sig,29792),
                                stdout=subprocess.PIPE,check=True)
        need(result.stdout == b"\1", "issuer authorization")
        self.entries, self.supplies = ([*self.entries, (occ,cm)], {**self.supplies, aid:issue.cap})
