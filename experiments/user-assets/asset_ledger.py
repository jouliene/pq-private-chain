"""Public AST1 effects and the active branch's one-time issuance registry."""
from dataclasses import dataclass
from hashlib import sha256
import struct

from state import PublicBackend, Slot
from wire import CT, ZERO, canonical, need, packet_width, pieces, u64


def issue_id(network, nullifier):
    raw = sha256(b"AST1/issue-id/v1\0" + network + nullifier).digest()
    return b"".join(u64(x & ((1 << 63)-1)) for x in struct.unpack("<4Q",raw))


def public_transition(nfs, cms, fee, issue_id, supply):
    return b"".join((*nfs, *cms, u64(fee), issue_id, u64(supply)))


@dataclass(frozen=True)
class AssetSlot(Slot):
    issue_id: bytes
    supply: int

    def transition(self):
        return public_transition(self.nfs, self.cms, self.fee, self.issue_id, self.supply)


class AssetBackend(PublicBackend):
    def verify(self, packet):
        need(packet_width(packet) == 1, "AST1 singleton required")
        reply = self.verifier.call(packet)
        need(len(reply) == 1 + 172 + 2*CT + 40 and reply[:1] == b"1", "cryptographic payment rejection")
        row = reply[1:]
        slot = AssetSlot(row[:32],int.from_bytes(row[32:36],"little"),tuple(pieces(row[36:100],32)),
                         tuple(pieces(row[100:164],32)),int.from_bytes(row[164:172],"little"),
                         tuple(pieces(row[172:-40],CT)),row[-40:-8],int.from_bytes(row[-8:],"little"))
        need(all(canonical(x) for x in (slot.anchor,*slot.nfs,*slot.cms,slot.issue_id)), "verified effect encoding")
        need(all(x != ZERO for x in slot.cms) and 0 < slot.fee < 2**62, "verified effect bounds")
        need(slot.supply < 2**62 and bool(slot.supply) == (slot.issue_id != ZERO), "issuance descriptor")
        need(b"".join(slot.cts) == packet[-2*CT:], "ordered receipt sidecars")
        return [slot]


class AssetRegistry:
    def check_issuance(self, slot, network):
        if slot.supply:
            need(slot.issue_id == issue_id(network,slot.nfs[0]), "issuance identity")
            need(not self.db.execute("SELECT 1 FROM assets WHERE id=?", (slot.issue_id,)).fetchone(),
                 "asset already issued")

    def public_assets(self, after, limit, tip):
        """Seek through a fixed selected tip's public issuance descriptors, independently of wallet holdings."""
        with self._transaction():
            head = self._head()["id"].hex()
            need(tip == head, "registry tip changed")
            rows = self.db.execute("SELECT id,supply,h,tx FROM assets WHERE id>? ORDER BY id LIMIT ?",
                                   (after,limit+1)).fetchall()
            return dict(tip=head, entries=[dict(id=r[0].hex(),supply=r[1],height=r[2],tx=r[3].hex()) for r in rows[:limit]],
                        next=rows[limit-1][0].hex() if len(rows)>limit else None)
