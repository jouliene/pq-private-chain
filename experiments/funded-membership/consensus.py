"""Prospective funded membership rules. All historical A/B blocks keep their original rules."""
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from managed_ledger import ManagedBackend, ManagedSlot
from swap_ledger import verify_pair
from swap_wire import c
from upgrade_rules import UpgradeSupport
from wire import Role, need

DEV = Path(__file__).resolve().parent
FIRST_C = 25


def funded_depth(count):
    need(type(count) is int and 1 <= count <= 4**20, "empty or invalid funded anchor")
    return max(1, ((count-1).bit_length()+1)//2)


def role(kind):
    label = {"managed":"c-", "swap":"c-swap-"}[kind]
    key = kind+".vk"
    keys = DEV.parent/(label+"keys")
    binary = DEV.parent/(label+"runtime")/"native"
    need(not keys.is_symlink() and set(keys.iterdir()) == {keys/key} and not (keys/key).is_symlink()
         and (keys/key).read_bytes() == (DEV/("c-"+key)).read_bytes(), "unapproved C registration")
    need(not binary.is_symlink() and not binary.parent.is_symlink(), "unapproved C runtime")
    pin = (DEV/("approved-"+label+"native.sha256")).read_text().strip()
    return Role(binary, pin, ["verify","/keys"], keys)


@dataclass(frozen=True)
class FundedSlot(ManagedSlot):
    depth: int


class ProvedDepth:
    """Read verified public fields from one submission, then reuse the original effect/approval parsers."""
    def __init__(self, verifier, magic):
        self.verifier = verifier
        self.magic = magic
        self.depths = []

    def call(self, message):
        reply = self.verifier.call(message)
        if message.startswith(self.magic):
            need(reply[:1]==b"1" and len(reply)>1 and 1 <= reply[-1] <= 20, "invalid C proof or depth")
            self.depths.append(reply[-1])
            return reply[:-1]
        need(message[:1] == b"V", "unexpected C verifier request")
        return reply

    def slots(self, rows):
        need(len(self.depths)==len(rows), "verified depth arity")
        return [FundedSlot(**vars(row), depth=d) for row,d in zip(rows,self.depths,strict=True)]


class MembershipSupport(UpgradeSupport):
    def __init__(self,*args,**kwargs):
        self._c_roles = {}
        try:
            super().__init__(*args,**kwargs)
        except BaseException:
            for verifier in self._c_roles.values():
                verifier.abort()
            raise

    def c_verifier(self, kind):
        if kind not in self._c_roles:
            self._c_roles[kind] = role(kind)
        return self._c_roles[kind]

    def setup_swap_tables(self):
        # Old locally validated pre-activation blocks are directly compatible. A
        # post-activation archived verdict from an older binary cannot authorize C state.
        self.db.execute("CREATE TABLE IF NOT EXISTS funded_c_blocks(id BLOB PRIMARY KEY REFERENCES blocks(id)) WITHOUT ROWID")
        missing = self.db.execute("SELECT 1 FROM blocks b WHERE h>=? AND NOT EXISTS "
                                  "(SELECT 1 FROM funded_c_blocks c WHERE c.id=b.id) LIMIT 1",(FIRST_C,)).fetchone()
        need(missing is None, "unverified post-C history: replay original blocks into a fresh database")
        super().setup_swap_tables()

    def _persist(self,data,txids,wallet_record):
        super()._persist(data,txids,wallet_record)
        if data[2] >= FIRST_C:
            self.db.execute("INSERT INTO funded_c_blocks VALUES(?)",(data[0],))

    def verify_single(self,packet,height):
        new = packet.startswith(b"MSP3\x01")
        need(new == (height >= FIRST_C), "inactive proof suite")
        if not new:
            return super().verify_single(packet,height)
        verifier = ProvedDepth(self.c_verifier("managed"), b"MNG3\x01")
        rows = ManagedBackend.verify(SimpleNamespace(verifier=verifier),packet)
        return verifier.slots(rows)

    def verify_swap(self,group,height):
        new = group[0].startswith(c.FRAME)
        need(new == (height >= FIRST_C), "inactive proof suite")
        if not new:
            return super().verify_swap(group,height)
        from chain import NETWORK
        verifier = ProvedDepth(self.c_verifier("swap"),c.LEG)
        return verifier.slots(verify_pair(group,verifier,NETWORK,height))

    def check_funding(self,slot,head):
        super().check_funding(slot,head)
        if isinstance(slot,FundedSlot):
            row = self.db.execute("SELECT n FROM sel JOIN blocks USING(id) WHERE sel.h=? AND ap=?",
                                  (slot.height,slot.anchor)).fetchone()
            need(row is not None and funded_depth(row[0]) == slot.depth, "verified funded depth mismatch")

    def close(self):
        try:
            super().close()
        finally:
            for verifier in self._c_roles.values():
                verifier.abort()
