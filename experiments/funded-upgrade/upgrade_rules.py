"""Candidate-height selection for two locally registered funded proof suites."""
from pathlib import Path
from types import SimpleNamespace

from managed_ledger import ManagedBackend
from managed_ops import B_MAGIC
from swap_wire import b as swap_b
from wire import Role, need

DEV = Path(__file__).resolve().parent
FIRST_B = 13
FIRST_B_ONLY = 15


def b_role(kind):
    need(kind in ("managed", "swap"), "unknown B role")
    prefix = "b-" if kind == "managed" else "b-swap-"
    key = kind + ".vk"
    runtime = DEV.parent / (prefix + "runtime")
    keys = DEV.parent / (prefix + "keys")
    vk = keys / key
    need(not keys.is_symlink() and set(keys.iterdir()) == {vk} and not vk.is_symlink()
         and vk.read_bytes() == (DEV / ("b-" + key)).read_bytes(), "unapproved B key")
    binary = runtime / "native"
    need(not runtime.is_symlink() and not binary.is_symlink(), "unapproved B executable")
    identity = (DEV / ("approved-" + prefix + "native.sha256")).read_text().strip()
    return Role(binary, identity, ["verify", "/keys"], keys)


def permitted(is_b, height):
    need(FIRST_B <= height if is_b else height < FIRST_B_ONLY, "inactive proof suite")


class UpgradeSupport:
    def __init__(self, *args, **kwargs):
        self._b_roles = {}
        try:
            super().__init__(*args, **kwargs)
        except BaseException:
            for role in self._b_roles.values():
                role.abort()
            if getattr(self, "_swap_verifier", None) is not None:
                self._swap_verifier.abort()
            raise

    def setup_swap_tables(self):
        super().setup_swap_tables()
        # An old process can have indexed blocks at or beyond the cutover
        # under different rules. Never treat a preexisting database verdict as
        # an upgraded verification result. Recheck all unmarked branches
        # against their archived heights before exposing the database.
        self.db.execute("CREATE TABLE IF NOT EXISTS funded_upgrade_blocks("
                        "id BLOB PRIMARY KEY REFERENCES blocks(id)) WITHOUT ROWID")
        from chain import decode_block
        from swap_wire import groups
        unknown = self.db.execute("SELECT b.id,b.h,b.raw FROM blocks b WHERE b.h>=? AND NOT EXISTS "
                                  "(SELECT 1 FROM funded_upgrade_blocks v WHERE v.id=b.id) ORDER BY b.h",
                                  (FIRST_B,))
        for bid, height, raw in unknown:
            block = decode_block(raw)
            need(block.height == height, "archived block height")
            for group in groups(block.packets):
                if len(group) == 1:
                    self.verify_single(group[0], height)
                else:
                    self.verify_swap(group, height)
            self.db.execute("INSERT INTO funded_upgrade_blocks VALUES(?)", (bid,))
        if self.db.execute("SELECT 1 FROM pool LIMIT 1").fetchone():
            self._refresh([], set())

    def _persist(self, data, txids, wallet_record):
        super()._persist(data, txids, wallet_record)
        if data[2] >= FIRST_B:
            self.db.execute("INSERT INTO funded_upgrade_blocks VALUES(?)", (data[0],))

    def b_verifier(self, kind):
        if kind not in self._b_roles:
            self._b_roles[kind] = b_role(kind)
        return self._b_roles[kind]

    def verify_single(self, packet, height):
        if packet.startswith(B_MAGIC):
            permitted(True, height)
            backend = SimpleNamespace(verifier=self.b_verifier("managed"))
            return ManagedBackend.verify(backend, packet)
        slots = self.backend.verify(packet)
        # A nonzero authenticated delta alone enters the original issuance
        # exception. Both AST1 and MSP1 ordinary proofs have a zero delta.
        if not slots[0].supply:
            permitted(False, height)
        return slots

    def verify_swap(self, group, height):
        from chain import NETWORK
        from swap_ledger import verify_pair
        is_b = group[0].startswith(swap_b.FRAME)
        permitted(is_b, height)
        role = self.b_verifier("swap") if is_b else self.swap_verifier()
        return verify_pair(group, role, NETWORK, height)

    def close(self):
        try:
            super().close()
        finally:
            for role in self._b_roles.values():
                role.abort()
