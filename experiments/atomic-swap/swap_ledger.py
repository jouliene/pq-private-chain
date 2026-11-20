"""Atomic admission of a complete two-owner group on the existing AST1/MNG1 branch."""
from hashlib import sha256
from pathlib import Path

from managed_ledger import ManagedSlot
from managed_ops import packet_width
from swap_wire import BUNDLE, FRAME, bundle, digest, groups, pair, read_frame, split
from wire import CT, ZERO, Role, canonical, need, pieces

DEV = Path(__file__).resolve().parent
ROOT = DEV.parent


def public_role():
    binary = ROOT/"swap-runtime/native"
    keys = ROOT/"swap-keys"
    approved = (DEV/"approved-swap-native.sha256").read_text().strip()
    vk = keys/"swap.vk"
    need(not keys.is_symlink() and set(keys.iterdir()) == {vk} and not vk.is_symlink() and
         vk.read_bytes() == (DEV/"swap.vk").read_bytes(), "unapproved swap key")
    return Role(binary,approved,["verify","/keys"],keys)


def physical_width(raw):
    if raw.startswith(FRAME):
        read_frame(raw)
        return 1
    return packet_width(raw)


def logical(packets):
    for group in groups(packets):
        yield group[0] if len(group)==1 else bundle(group)


def read_leg(verifier, leg):
    raw = verifier.call(leg)
    need(len(raw)==1+172+2*CT+32 and raw[:1]==b"1", "invalid swap leg proof")
    row = raw[1:]
    anchor = row[:32]
    nfs, cms = tuple(pieces(row[36:100],32)),tuple(pieces(row[100:164],32))
    cts = tuple(pieces(row[172:-32],CT))
    fee = int.from_bytes(row[164:172],"little")
    need(all(canonical(w) for w in (anchor,*nfs,*cms)) and ZERO not in cms
         and fee in (0,3) and b"".join(cts)==leg[-2*CT:], "invalid swap proof effects")
    return anchor,int.from_bytes(row[32:36],"little"),nfs,cms,fee,cts,row[-32:]


def verify_pair(frames, verifier, network, height):
    parts = pair(frames)
    a = parts[0]
    need(a.network==network,"wrong swap network")
    need(height <= a.expiry,"swap expired")
    statement = digest(network,a.terms,a.expiry,a.payer,tuple(p.leg for p in parts))
    result, keys = [], []
    for i, p in enumerate(parts):
        anchor,h,nfs,cms,fee,cts,key = read_leg(verifier,p.leg)
        need(fee==(3 if i==a.payer else 0),"swap fee payer")
        need(verifier.call(b"V"+key+statement+p.signature)==b"1","invalid swap authorization")
        keys.append(key)
        result.append(ManagedSlot(anchor,h,nfs,cms,fee,cts,ZERO,0,"swap",b"",0,ZERO,sha256(frames[i]).digest()))
    need(keys[0]!=keys[1],"duplicate swap authority")
    for attr in ("nfs","cms"):
        need(len({x for s in result for x in getattr(s,attr)})==4,"duplicate public effect")
    return result


class SwapSupport:
    def setup_swap_tables(self):
        self.db.execute("CREATE TABLE IF NOT EXISTS swap_pool(id BLOB PRIMARY KEY, a BLOB UNIQUE REFERENCES pool(tx) ON DELETE CASCADE,b BLOB UNIQUE REFERENCES pool(tx) ON DELETE CASCADE) WITHOUT ROWID")
        self.db.execute("CREATE TABLE IF NOT EXISTS swap_archive(id BLOB,bid BLOB REFERENCES blocks(id),idx INTEGER,PRIMARY KEY(id,bid)) WITHOUT ROWID")

    def swap_verifier(self):
        if self._swap_verifier is None:
            self._swap_verifier = public_role()
        return self._swap_verifier

    def close(self):
        try:
            super().close()
        finally:
            if self._swap_verifier is not None:
                self._swap_verifier.abort()

    def group_effects(self,packets,head):
        from chain import NETWORK
        for group in groups(packets):
            if len(group)==1:
                yield self._effects(group[0],head)
                continue
            for slot in verify_pair(group,self.swap_verifier(),NETWORK,head["h"]+1):
                self.check_funding(slot,head)
                yield slot

    def _enqueue(self,packet,head):
        from chain import MAX_PENDING
        if not packet.startswith(BUNDLE):
            need(not packet.startswith(FRAME),"incomplete atomic swap")
            return super()._enqueue(packet,head)
        frames = split(packet)
        gid = sha256(packet).digest()
        if self.db.execute("SELECT 1 FROM swap_pool WHERE id=?",(gid,)).fetchone():
            return gid,True
        need(self.db.execute("SELECT count(*) FROM pool").fetchone()[0]+2<=MAX_PENDING,"pool full")
        slots = list(self.group_effects(frames,head))
        txids = [sha256(f).digest() for f in frames]
        # Refresh can catch a conflict and continue its enclosing reorg transaction.
        # Roll back the first row even when only the second leg conflicts.
        self.db.execute("SAVEPOINT swap_offer")
        try:
            for slot,frame,txid in zip(slots,frames,txids,strict=True):
                self.insert_pool_slot(txid,frame,slot)
            self.db.execute("INSERT INTO swap_pool VALUES(?,?,?)",(gid,*txids))
        except BaseException:
            self.db.execute("ROLLBACK TO swap_offer")
            raise
        finally:
            self.db.execute("RELEASE swap_offer")
        return gid,False

    def pending(self):
        with self._transaction():
            rows=self.db.execute("SELECT coalesce(g.id,p.tx) FROM pool p LEFT JOIN swap_pool g ON g.a=p.tx "
                                 "WHERE NOT EXISTS(SELECT 1 FROM swap_pool q WHERE q.b=p.tx) ORDER BY seq")
            return [r[0].hex() for r in rows]

    def tx(self,txid):
        from chain import decode_block
        with self._transaction():
            row=self.db.execute("SELECT p.packet,q.packet FROM swap_pool g JOIN pool p ON p.tx=g.a "
                                "JOIN pool q ON q.tx=g.b WHERE g.id=?",(txid,)).fetchone()
            if row:
                return bundle(row)
            row=self.db.execute("SELECT raw,idx FROM swap_archive JOIN sel ON sel.id=bid JOIN blocks ON blocks.id=bid "
                                "WHERE swap_archive.id=? LIMIT 1",(txid,)).fetchone()
            if row:
                frames=decode_block(row[0]).packets[row[1]:row[1]+2]
                return bundle(frames)
        return super().tx(txid)

    def template(self,pk,packets=None):
        from chain import MAX_TX
        with self._transaction():
            if packets is None:
                packets=[r[0] for r in self.db.execute("SELECT packet FROM pool ORDER BY seq LIMIT ?",(MAX_TX,))]
                # A pair waiting behind three ordinary slots stays intact for the next block.
                if packets and packets[-1].startswith(FRAME) and read_frame(packets[-1]).side==0:
                    packets.pop()
            return self._candidate(self._head(),pk,packets)[0]

    def _persist(self,data,txids,wallet_record):
        from chain import decode_block
        super()._persist(data,txids,wallet_record)
        pos=0
        for g in groups(decode_block(data[-1]).packets):
            if len(g)==2:
                self.db.execute("INSERT INTO swap_archive VALUES(?,?,?)",(sha256(bundle(g)).digest(),data[0],pos))
            pos+=len(g)
