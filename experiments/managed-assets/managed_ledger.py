"""Managed proof effects, immutable policy and selected-chain supply event log."""
from dataclasses import dataclass
from hashlib import sha256

from asset_ledger import AssetBackend, issue_id
from managed_ops import BURN, LIMIT, SIGNED, authorization_digest, managed_id, parse
from state import PublicBackend, Slot
from wire import CT, ZERO, canonical, need, pieces, u64


def public_transition(nfs, cms, fee, issue_id, supply, envelope_digest):
    return b"".join((*nfs,*cms,u64(fee),issue_id,u64(supply),envelope_digest))


@dataclass(frozen=True)
class ManagedSlot(Slot):
    issue_id: bytes
    supply: int
    operation: str
    public_key: bytes
    sequence: int
    previous: bytes
    envelope_digest: bytes

    def transition(self):
        return public_transition(self.nfs,self.cms,self.fee,self.issue_id,self.supply,self.envelope_digest)


class ManagedBackend(PublicBackend):
    def verify(self, packet):
        from chain import NETWORK
        if packet.startswith(b"AST1\x01"):
            old, = AssetBackend.verify(self,packet)
            return [ManagedSlot(old.anchor,old.height,old.nfs,old.cms,old.fee,old.cts,old.issue_id,old.supply,
                                "fixed" if old.supply else "transfer",b"",0,ZERO,b"")]
        env = parse(packet)
        reply = self.verifier.call(env.inner)
        need(len(reply)==1+172+2*CT+40 and reply[:1]==b"1", "cryptographic payment rejection")
        row = reply[1:]
        s = ManagedSlot(row[:32],int.from_bytes(row[32:36],"little"),tuple(pieces(row[36:100],32)),
                        tuple(pieces(row[100:164],32)),int.from_bytes(row[164:172],"little"),
                        tuple(pieces(row[172:-40],CT)),row[-40:-8],int.from_bytes(row[-8:],"little"),
                        env.operation,env.public_key,env.sequence,env.previous,sha256(packet).digest())
        need(all(canonical(x) for x in (s.anchor,*s.nfs,*s.cms,s.issue_id)) and ZERO not in s.cms
             and s.fee==3 and b"".join(s.cts)==env.inner[-2*CT:], "verified effect encoding")
        need((s.issue_id==ZERO)==(s.supply==0) and s.supply<2*BURN and s.supply!=BURN, "supply descriptor")
        if env.operation=="transfer":
            need(not s.supply, "operation mismatch")
        else:
            need(s.supply and (s.supply>=BURN)==(env.operation=="burn"), "operation mismatch")
        if env.operation in SIGNED:
            digest = authorization_digest(env.inner,env.operation,NETWORK,env.public_key,env.sequence,env.previous)
            need(self.verifier.call(b"V"+env.public_key+digest+env.signature)==b"1", "invalid issuer signature")
        return [s]


class SupplyRegistry:
    def latest_asset(self, aid):
        return self.db.execute("SELECT * FROM assets WHERE id=? ORDER BY sequence DESC LIMIT 1",(aid,)).fetchone()

    def check_issuance(self, slot, network):
        if not slot.supply:
            return
        old = self.latest_asset(slot.issue_id)
        if slot.operation in ("register","fixed"):
            expected = (managed_id(network,slot.public_key,slot.nfs[0]) if slot.operation=="register"
                        else issue_id(network,slot.nfs[0]))
            need(slot.issue_id==expected, "issuance identity")
            need(old is None, "asset already registered")
            need(slot.sequence==0 and slot.previous==ZERO, "registration state")
            return
        need(old is not None, "unregistered asset")
        need(old["mode"]=="managed", "immutable fixed supply")
        if slot.operation=="mint":
            need(old["authority"]==slot.public_key, "wrong issuer authority")
            need(old["sequence"]==slot.sequence and old["tx"]==slot.previous, "stale issuer state")
            need(old["supply"]+slot.supply<=LIMIT, "outstanding supply overflow")
        else:
            need(old["supply"]>=slot.supply-BURN, "outstanding supply underflow")

    def record_event(self, slot, height, tx):
        old = self.latest_asset(slot.issue_id)
        mode = old["mode"] if old else ("fixed" if slot.operation=="fixed" else "managed")
        key = old["authority"] if old else slot.public_key
        sequence = old["sequence"]+1 if old else 1
        net = (old["supply"] if old else 0)+(BURN-slot.supply if slot.operation=="burn" else slot.supply)
        self.db.execute("INSERT INTO assets VALUES(?,?,?,?,?,?,?)",(slot.issue_id,sequence,mode,key,net,height,tx))

    def public_assets(self, after, limit, tip):
        with self._transaction():
            h = self.db.execute("SELECT h FROM sel WHERE id=?",(bytes.fromhex(tip),)).fetchone()
            need(h is not None, "registry tip changed")
            rows = self.db.execute("SELECT a.* FROM assets a WHERE a.id>? AND a.h<=? AND a.sequence="
                                   "(SELECT max(b.sequence) FROM assets b WHERE b.id=a.id AND b.h<=?) "
                                   "ORDER BY a.id LIMIT ?",(after,h[0],h[0],limit+1)).fetchall()
            return dict(tip=tip,entries=[dict(id=r["id"].hex(),mode=r["mode"],authority=r["authority"].hex(),
                                              sequence=r["sequence"],supply=r["supply"],height=r["h"],tx=r["tx"].hex())
                                        for r in rows[:limit]],
                        next=rows[limit-1]["id"].hex() if len(rows)>limit else None)

    def supply_observation(self, txids):
        """Observe selected burns and confirming work in one database snapshot."""
        with self._transaction():
            head = self._head()
            rows = []
            for tx in txids:
                from chain import decode_block
                hit = self.db.execute("SELECT b.id,b.raw,l.idx,s.h FROM txloc l JOIN sel s ON s.id=l.bid "
                                      "JOIN blocks b ON b.id=l.bid WHERE l.tx=?",(tx,)).fetchone()
                if hit is None:
                    rows.append(None)
                    continue
                packet = decode_block(hit["raw"]).packets[hit["idx"]]
                need(sha256(packet).digest()==tx,"selected packet identity")
                slot, = self.backend.verify(packet)
                rows.append(dict(tx=tx.hex(),asset=slot.issue_id.hex(),op=slot.operation,
                                 quantity=slot.supply & LIMIT,nfs=[v.hex() for v in slot.nfs],height=hit["h"],
                                 block=hit["id"].hex(),confirmations=head["h"]-hit["h"]+1))
            return dict(height=head["h"],tip=head["id"].hex(),events=rows)
