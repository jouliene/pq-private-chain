"""Resident swap wallet. Its coordinator pipe carries public records, proposals, cores and signatures."""
import json
from pathlib import Path
import os
import secrets
import sys

from packets import SIGNATURE, anchor, digest, helper, pair_frame, pair_message, parse
from funding_fixture import GRANTS, ISSUE_FILES, NOTE, POLICY, issue_record, parse_note
from issuer import Issue
from ledger import Ledger
from native.verify import verify
from relation import FundedTree, ZERO, credit_occ, funding_asset, h, le, need, new_note, spend_key
from wallet import Coin, descriptor, prepare, prove


def unpack(value, size):
    data = bytes.fromhex(value)
    need(len(data)==size,"public message width")
    return data


class Owner:
    def __init__(self, public, slot, enrollment, *, allow_conflict=False):
        self.allow_conflict = allow_conflict and slot==0
        self.enrollment = enrollment
        self.public = public
        self.slot = slot
        self.peer = 1-slot
        self.wave = 0
        self.phase = "new"
        self.node = None

    def initial(self, request):
        need(self.phase=="new","wallet already initialized")
        self.chain = h("chain",unpack(request["nonce"],64),POLICY)
        self.seed = secrets.token_bytes(64)
        self.ask = spend_key(self.chain,self.seed)
        self.desc = descriptor(self.chain,self.seed)
        self.identity = helper("approval.mjs","key",b"")
        self.enrollment.write(b"SWI1"+bytes([self.slot])+self.chain+self.desc+self.identity[:64])
        self.grant = new_note(self.desc[:64],100+self.slot,ZERO,0)
        cap = (99,173)[self.slot]
        issuer = helper("approval.mjs","key",b"")
        pk,nonce = issuer[:64],secrets.token_bytes(64)
        aid = funding_asset(self.chain,pk,nonce,cap)
        self.issued = new_note(self.desc[:64],0,aid,cap)
        fid = h("funding_id",self.chain,b"\x01",aid)
        ctx = self.chain+credit_occ(self.chain,fid,0)+b"\0"+self.issued.cm(self.chain)
        receipt = helper("receipt.mjs","seal",ctx+self.desc+self.issued.encode())
        need(helper("receipt.mjs","open",ctx+self.seed+receipt)==self.issued.encode(),"issued receipt")
        issue = Issue(pk,nonce,cap,self.issued,receipt)
        sig = helper("approval.mjs","sign",issue.public_fields(self.chain)[1]+issuer[64:])
        self.record = issue_record(issue)+sig
        self.phase = "funding"
        return {"descriptor":self.desc.hex(),"grant":self.grant.encode().hex(),"issuance":self.record.hex()}

    def register(self, request):
        need(self.phase=="funding","unexpected funding registration")
        self.pin = unpack(request["pin"],32)
        data = self.enrollment.read(4+1+64+1632+64+1)
        self.enrollment.close()
        need(len(data)==4+1+64+1632+64 and data[:69]==b"SWI1"+bytes([self.peer])+self.chain,
             "incompatible peer enrollment")
        self.peer_desc = data[69:-64]
        self.descriptors = [self.desc,self.peer_desc] if self.slot==0 else [self.peer_desc,self.desc]
        keys = (self.identity[:64],data[-64:])
        self.identities = list(keys if self.slot==0 else reversed(keys))
        need(self.desc[:64]!=self.peer_desc[:64] and self.identities[0]!=self.identities[1],
             "duplicate enrolled owner or signing identity")
        need(unpack(request["peer_descriptor"],1632)==self.peer_desc,"unregistered peer descriptor")
        self.node = Ledger(":memory:",self.public,self.pin)
        need(self.node.chain==self.chain,"unexpected signed funding chain")
        self.rows = [(occ,cm) for occ,cm in self.node.db.execute(
            "SELECT occ,cm FROM outputs ORDER BY pos")]
        prefix = self.public/"prefix"
        genesis = (prefix/"genesis.bin").read_bytes()
        need(digest(genesis)==self.pin,"unrecognized genesis")
        peer = parse_note(genesis[136+self.peer*NOTE:136+(self.peer+1)*NOTE])
        need(self.peer_desc[:64]==peer.owner and self.rows[self.peer][1]==peer.cm(self.chain),
             "peer funding descriptor mismatch")
        need((prefix/ISSUE_FILES[self.slot]).read_bytes()==self.record,"own issuance mismatch")
        other = (prefix/ISSUE_FILES[self.peer]).read_bytes()
        peer_issue = parse_note(other[140:140+NOTE])
        need(self.rows[GRANTS+self.peer][1]==peer_issue.cm(self.chain),"unrecognized counterasset")
        self.assets = [None,None]
        self.assets[self.slot] = self.issued.asset
        self.assets[self.peer] = peer_issue.asset
        self.coins = {}
        self.next_inputs = (self.slot,GRANTS+self.slot)
        for index,note in zip(self.next_inputs,(self.grant,self.issued)):
            need(self.rows[index][1]==note.cm(self.chain),"own funding mismatch")
            self.coins[index] = Coin(index,note,self.ask)
        self.phase = "ready"
        return {"funding_root":self.node.tip()[2].hex()}

    def receipt(self,leg,slot):
        occ,cm = leg.rows(self.chain)[slot]
        raw = helper("receipt.mjs","open",self.chain+occ+bytes([slot])+cm+self.seed+leg.body.receipts[slot])
        if not raw:
            return None
        note = parse_note(raw)
        need(note.owner==self.desc[:64] and note.cm(self.chain)==cm,"unexpected recovered opening")
        return note

    def sync(self,height):
        for i in range(self.node.tip()[0]+1,height+1):
            wire = (self.public/f"op-{i:02}.bin").read_bytes()
            self.node.admit(wire)
            for leg in parse(wire):
                spent = set(leg.body.nfs)
                self.coins = {idx:c for idx,c in self.coins.items()
                              if h("nf",c.ask,self.rows[idx][0]) not in spent}
                for k,row in enumerate(leg.rows(self.chain)):
                    idx = len(self.rows)
                    note = self.receipt(leg,k)
                    if note is not None:
                        self.coins[idx] = Coin(idx,note,self.ask)
                    self.rows.append(row)
        tip = self.node.tip()
        need(tip[0]==height and tip[2:4]==(FundedTree(self.rows).root,len(self.rows)),"independent history mismatch")
        return tip

    def offer(self, request):
        need(self.phase=="ready" and request["wave"]==self.wave,"unexpected wave")
        tip = self.sync(10*self.wave)
        self.root,self.count = tip[2:4]
        self.wave_anchor = anchor(self.pin.hex(),self.chain,self.root,self.count)
        self.keys = helper("approval.mjs","key",b"")
        self.phase = "offered"
        return {"key":self.keys[:64].hex(),"asset":self.assets[self.slot].hex(),
                "quantity":(7,9)[self.slot],"cash":4,"anchor":self.wave_anchor.hex()}

    def agree(self, request):
        need(self.phase=="offered","unexpected terms")
        offers,salt = request["offers"],unpack(request["salt"],64)
        need(len(offers)==2 and offers[self.slot]["key"]==self.keys[:64].hex(),"own key substitution")
        self.pks = [unpack(o["key"],64) for o in offers]
        need(self.pks[0]!=self.pks[1],"reused approval key")
        desc = [unpack(encoded,1632) for encoded in request["descriptors"]]
        need(desc==self.descriptors,"unregistered receiving descriptors")
        for i,o in enumerate(offers):
            need(unpack(o["asset"],64)==self.assets[i] and o["cash"]==4 and o["quantity"]==(7,9)[i]
                 and unpack(o["anchor"],64)==self.wave_anchor,"unagreed asset, amount or anchor")
        self.expiry = 100
        self.terms = h("terms",b"SGM1/pinned-swap/v1",self.pin,self.chain,self.wave_anchor,
                       le(self.wave,8),salt,le(self.expiry,8),le(1,8),*self.identities,*self.pks,
                       *desc,*(a+le(q,8)+le(4,8) for a,q in zip(self.assets,(7,9))))
        approval = helper("approval.mjs","sign",self.authorization(self.slot)+self.identity[64:])
        self.phase = "attested"
        return {"terms":self.terms.hex(),"approval":approval.hex()}

    def authorization(self,slot):
        return h("terms",b"SGM1/pre-draft-approval/v1",bytes([slot]),self.terms)

    def unlock(self,request):
        need(self.phase=="attested" and unpack(request["terms"],64)==self.terms,"wrong pre-draft terms")
        approvals = request["approvals"]
        need(len(approvals)==2,"two pre-draft approvals required")
        for i,(token,pk) in enumerate(zip(approvals,self.identities,strict=True)):
            message = self.authorization(i)+pk+unpack(token,SIGNATURE)
            need(helper("approval.mjs","verify",message)==b"\x01","invalid pre-draft approval")
        self.phase = "agreed"
        return {"ready":True}

    def conflict(self, request):
        need(self.phase=="agreed" and self.wave==0 and self.allow_conflict,"unexpected conflicting operation")
        need(set(request)=={"action"},"unexpected destination for own conflicting variant")
        self.allow_conflict = False
        asset = self.assets[0]
        body,st,wit,_,_ = prepare(self.pin,self.chain,self.rows,[self.coins[i] for i in self.next_inputs],
                                  [(self.desc,1,asset,5),(self.desc,98,asset,94)],1)
        return {"core":prove(self.pin,body,st,wit).hex()}

    def draft(self, request):
        need(self.phase=="agreed" and set(request)=={"action"},"unexpected draft")
        coins = [self.coins[i] for i in self.next_inputs]
        fee = int(self.slot==0)
        qty = (7,9)[self.slot]
        asset = self.assets[self.slot]
        recipients = [(self.peer_desc,4,asset,qty),
                      (self.desc,sum(c.note.native for c in coins)-4-fee,asset,sum(c.note.qty for c in coins)-qty)]
        body,st,wit,_,notes = prepare(self.pin,self.chain,self.rows,coins,recipients,fee,self.slot+1,
                                      (self.terms,self.keys[:64],self.expiry))
        core = prove(self.pin,body,st,wit)
        self.own_core = digest(core)
        self.change = notes[1]
        self.phase = "drafted"
        return {"core":core.hex()}

    def approve(self, request):
        need(self.phase=="drafted","unexpected signature request")
        self.sync(10*self.wave+9)
        cores = [bytes.fromhex(v) for v in request["cores"]]
        need(len(cores)==2 and digest(cores[self.slot])==self.own_core,"changed local draft")
        legs = parse(pair_frame(cores[0],bytes(SIGNATURE),cores[1],bytes(SIGNATURE)))
        statements = self.node.select(legs)
        for i,(leg,statement) in enumerate(zip(legs,statements,strict=True)):
            b = leg.body
            need(b.role==i+1 and b.ephemeral==self.pks[i] and b.terms==self.terms
                 and b.anchor==self.wave_anchor and b.expiry==self.expiry and b.fee==int(i==0),
                 "changed negotiated swap")
            verify(self.pin,statement,leg.proof)
        incoming = self.receipt(legs[self.peer],0)
        need(incoming is not None and incoming.asset==self.assets[self.peer]
             and incoming.qty==(7,9)[self.peer] and incoming.native==4,"unspendable or changed incoming note")
        self.incoming = incoming
        self.message = pair_message(self.chain,*cores)
        signature = helper("approval.mjs","sign",self.message+self.keys[64:])
        self.keys = None
        self.phase = "signed"
        return {"signature":signature.hex()}

    def confirm(self, request):
        need(self.phase=="signed","unexpected confirmation")
        height = 10*(self.wave+1)
        start = len(self.rows)
        self.sync(height)
        # Bind this confirmation to the immutable bytes verified by this wallet's local ledger.
        wire = self.node.db.execute("SELECT wire FROM blocks WHERE height=?",(height,)).fetchone()[0]
        legs = parse(wire)
        need(len(legs)==2 and pair_message(self.chain,*(l.core for l in legs))==self.message,
             "unexpected confirmed pair")
        own_index,received_index = start+2*self.slot+1,start+2*self.peer
        need(self.coins[own_index].note==self.change and self.coins[received_index].note==self.incoming,
             "unexpected scanned change or delivery")
        self.next_inputs = (own_index,)
        self.wave += 1
        self.phase = "ready"
        return {"height":height,"root":self.node.tip()[2].hex()}


def main():
    slot = int(sys.argv[1])
    need(slot in (0,1),"owner role")
    need(sys.argv[4:] in ([],["--fixture-conflict"]),"unregistered fixture option")
    wallet = Owner(Path(sys.argv[2]),slot,os.fdopen(int(sys.argv[3]),"r+b",buffering=0),
                   allow_conflict=sys.argv[4:]==["--fixture-conflict"])
    actions = {name:getattr(wallet,name) for name in
               ("initial","register","offer","agree","unlock","conflict","draft","approve","confirm")}
    try:
        for line in sys.stdin.buffer:
            try:
                req = json.loads(line)
                need(wallet.phase!="aborted" and req["action"] in actions,"closed or unknown command")
                result = actions[req["action"]](req)
            except (ValueError,KeyError,TypeError,IndexError):
                wallet.phase = "aborted"
                result = {"error":"rejected"}
            print(json.dumps(result,separators=(",",":")),flush=True)
    finally:
        if wallet.node is not None:
            wallet.node.close()


if __name__=="__main__":
    main()
