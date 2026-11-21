import os
from collections import Counter
from dataclasses import replace
from pathlib import Path
import secrets
import subprocess
import unittest

from envelope import Body, pair_frame, pair_message, SIGNATURE
from issuer import Funding, Issue
from relation import (ZERO, FundedTree, Input, Statement, Witness, credit_occ, evaluate,
                      funding_asset, h, new_note, occurrence, owner, spend_key)
from side import schedule

rnd = lambda: secrets.token_bytes(64)


def funded(ask, note, occ, index, tree):
    return Input(ask, note.native, note.asset, note.qty, note.salt, occ, index, tree.path(index))


def form(chain, tree, inputs, outputs, common, active=1, role=0, fee=3, receipts=None, keys=None, anchor=None):
    nf = tuple(h("nf" if slot == 0 or active else "dummy_nf", x.ask, x.occ)
               for slot, x in enumerate(inputs))
    cms = tuple(n.cm(chain) for n in outputs)
    if receipts is None:
        # Opaque extent for serialization tests; never admitted or presented as an envelope.
        receipts = (bytes(1792), bytes(1792))
    terms, ephemeral, expiry = keys or (b"", b"", 0)
    b = Body(1, role, rnd() if anchor is None else anchor, fee, nf, cms, receipts, terms, ephemeral, expiry)
    intent = b.intent(chain, tree.root, tree.count)
    s = Statement(chain, tree.root, tree.count, fee, nf, cms, intent, h("auth", inputs[0].ask, intent))
    return b, s, Witness(tuple(inputs), tuple(outputs), active, common)


class RelationTest(unittest.TestCase):
    def setUp(self):
        self.chain, self.seed, self.offline = rnd(), rnd(), rnd()
        self.ask = spend_key(self.chain, self.seed)
        self.receiver = owner(spend_key(self.chain, self.offline))
        self.aid = funding_asset(self.chain, rnd(), rnd(), 60)
        grants = (new_note(owner(self.ask), 17, ZERO, 0),
                  new_note(owner(self.ask), 0, self.aid, 60))
        self.entries = [(credit_occ(self.chain, rnd(), 0), n.cm(self.chain)) for n in grants]
        self.tree = FundedTree(self.entries)
        self.ins = [funded(self.ask,n,o,j,self.tree) for j,(n,(o,_)) in enumerate(zip(grants,self.entries))]
        self.outs = (new_note(self.receiver, 8, self.aid, 25),
                     new_note(owner(self.ask), 6, self.aid, 35))
        self.body,self.s,self.w = form(self.chain,self.tree,self.ins,self.outs,self.aid)

    def test_money_and_geometry(self):
        counts = evaluate(self.s,self.w)
        self.assertEqual(counts, Counter({("owner",66):2,("cm",274):4,("leaf",130):2,
            ("parent",131):80,("nf",130):2,("auth",130):1}))
        self.assertEqual(sum(counts.values()),91)
        self.assertEqual(sum(n*(1+b//136) for (_,b),n in counts.items()),99)
        self.assertEqual(sum(schedule().values()),3854992)
        self.assertEqual((len(self.w.encode()),len(self.s.encode())),(6155,526))
        self.assertEqual(len(self.body.core(self.s.auth,b"X"))-1,3990)

    def test_ordinary_correctness(self):
        for s,w in [(replace(self.s, fee=4),self.w),(replace(self.s,count=1),self.w),
                    (replace(self.s,root=rnd()),self.w),(replace(self.s,auth=rnd()),self.w),
                    (self.s,replace(self.w,asset=rnd())),
                    (self.s,replace(self.w,inputs=(self.ins[0],replace(self.ins[1],occ=rnd())))),
                    (self.s,replace(self.w,active=0))]:
            with self.assertRaises(ValueError):
                evaluate(s,w)
        # Force exact conservation to operate on the boundary, after input and output binding.
        max64 = (1<<64)-1
        for value in (max64,max64+1):
            altered = (replace(self.outs[0],native=value),self.outs[1])
            with self.assertRaises(ValueError):
                _,s,w = form(self.chain,self.tree,self.ins,altered,self.aid)
                evaluate(s,w)

    def test_occurrence_identity_and_one_real(self):
        first = self.ins[0]
        copies = [(first.occ,self.entries[0][1]),(credit_occ(self.chain,rnd(),1),self.entries[0][1])]
        a, b = copies
        self.assertNotEqual(h("nf",self.ask,a[0]), h("nf",self.ask,b[0]))
        for rows in ([a,b],[b,a]):
            tree = FundedTree(rows)
            i = funded(self.ask,first.note(),a[0],rows.index(a),tree)
            outs = (new_note(self.receiver,14,ZERO,0),new_note(owner(self.ask),0,ZERO,0))
            _,s,w = form(self.chain,tree,(i,i),outs,ZERO,active=0)
            self.assertEqual(s.nfs[0],h("nf",self.ask,a[0]))
            self.assertEqual(sum(evaluate(s,w).values()),91)

    def test_two_owners_swap(self):
        # Each owner prepares its own assignment. Both require the other's actual incoming
        # output before approval. The two conjunctions alone do not execute consensus.
        counter = spend_key(self.chain,rnd())
        native = new_note(owner(counter),21,ZERO,0)
        o = credit_occ(self.chain,rnd(),0)
        tree = FundedTree(self.entries + [(o,native.cm(self.chain))])
        x = funded(counter,native,o,2,tree)
        y = funded(self.ask,self.ins[1].note(),self.ins[1].occ,1,tree)
        terms = rnd()
        roles = []
        for i,outs,aid,fee,role in [
            (y,(new_note(owner(counter),0,self.aid,25),new_note(owner(self.ask),0,self.aid,35)),self.aid,0,1),
            (x,(new_note(owner(self.ask),10,ZERO,0),new_note(owner(counter),8,ZERO,0)),ZERO,3,2)]:
            b,s,w = form(self.chain,tree,(i,i),outs,aid,0,role,fee,keys=(terms,rnd(),8))
            evaluate(s,w)
            roles.append((b,s))
        a,b = roles
        self.assertEqual(len(set(a[1].nfs + b[1].nfs)),4)
        self.assertEqual(a[1].fee + b[1].fee,3)
        # Marker counts only check serializer extent; no public verifier accepts this fixture.
        marker=b'X'
        sig=bytes(SIGNATURE)
        pair = pair_frame(a[0].core(a[1].auth,marker),sig,b[0].core(b[1].auth,marker),sig)
        self.assertEqual(len(pair)-2,67856)

    def test_issuer_and_both_approvals(self):
        def run(op,data):
            return subprocess.run([os.environ.get("FS_RECEIPT_NODE","node"),Path(__file__).with_name("approval.mjs"),op],
                                  input=data,stdout=subprocess.PIPE,check=True).stdout
        keys = [run("key",b"") for _ in range(2)]
        issuer,nonce = keys[0][:64], rnd()
        aid = funding_asset(self.chain,issuer,nonce,60)
        issue = Issue(issuer,nonce,60,new_note(self.receiver,0,aid,60),bytes(1792))
        _,msg,_,_ = issue.public_fields(self.chain)
        sig = run("sign",msg+keys[0][64:])
        self.assertEqual(run("verify",msg+issuer+sig),b"\1")
        with self.assertRaises(ValueError):
            replace(issue,cap=61).public_fields(self.chain)
        # Isolated final-approval primitive; the two opaque cores have no proof verdict.
        msg = pair_message(self.chain,b"synthetic core 0",b"synthetic core 1")
        for i,k in enumerate(keys):
            sig = run("sign",msg+k[64:])
            self.assertEqual(run("verify",msg+k[:64]+sig),b"\1")
            self.assertEqual(run("verify",msg+keys[1-i][:64]+sig),b"\0")

    def test_offline_restore_and_onward_relation(self):
        def run(op, data):
            return subprocess.run([os.environ.get("FS_RECEIPT_NODE","node"),Path(__file__).with_name("receipt.mjs"),op],
                                  input=data,stdout=subprocess.PIPE,check=True).stdout
        def approval(op,data):
            return subprocess.run([os.environ.get("FS_RECEIPT_NODE","node"),Path(__file__).with_name("approval.mjs"),op],
                                  input=data,stdout=subprocess.PIPE,check=True).stdout
        key = approval("key",b"")
        nonce = rnd()
        self.aid = funding_asset(self.chain,key[:64],nonce,60)
        self.outs = (replace(self.outs[0],asset=self.aid),replace(self.outs[1],asset=self.aid))
        native = self.ins[0].note()
        token = new_note(owner(self.ask),0,self.aid,60)
        state = Funding(self.chain,[native])
        fid = h("funding_id",self.chain,b"\1",self.aid)
        token_context = self.chain+credit_occ(self.chain,fid,0)+b"\0"+token.cm(self.chain)
        owner_desc = run("descriptor",self.chain+self.seed)
        issue = Issue(key[:64],nonce,60,token,run("seal",token_context+owner_desc+token.encode()))
        _,message,_,_ = issue.public_fields(self.chain)
        sig = approval("sign",message+key[64:])
        state.register(issue,sig)
        with self.assertRaises(ValueError):
            state.register(issue,sig)
        self.assertEqual(state.native,17)
        self.assertEqual(state.supplies,{self.aid:60})
        self.entries = state.entries
        self.tree = FundedTree(self.entries)
        self.ins = [funded(self.ask,n,o,j,self.tree)
                    for j,(n,(o,_)) in enumerate(zip((native,token),self.entries))]
        self.body,self.s,self.w = form(self.chain,self.tree,self.ins,self.outs,self.aid)
        desc = run("descriptor",self.chain+self.offline)
        self.assertEqual(desc[:64],self.receiver)
        n = self.outs[0]
        occ = occurrence(self.chain,0,self.s.nfs,0)
        ctx = self.chain+occ+b'\x00'+self.s.cms[0]
        envelope = run("seal",ctx+desc+n.encode())
        self.assertEqual(len(envelope),1792)
        change_desc = run("descriptor",self.chain+self.seed)
        change_ctx = self.chain+occurrence(self.chain,0,self.s.nfs,1)+b'\x01'+self.s.cms[1]
        change_env = run("seal",change_ctx+change_desc+self.outs[1].encode())
        b,s,w = form(self.chain,self.tree,self.ins,self.outs,self.aid,receipts=(envelope,change_env))
        self.assertFalse(run("open",change_ctx+self.offline+change_env))
        evaluate(s,w)
        retry_envelopes = (run("seal",ctx+desc+n.encode()),
                           run("seal",change_ctx+change_desc+self.outs[1].encode()))
        b_retry,s_retry,w_retry = form(self.chain,self.tree,self.ins,self.outs,self.aid,
                                       receipts=retry_envelopes,anchor=b.anchor)
        evaluate(s_retry,w_retry)
        self.assertTrue(b_retry.prefix() == b.prefix())
        self.assertTrue(all(now != old for now,old in zip(retry_envelopes,b.receipts)))
        self.assertTrue(s_retry.nfs == s.nfs and s_retry.intent != s.intent and s_retry.auth != s.auth)
        # Fresh native process, backup and public row only.
        recovered = run("open",ctx+self.offline+envelope)
        self.assertTrue(recovered == n.encode())
        self.assertFalse(run("open",ctx+rnd()+envelope))
        self.assertFalse(run("open",ctx+self.offline+envelope[:-1]+bytes([envelope[-1]^1])))
        altered = bytearray(envelope)
        altered[1568] ^= 1
        self.assertFalse(run("open",ctx+self.offline+altered))
        from relation import Note
        n2 = Note(recovered[:64],int.from_bytes(recovered[64:72],"little"),recovered[72:136],
                  int.from_bytes(recovered[136:144],"little"),recovered[144:208])
        rows = self.entries + [(occ,self.s.cms[0]),(occurrence(self.chain,0,self.s.nfs,1),self.s.cms[1])]
        tree = FundedTree(rows)
        restored = spend_key(self.chain,self.offline)
        i = funded(restored,n2,rows[2][0],2,tree)
        _,s2,w2 = form(self.chain,tree,(i,i),(new_note(owner(self.ask),4,self.aid,20),
                       new_note(owner(restored),1,self.aid,5)),self.aid,active=0)
        self.assertEqual(sum(evaluate(s2,w2).values()),91)
        self.assertTrue(set(s2.nfs).isdisjoint(s_retry.nfs))


if __name__ == "__main__":
    unittest.main(verbosity=2)
