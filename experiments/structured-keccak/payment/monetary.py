"""Compile the complete FS01 public statement and private payment relation."""
from pathlib import Path
import sys

import numpy as np

EXPERIMENTS = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(EXPERIMENTS / "structured-keccak" / "funding"))
from plan import Wiring, public_bits, I, B
from argument import shape
# The proof runtime has its own module search path. Import the FS01 clear relation
# by exact path to avoid conflating it with SmallWood's generic R1CS relation.py.
from importlib.util import module_from_spec, spec_from_file_location
spec = spec_from_file_location("fs01_payment_reference", EXPERIMENTS / "fresh-spend/binding/relation.py")
ref = module_from_spec(spec)
sys.modules[spec.name] = ref
spec.loader.exec_module(ref)

ZERO = np.zeros(1, I)
ONE = np.ones(1, I)


class PaymentWiring(Wiring):
    def constant(self, n, width):
        return ((int(n) >> np.arange(width, dtype=object)) & 1).astype(I)

    def equal(self, a, b):
        a, b = np.asarray(a, I), np.asarray(b, I)
        if a.shape != b.shape:
            raise ValueError("mismatched equality dimensions")
        self.linear.append(((a,b),np.zeros(len(a), B)))

    def invert(self, x):
        return self.xor(x,np.ones(len(x), I))

    def gate(self, x, bit):
        return self.product(x,np.full(len(x),int(bit[0]),I))

    def nonzero(self, x):
        # One minus the product of (1+x_i), including every input bit.
        v = self.invert(x)
        while len(v) > 1:
            pairs = len(v)//2
            v = np.concatenate((self.product(v[:2*pairs:2],v[1:2*pairs:2]),v[2*pairs:]))
        return self.invert(v)

    def add(self, a, b):
        a = np.pad(a,(0,66-len(a)))
        b = np.pad(b,(0,66-len(b)))
        propagate = self.xor(a,b)
        generate = self.product(a,b)
        carry = ZERO
        carries = []
        for j in range(66):
            carries.append(carry)
            carry = self.xor(generate[j:j+1],self.product(propagate[j:j+1],carry))
        self.pin(carry,[0])
        return self.xor(propagate,np.concatenate(carries))

    def nullifier1(self, ask, occurrence, inactive):
        # NF tag 8 and dummy NF tag 9 differ only in their low bit. A 130-byte message fits one rate block.
        tag = np.concatenate((inactive,public_bits(b"\x08")[1:]))
        block = np.concatenate((public_bits(b"\xf1"),tag,ask,occurrence,
                                public_bits(b"\x1f\x00\x00\x00\x00\x80"),np.zeros(512,I)))
        return self.permutation(block)[:512]


def build_payment(s, flatten, witness=None):
    s.encode()
    if s.nfs[0] == s.nfs[1] or flatten <= 0 or 24 % flatten:
        raise ValueError("invalid monetary public parameters")
    private = witness is not None
    if private:
        witness.encode()
    w = PaymentWiring(flatten, private)
    active = w.allocate(1,[witness.active] if private else None)
    inactive = w.invert(active)
    common = w.secret(64,witness.asset if private else None)

    asks, indices, records, notes = [], [], [], []
    for slot in range(2):
        x = witness.inputs[slot] if private else None
        def inp(n, width):
            data = getattr(x,n) if private else None
            if isinstance(data,int):
                data = data.to_bytes(width,"little")
            return w.secret(width,data)
        ask,occ = inp("ask",64),inp("occ",64)
        native,asset,qty,salt = (inp(name,width) for name,width in
                                 (("native",8),("asset",64),("qty",8),("salt",64)))
        idx = inp("index",5)
        asks.append(ask)
        indices.append(idx)
        records.append(np.concatenate((ask,native,asset,qty,salt,occ,idx)))
        notes.append((native,asset,qty))
        owner = w.shake(3,ask)
        cm = w.shake(4,public_bits(s.chain),owner,native,asset,qty,salt)
        cur = w.shake(5,occ,cm)
        w.below_count(idx,s.count)
        for level in range(40):
            sibling = w.secret(64,x.path[level] if private else None)
            left,right = w.order(cur,sibling,idx[level])
            cur = w.shake(7,public_bits(bytes((level,))),left,right)
        w.pin(cur,public_bits(s.root))
        nf = w.shake(8,ask,occ) if slot == 0 else w.nullifier1(ask,occ,inactive)
        w.pin(nf,public_bits(s.nfs[slot]))

    # Distinct index exactly when active; when inactive the entire 277-byte scalar records must agree.
    w.equal(w.nonzero(w.xor(*indices)),active)
    diff = w.xor(*records)
    w.pin(w.gate(diff,inactive),np.zeros(len(diff),B))
    for slot in range(2):
        note = witness.outputs[slot] if private else None
        def out(name, width):
            v = getattr(note,name) if private else None
            return w.secret(width,v.to_bytes(width,"little") if isinstance(v,int) else v)
        owner,native,asset,qty,salt = (out(n,b) for n,b in (("owner",64),("native",8),("asset",64),
                                                           ("qty",8),("salt",64)))
        notes.append((native,asset,qty))
        cm = w.shake(4,public_bits(s.chain),owner,native,asset,qty,salt)
        w.pin(cm,public_bits(s.cms[slot]))
    qnz = [w.nonzero(qty) for _,_,qty in notes]
    w.equal(w.nonzero(common),w.nonzero(np.concatenate(qnz)))
    for index,(native,asset,_) in enumerate(notes):
        w.equal(asset,w.gate(common,qnz[index]))
        if index < 2:
            w.pin(w.nonzero(np.concatenate((native,qnz[index]))),[1])
    for field in (0,2):
        v = [note[field] for note in notes]
        lhs = w.add(v[0],w.gate(v[1],active))
        rhs = w.add(v[2],v[3])
        if field == 0:
            # The public fee is embedded as canonical 64-bit constants.
            rhs = w.add(rhs,w.constant(s.fee,64))
        w.equal(lhs,rhs)
    w.pin(w.shake(10,asks[0],public_bits(s.intent)),public_bits(s.auth))
    if len(w.bounds) != 99 or len(w.selectors) != 80:
        raise ValueError("unexpected monetary hash geometry")
    return w


def public_statement(data):
    if len(data) != 526:
        raise ValueError("expected exactly one FS01 statement")
    s = ref.Statement(data[:64],data[64:128],int.from_bytes(data[128:134],"little"),
                      int.from_bytes(data[134:142],"little"),
                      (data[142:206],data[206:270]),(data[270:334],data[334:398]),
                      data[398:462],data[462:526])
    if s.encode() != data:
        raise ValueError("noncanonical statement")
    return s


def private_witness(data):
    if len(data) != 6155:
        raise ValueError("expected exactly one private FS01 witness")
    slots = []
    for i in range(2):
        x=data[i*2837:(i+1)*2837]
        slots.append(ref.Input(x[:64],int.from_bytes(x[64:72],"little"),x[72:136],
                               int.from_bytes(x[136:144],"little"),x[144:208],x[208:272],
                               int.from_bytes(x[272:277],"little"),
                               tuple(x[j:j+64] for j in range(277,2837,64))))
    notes = []
    for j in range(2):
        x = data[5674+j*208:5674+(j+1)*208]
        notes.append(ref.Note(x[:64],int.from_bytes(x[64:72],"little"),x[72:136],
                              int.from_bytes(x[136:144],"little"),x[144:208]))
    w = ref.Witness(tuple(slots),tuple(notes),data[6090],data[6091:])
    if w.encode() != data:
        raise ValueError("noncanonical witness")
    return w
