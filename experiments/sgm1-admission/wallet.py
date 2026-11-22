"""Research wallet roles. Receipt and approval secrets travel only on private process pipes."""
from dataclasses import dataclass
import subprocess
import sys
from packets import HERE, Leg, anchor, helper, occurrence
from funding_fixture import parse_note
from relation import (FundedTree, Input, Witness, Statement, ZERO, evaluate, h, le, need,
                      new_note, spend_key)

@dataclass(frozen=True)
class Coin:
    index: int
    note: object
    ask: bytes

def descriptor(chain, seed):
    return helper("receipt.mjs","descriptor",chain+seed)

def prepare(pin, chain, rows, coins, recipients, fee, role=0, extension=()):
    """A wallet needs only its own coins/keys and public descriptors and history."""
    tree = FundedTree(rows)
    real = []
    for coin in coins:
        i, n = coin.index, coin.note
        occ, cm = rows[i]
        need(cm == n.cm(chain), "unexpected funded note")
        real.append(Input(coin.ask,n.native,n.asset,n.qty,n.salt,occ,i,tree.path(i)))
    active = int(len(real) == 2)
    need(1 <= len(real) <= 2,"wallet arity")
    if not active:
        real.append(real[0])
    nfs = (h("nf",real[0].ask,real[0].occ),
           h("nf" if active else "dummy_nf",real[1].ask,real[1].occ))
    outputs, receipts, effects = [], [], []
    for i,(desc,value,asset,qty) in enumerate(recipients):
        n = new_note(desc[:64],value,asset,qty)
        cm,occ = n.cm(chain),occurrence(chain,role,nfs,i)
        receipts.append(helper("receipt.mjs","seal",chain+occ+bytes((i,))+cm+desc+n.encode()))
        outputs.append(n)
        effects.append((occ,cm))
    body = Leg(1,role,anchor(pin.hex(),chain,tree.root,len(rows)),fee,nfs,
               tuple(cm for _,cm in effects),tuple(receipts),*extension)
    intent = body.intent(chain,tree.root,len(rows))
    auth = h("auth",real[0].ask,intent)
    st = Statement(chain,tree.root,len(rows),fee,nfs,body.cms,intent,auth)
    asset_ids = {n.asset for n in [*(c.note for c in coins),*outputs] if n.qty}
    need(len(asset_ids) <= 1,"one asset per leg")
    wit = Witness(tuple(real),tuple(outputs),active,next(iter(asset_ids),ZERO))
    evaluate(st,wit)
    return body,st,wit,effects,outputs

def prove(pin, body, st, wit):
    data = subprocess.check_output([sys.executable,"-B",HERE/"reference.py","prove",pin.hex()],
                                   input=st.encode()+wit.encode())
    return body.core(st.auth,data)

def recover():
    """Fresh wallet takes one seed from stdin. Its directory contains only public chain data."""
    from tempfile import TemporaryDirectory
    from ledger import Ledger
    from fixtures_public import read_prefix, read_rows
    from packets import parse
    from pathlib import Path
    public = Path(sys.argv[2])
    seed = sys.stdin.buffer.read(65)
    need(len(seed)==64,"backup length")
    pin,chain,rows = read_prefix(public)
    spent=set()
    matches=[]
    with TemporaryDirectory(prefix="sgm1-restored-node-") as private_store:
        node=Ledger(Path(private_store)/"node.sqlite",public,pin)
        for wire in read_rows(public,10):
            node.admit(wire)
        # Scan only the verified canonical bodies, with no ownership-dependent request.
        history=[row[0] for row in node.db.execute("SELECT wire FROM blocks WHERE height>0 ORDER BY height")]
        accepted=node.tip()
        node.close()
    for wire in history:
        for l in parse(wire):
            spent.update(l.body.nfs)
            for slot,(occ,cm) in enumerate(l.rows(chain)):
                raw=helper("receipt.mjs","open",chain+occ+bytes((slot,))+cm+seed+l.body.receipts[slot])
                if raw:
                    matches.append(Coin(len(rows),parse_note(raw),spend_key(chain,seed)))
                rows.append((occ,cm))
    need((FundedTree(rows).root,len(rows)) == accepted[2:4],"wallet/validated root disagreement")
    matches=[c for c in matches if h("nf",c.ask,rows[c.index][0]) not in spent]
    need(len(matches)==1 and matches[0].note.native==8 and matches[0].note.qty==0,"restored funds")
    dest=(public/"onward.addr").read_bytes()
    out=[(dest,4,ZERO,0),(descriptor(chain,seed),3,ZERO,0)]
    body,st,wit,_,_=prepare(pin,chain,rows,matches,out,1)
    sys.stdout.buffer.write(prove(pin,body,st,wit))

if __name__=="__main__":
    if sys.argv[1]=="recover":
        recover()
    else:
        raise ValueError("unknown wallet role")
