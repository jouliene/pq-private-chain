"""Focused private negotiation encoding, role consent and shared outbox reservation checks."""
from importlib.util import module_from_spec, spec_from_file_location
from hashlib import sha256
from pathlib import Path
import sqlite3
import struct
from types import SimpleNamespace
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))
from terms import MAGIC, MAGIC_V2, SIZE, SIZE_V2, LIMIT, ZERO, Party, Terms, asset_id
from stage import stage_wallet


def load(name, path):
    spec = spec_from_file_location(name,path)
    result = module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def reject(fn, *args):
    try:
        fn(*args)
    except ValueError:
        return
    raise AssertionError("expected rejection")


def check_terms(net, a, b):
    # Reconstruct the V1 preimage independently so previously negotiated sessions can be resumed.
    old = Terms(net, bytes([42])*32, 43, (a,b))
    payload = MAGIC + net + bytes([42])*32 + struct.pack("<I",43)
    for party in (a,b):
        payload += party.address + party.give + struct.pack("<Q",party.qty)
    assert len(payload) == SIZE and Terms.decode(payload) == old
    assert old.commitment() == sha256(b"SWP1/private-terms/v1\0"+payload).digest()
    assert old.fee(0) == 3 and old.fee(1) == 0

    seller = Party(a.address, a.give, 20)
    buyer = Party(b.address, asset_id("native"), 8)
    assert (buyer.native,buyer.token,seller.native,seller.token) == (8,0,0,20)
    sale = Terms.fresh(net,43,(seller,buyer))
    raw = sale.encode()
    assert len(raw) == SIZE_V2 and raw[:8] == MAGIC_V2 and raw[76] == 1
    assert raw[77] == 1 and raw[77+1642] == 0 and Terms.decode(raw) == sale
    assert sale.commitment() == sha256(b"SWP1/private-terms/v2\0"+raw).digest()
    assert (sale.fee(0),sale.fee(1)) == (0,3)
    reverse = Terms.fresh(net,43,(buyer,seller))
    assert (reverse.fee(0),reverse.fee(1)) == (3,0) and Terms.decode(reverse.encode()) == reverse
    other_payer = Terms(net,sale.blind,43,(seller,buyer),0)
    assert other_payer.commitment() != sale.commitment()
    # A branded currency cannot be relabelled as native, and V1 cannot encode a native side.
    for pos,value in [(76,2),(77,0),(77+1642,1),(77+1642,2)]:
        bad = bytearray(raw)
        bad[pos] = value
        reject(Terms.decode,bytes(bad))
    reject(Terms.decode,raw[:-1])
    reject(Terms.decode,raw+b"x")
    reject(Terms.decode,payload[:76+1601]+ZERO+payload[76+1601+32:])
    reject(Terms.fresh,net,43,(buyer,Party(a.address,ZERO,9)))
    reject(asset_id,"0"*64)
    for q in (0, -1, LIMIT+1):
        reject(Party,b.address,ZERO,q)
    sale.confirm(0,seller.address,seller.give,20,ZERO,8)
    reject(sale.confirm,0,seller.address,seller.give,20,ZERO,7)
    reject(sale.confirm,0,seller.address,seller.give,20,b.give,8)
    return seller,buyer


def check_selection(book, choose, seller, buyer):
    # Isolated SQL inventory. Real spend/proof and decryption are exercised by the PoW walkthrough.
    with sqlite3.connect(":memory:") as db:
        db.row_factory = sqlite3.Row
        db.execute("CREATE TABLE owned (cm BLOB,amount INTEGER,asset BLOB,token INTEGER,origin BLOB,"
                   "path BLOB,nf BLOB,pos INTEGER,spent TEXT)")
        state = SimpleNamespace(db=db)
        def note(pos, native, asset, token, spent=None):
            cm = bytes([pos])*32
            db.execute("INSERT INTO owned VALUES(?,?,?,?,?,?,?, ?,?)",(cm,native,asset,token,b"",b"",cm,pos,spent))
        note(1,200,bytes([6])*32,90)
        note(2,0,seller.give,100)
        note(3,8,ZERO,0)
        note(4,20,ZERO,0,"spent")
        r,n,t = choose(state,book,seller,0)
        assert ([v["cm"][0] for v in r],n,t) == ([2],0,80)
        r,n,t = choose(state,book,seller,3)
        assert ([v["cm"][0] for v in r],n,t) == ([2,3],5,80)
        reject(choose,state,book,buyer,3)
        note(5,5,ZERO,0)
        r,n,t = choose(state,book,buyer,3)
        assert ([v["cm"][0] for v in r],n,t) == ([3,5],2,0)
        note(6,25,ZERO,0)
        r,n,t = choose(state,book,buyer,3)
        assert ([v["cm"][0] for v in r],n,t) == ([6],14,0)
        r,n,t = choose(state,book,Party(buyer.address,ZERO,25),0)
        assert ([v["cm"][0] for v in r],n,t) == ([6],0,0)
        with book.db:
            book.db.execute("INSERT INTO swap_reservations VALUES(?,?,0)",((bytes([6])*32).hex(),bytes(32)))
        r,n,t = choose(state,book,buyer,3)
        assert ([v["cm"][0] for v in r],n,t) == ([3,5],2,0)
        # The seller's valuable off-currency note is never put at risk in either leg.
        db.execute("UPDATE owned SET spent='spent' WHERE pos IN (2,3,5)")
        reject(choose,state,book,seller,0)
        reject(choose,state,book,buyer,3)


def main():
    a = Party(b"\x01"+bytes([2])*1600,bytes([1])*32,7)
    b = Party(b"\x01"+bytes([3])*1600,bytes([2])*32,30)
    net = bytes([4])*32
    seller,buyer = check_terms(net,a,b)
    terms = Terms.fresh(net,43,(a,b))
    same_economics = Terms.fresh(net,43,(a,b))
    assert Terms.decode(terms.encode()) == terms
    assert terms.commitment() != same_economics.commitment()
    assert Terms(net,terms.blind,44,(a,b)).commitment() != terms.commitment()
    terms.confirm(0,a.address,a.give,7,b.give,30)
    terms.confirm(1,b.address,b.give,30,a.give,7)
    reject(terms.confirm,1,a.address,a.give,7,b.give,30)
    reject(terms.confirm,0,a.address,a.give,7,b.give,29)
    reject(Terms,net,bytes(32),43,(a,b))
    reject(Terms.fresh,net,43,(a,a))
    with tempfile.TemporaryDirectory() as scratch:
        directory = Path(scratch)
        mng = load("managed_base",ROOT/"experiments/managed-assets/stage.py")
        dev = mng.install_sources(directory)
        stage_wallet(dev)
        sys.path.insert(0,str(dev))
        from intents import Outbox
        from swap_wallet import choose, emit, read_file
        f = directory/"agreed"
        emit(f,terms.encode())
        assert read_file(f,len(terms.encode()),private=True) == terms.encode()
        reject(emit,f,same_economics.encode())
        assert f.read_bytes() == terms.encode()
        for name in ("intents.py","swap_wallet.py","terms.py","swap_terms.py"):
            compile((dev/name).read_text(),name,"exec")
        with Outbox(directory) as book:
            with book.db:
                book.db.execute("INSERT INTO swap_sessions VALUES(?,0,'offered',NULL,?,?,?,?,?,NULL,NULL)",
                                (bytes(32),bytes(32),b"","[]","[]","{}"))
            check_selection(book,choose,seller,buyer)
            cm = "10"*32
            key = terms.commitment()
            assert not book.reserved(cm,"ordinary-intent")
            with book.db:
                book.db.execute("INSERT INTO swap_sessions VALUES(?,0,'offered',NULL,?,?,?,?,?,NULL,NULL)",
                                (key,bytes(32),b"","[]","[]","{}"))
                book.db.execute("INSERT INTO swap_reservations VALUES(?,?,0)",(cm,key))
            assert book.reserved(cm,"ordinary-intent") and book.reserved(cm,"")
        with Outbox(directory) as book:
            assert book.reserved(cm,"ordinary-intent")
            with book.db:
                book.db.execute("DELETE FROM swap_reservations WHERE terms=? AND side=0",(key,))
            assert not book.reserved(cm,"ordinary-intent")
    print("PASS: legacy and native terms, currency/fee/amount binding, native-only and token-only selection, "
          "hash sensitivity, persistent SWP1 reservations shared with the ordinary wallet")


if __name__ == "__main__":
    main()
