"""Focused private negotiation encoding, role consent and shared outbox reservation checks."""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))
from terms import Party, Terms
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


def main():
    a = Party(b"\x01"+bytes([2])*1600,bytes([1])*32,7)
    b = Party(b"\x01"+bytes([3])*1600,bytes([2])*32,30)
    net = bytes([4])*32
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
        from swap_wallet import emit, read_file
        f = directory/"agreed"
        emit(f,terms.encode())
        assert read_file(f,len(terms.encode()),private=True) == terms.encode()
        reject(emit,f,same_economics.encode())
        assert f.read_bytes() == terms.encode()
        for name in ("intents.py","swap_wallet.py","swap_terms.py"):
            compile((dev/name).read_text(),name,"exec")
        with Outbox(directory) as book:
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
    print("PASS: independent role economics, strong per-agreement randomization, private file pinning, "
          "hash sensitivity, persistent SWP1 reservations shared with the ordinary wallet")


if __name__ == "__main__":
    main()
