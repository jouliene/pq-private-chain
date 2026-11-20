"""Exercise exact external-return identification using the wallet's SQLite row format."""
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
from redemption import ZERO, return_commitment, select_return


def reject(call, *args):
    try:
        call(*args)
    except ValueError:
        return
    raise AssertionError("expected return selection rejection")


def check():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE owned(cm BLOB, amount INTEGER, asset BLOB, token INTEGER, kind TEXT,"
               " creator BLOB, spender BLOB, spent INTEGER, pos INTEGER)")
    asset, tx = bytes([5])*32, bytes([8])*32
    req = SimpleNamespace(asset=asset, burn=12, return_tx=tx)
    def insert(i, amount, ident, token, kind, creator):
        db.execute("INSERT INTO owned VALUES(?,?,?,?,?,?,NULL,NULL,?)",
                   (bytes([i])*32, amount, ident, token, kind, creator, i))
    insert(1, 9, asset, 12, "incoming", bytes(32))  # Pre-existing treasury.
    insert(2, 0, asset, 12, "incoming", tx)
    insert(3, 9, ZERO, 0, "reward", None)
    insert(4, 9, asset, 12, "change", tx)
    never = lambda _: False
    def exact_fee(req, native, token):
        return (native-3, token-req.burn) if native >= 3 and token >= req.burn else None
    assert select_return(db, req, never, exact_fee) == ((bytes([2])*32).hex(), (bytes([3])*32).hex())
    reject(return_commitment, db, tx, asset, 13)
    reject(return_commitment, db, bytes([11])*32, asset, 12)
    reject(select_return, db, req, lambda cm: cm == (bytes([2])*32).hex(), exact_fee)
    db.execute("UPDATE owned SET spent=1 WHERE pos=2")
    reject(return_commitment, db, tx, asset, 12)
    db.execute("UPDATE owned SET spent=NULL WHERE pos=2")
    db.execute("UPDATE owned SET spender=? WHERE pos=3", (tx,))
    reject(return_commitment, db, tx, asset, 12)
    db.execute("UPDATE owned SET spender=NULL WHERE pos=3")
    insert(5, 0, asset, 12, "incoming", tx)
    reject(return_commitment, db, tx, asset, 12)
    print("PASS: exact external return, change exclusion, local-input exclusion, fee selection, missing, spent and ambiguous returns")


if __name__ == "__main__":
    check()
