"""Focused Python controls. These use no proofs, private fixtures or node substitutes."""
from pathlib import Path
import shutil
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))
from asset_wallet import MAX_AMOUNT, ZERO, Request, change_for, default_id, issuance_id, parse_asset, select_amounts, tally
from stage import stage_wallet


def reject(fn, *args):
    try:
        fn(*args)
    except ValueError:
        return
    raise AssertionError("expected rejection")


def word(i):
    return i.to_bytes(32, "little")


def check():
    first, second = word(81), word(82)
    native = (word(1), 10, ZERO, 0)
    a = (word(2), 1, first, 12)
    b = (word(3), 5, second, 15)
    rows = [native, a, b]
    choose = lambda rows, req: select_amounts(rows, req, lambda _: False)
    send = Request(2, first, 11)
    issue = Request.issue(8)
    assert choose(rows, issue) == (word(1).hex(),)
    assert choose(rows, send) == (word(1).hex(), word(2).hex())
    reject(choose, [a, b], send)
    reject(choose, [a, b], issue)
    reject(select_amounts, rows, send, lambda cm: cm == word(1).hex())
    assert choose([b], Request(2, ZERO, 0)) == (word(3).hex(),)
    reject(choose, [a, b], Request(3, ZERO, 0))
    assert change_for(send, 11, 12) == (6, 1)
    assert change_for(issue, 10, 0) == (7, 0)
    assert change_for(Request(2, ZERO, 0), 5, 15) == (0, 15)
    assert change_for(send, MAX_AMOUNT * 2, 12) is None
    reject(Request, 1, ZERO, 1)
    reject(Request, 1, first, 0)
    reject(Request.issue, 0)
    reject(Request.issue, MAX_AMOUNT + 1)
    reject(Request.issue, True)
    reject(Request, 0, first, 8, 8)
    reject(parse_asset, "ff" * 32)
    assert parse_asset("native") == ZERO and parse_asset(first.hex()) == first
    assert default_id(bytes(1601), send) != default_id(bytes(1601), Request(2, second, 11))
    assert default_id(bytes(1601), Request.issue(11)) != default_id(bytes(1601), send)
    assert issuance_id(ZERO, word(1)) != issuance_id(word(1), word(1))
    assert issuance_id(ZERO, word(1)) != issuance_id(ZERO, word(2))
    assert issuance_id(ZERO, word(1)).hex() == "6eebfd648a84a55fbb30828a411e677805420a110fe2386e520bb8a80e9f0b18"
    balance = dict(balance=0, assets={}, notes=0, reward_notes=0, incoming_notes=0,
                   change_notes=0, receipt_notes=0)
    tally(balance, "reward", 10, ZERO, 0, 1)
    tally(balance, "incoming", 0, first, 12, 1)
    tally(balance, "incoming", 0, second, 2, 1)
    tally(balance, "incoming", 0, first, 12, -1)
    assert balance == dict(balance=10, assets={second.hex(): 2}, notes=2, reward_notes=1,
                           incoming_notes=1, change_notes=0, receipt_notes=1)
    with tempfile.TemporaryDirectory() as temp:
        dev = Path(temp)
        for name in ("wallet", "wallet_sync", "intents", "cli"):
            shutil.copyfile(ROOT / "devnet" / (name + ".py"), dev / (name + ".py"))
        stage_wallet(dev)
        sys.path.insert(0, str(dev))
        from intents import Outbox
        address = bytes(1601)
        with Outbox(dev) as book:
            book.register("fixed", address, send)
            book.register("fixed", address, send)
            for other in (Request(2, second, 11), Request(3, first, 11), Request.issue(11)):
                reject(book.register, "fixed", address, other)
            reject(book.register, "fixed", address[::-1][:-1] + b"1", send)
            book.register("issue", address, issue)
        with Outbox(dev) as resumed:
            assert Request.from_row(resumed.get("fixed")) == send
            assert Request.from_row(resumed.get("issue")) == issue
            assert resumed.summary("issue")["issue_supply"] == 8
            assert not resumed.summary("fixed")["attempts"]
    print("PASS: asset identities, selection, exact fee/change, per-ID inventory, intent persistence and base staging")


if __name__ == "__main__":
    check()
