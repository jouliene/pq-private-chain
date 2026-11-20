"""Test service accounting/crash semantics against an explicit deterministic observation sequence."""
from concurrent.futures import ProcessPoolExecutor
from contextlib import closing, contextmanager
import multiprocessing
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from redeem_service import Service, open_private

NETWORK = bytes([7])*32
ASSET = bytes([8])*32
RETURN_TX = bytes([9])*32
PRIVATE_NF = bytes([10])*32
BURN = (bytes([3])*32).hex()
REPLACEMENT = (bytes([4])*32).hex()


@contextmanager
def service(directory):
    folder = Path(directory)
    with closing(open_private(folder/"requests.sqlite")) as db, closing(open_private(folder/"bank.sqlite")) as bank:
        yield Service(db, bank, NETWORK)


def observation(selected, depth, *, quantity=200, correct_return=True):
    def observe(ids):
        return dict(tip=(bytes([depth])*32).hex(), height=20, events=[
            dict(tx=tx, op="burn", quantity=quantity, asset=ASSET.hex(),
                 nfs=[(PRIVATE_NF if correct_return else bytes(32)).hex(), (bytes([81])*32).hex()],
                 block=(bytes([5])*32).hex(), height=21-depth, confirmations=depth)
            if tx == selected else None for tx in ids])
    return observe


def drive(directory, tx, depth, crash=False):
    with service(directory) as svc:
        return svc.reconcile("order1", observation(tx, depth), tx, crash)


def rejected(fn, *args):
    try:
        fn(*args)
    except ValueError:
        return
    raise AssertionError("expected redemption rejection")


def enroll(svc):
    svc.enroll("order1", "treasury", ASSET, 200, RETURN_TX, "alice", lambda: PRIVATE_NF)


def check():
    os.umask(0o077)
    ctx = multiprocessing.get_context("spawn")
    with tempfile.TemporaryDirectory() as tmp:
        with service(tmp) as svc:
            enroll(svc)
            # Already enrolled requests do not reopen a now-spent return.
            svc.enroll("order1", "treasury", ASSET, 200, RETURN_TX, "alice", None)
            rejected(svc.enroll, "alias", "treasury", ASSET, 200, RETURN_TX, "alice", lambda: PRIVATE_NF)
            rejected(svc.enroll, "order1", "treasury", ASSET, 200, RETURN_TX, "other", lambda: PRIVATE_NF)
            for bad in (observation(None, 1), observation(BURN, 2, quantity=201),
                        observation(BURN, 2, correct_return=False)):
                rejected(svc.reconcile, "order1", bad, BURN)
            assert not svc.candidate_ids("order1")
            info = svc.reconcile("order1", observation(BURN, 2), BURN)
            assert (info["paid"], info["owed"], info["confirmations"], info["attempts"]) == (0, 200, 2, 1)
        proc = ctx.Process(target=drive, args=(tmp, BURN, 3, True))
        proc.start()
        proc.join(15)
        assert proc.exitcode == 75
        with service(tmp) as svc:
            assert svc.request("order1")["acknowledged"] is None
            assert svc.bank.execute("SELECT count(*) FROM payments").fetchone()[0] == 1
            info = svc.reconcile("order1", observation(None, 0))
            receipt = info["bank_receipt"]
            assert receipt == svc.request("order1")["acknowledged"]
            assert (info["paid"], info["owed"], info["confirmations"], info["exposure"]) == (200, 0, 0, 200)
        with ProcessPoolExecutor(max_workers=3, mp_context=ctx) as pool:
            answers = list(pool.map(drive, [tmp]*4, [REPLACEMENT]*4, [3]*4))
        assert all((a["payout_count"], a["bank_receipt"], a["exposure"], a["attempts"]) ==
                   (1, receipt, 0, 2) for a in answers)
    with tempfile.TemporaryDirectory() as tmp:
        with service(tmp) as svc:
            enroll(svc)
        with ProcessPoolExecutor(max_workers=3, mp_context=ctx) as pool:
            answers = list(pool.map(drive, [tmp]*4, [BURN]*4, [3]*4))
        assert len({a["bank_receipt"] for a in answers}) == 1
        with service(tmp) as svc:
            assert tuple(svc.bank.execute("SELECT count(*),sum(amount) FROM payments").fetchone()) == (1, 200)
    print("PASS: immutable enrollment, exact return binding, confirmation threshold, real post-commit process crash, "
          "orphan exposure, replacement reconciliation and concurrent bank idempotency")


if __name__ == "__main__":
    check()
