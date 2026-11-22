"""Fast local inventory and crash controls. Supply the staged profile-C deployment as the argument."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent/"atomic-swap/wallet")]
from partial_state import Book, Order
from terms import LIMIT, Party, Terms


def ident(label):
    return sha256(label.encode()).hexdigest()


def address(name):
    return b"\x01" + bytes.fromhex(ident(name)) * 50


SELL = "01" * 32
BUY = "02" * 32
NETWORK = ident("network")
ORDER = Order(ident("order"), NETWORK, address("maker").hex(), SELL, BUY, 100, 10, 1)
RID = ident("reservation")
BASE = ident("branch before fork")


def snapshot(tip, height, bundles=None):
    return dict(network=NETWORK, tip=tip, height=height, bundles=bundles or {})


def terms(request, quantity, expiry=33, buyer="buyer", price=1):
    return Terms(bytes.fromhex(NETWORK), bytes.fromhex(ident(request)), expiry, (
        Party(address(buyer), bytes.fromhex(BUY), quantity // 10 * price),
        Party(address("maker"), bytes.fromhex(SELL), quantity)))


def reserve(book, request, quantity, tip=BASE, expiry=33):
    return book.reserve(ORDER.order_id, request, ident("request" + request), quantity, expiry, tip,
                        agreement=terms(request, quantity, expiry).encode())


def case():
    # Deliberate wire-shaped unit vectors. Genuine signature/proof acceptance belongs to the wallet/node test.
    import swap_wire_c as c
    agreement = terms(RID, 90)
    legs = [c.LEG + (1).to_bytes(4, "little") + bytes([i]) * (1 + c.CT_PAIR) for i in (1, 2)]
    sigs = [bytes([i]) * c.SIG for i in (3, 4)]
    packet = c.assemble(agreement.network, agreement.commitment(), agreement.expiry, 0, legs, sigs)
    return agreement, legs, sigs, packet


def pin(book, tip, *, agreement=None, legs=None, sig=None, payer=0):
    t, pair, sigs, _ = case()
    t = agreement or t
    return book.pin(ORDER.order_id, RID, t.commitment(), *(legs or pair), sig or sigs[0], payer, tip,
                    agreement=t.encode())


def no(fn, why):
    try:
        fn()
    except ValueError:
        return
    raise AssertionError(why)


def deliberate_exit(stage, dbpath):
    book = Book(dbpath)
    if stage == "pin":
        pin(book, BASE)
    elif stage == "release":
        book.release(ORDER.order_id, RID, case()[-1], BASE)
    else:
        raise ValueError("unknown crash boundary")
    os._exit(19)  # After commit, before application acknowledgment or cleanup.


def run(dbpath, deployment):
    import swap_wire_c as c
    oid = ORDER.order_id
    t, legs, sigs, packet = case()
    signer_identity = sha256(packet).hexdigest()
    with Book(dbpath) as book:
        book.create(ORDER)
        book.create(ORDER)
        for policy in (replace(ORDER, total=110), replace(ORDER, lot=5), replace(ORDER, price=2),
                       replace(ORDER, maker=address("other").hex()), replace(ORDER, asset="03"*32),
                       replace(ORDER, take="03"*32), replace(ORDER, network=ident("other net"))):
            no(lambda: book.create(policy), "immutable order field changed")
        for field in (dict(total=91), dict(lot=0), dict(price=True), dict(price=LIMIT),
                      dict(take=SELL), dict(asset="00"*32), dict(fee=4)):
            no(lambda: replace(ORDER, **field), "failed policy bound")
        book.sync(oid, snapshot(ident("pre-C"), 23))
        no(lambda: reserve(book, RID, 90, ident("pre-C")), "premature C candidate")
        book.sync(oid, snapshot(BASE, 30))
        no(lambda: reserve(book, RID, 15), "fractional lot")
        no(lambda: book.reserve(oid, RID, ident("request"+RID), 90, 33, BASE,
                                agreement=terms(RID, 90, price=2).encode()), "wrong consideration")
        reserve(book, RID, 90)
        assert reserve(book, RID, 90)["state"] == "reserved"
        no(lambda: reserve(book, RID, 80), "same id with different request")
        no(lambda: book.reserve(oid, ident("different request"), ident("other digest"), 10, 33, BASE,
                                agreement=t.encode()), "mismatched agreed quantity")
        no(lambda: pin(book, BASE, agreement=terms(RID, 90, buyer="different buyer")), "different buyer")
        no(lambda: pin(book, BASE, payer=1), "wrong payer")
        no(lambda: pin(book, BASE, legs=[b"SLG2"+legs[0][4:], legs[1]]), "legacy profile in pin")
        assert book.status(oid)["available"] == 10

    # Two independent connections enter the last-lot allocation concurrently.
    gate = threading.Barrier(2)
    def race(name):
        request = ident(name)
        with Book(dbpath) as b:
            gate.wait(timeout=10)
            try:
                reserve(b, request, 10, expiry=31)
                return request
            except ValueError as e:
                assert str(e) == "insufficient available offer quantity"
                return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(race, ("last one", "last two")))
    assert sum(bool(r) for r in results) == 1
    winner = next(r for r in results if r)

    def crash(stage):
        p = subprocess.run([sys.executable, "-IB", str(Path(__file__).resolve()), str(deployment),
                            "--crash", stage, str(dbpath)], check=False)
        assert p.returncode == 19

    crash("pin")
    with Book(dbpath) as book:
        assert book.record(oid, RID)["state"] == "pinned"
        assert book.status(oid)["exposed"] == 90 and book.status(oid)["available"] == 0
        assert book.status(oid)["pinned_uncertain"] == 90 and book.status(oid)["signed_unconfirmed"] == 0
        no(lambda: book.cancel(oid, RID), "cancelled unresolved signature")
        no(lambda: pin(book, BASE, sig=sigs[1]), "changed pinned buyer signature")
        no(lambda: pin(book, BASE, legs=list(reversed(legs))), "changed pinned joint digest")
        no(lambda: book.release(oid, RID, b"SWB2"+packet[4:], BASE), "old envelope")
        wrong = c.assemble(t.network,t.commitment(),t.expiry,0,legs,(sigs[1],sigs[0]))
        no(lambda: book.release(oid,RID,wrong,BASE), "changed buyer signature in complete pair")
        alt = ident("same height fork")
        book.sync(oid, snapshot(alt, 30))
        assert book.record(oid, RID)["pin_tip"] is None
        no(lambda: book.release(oid,RID,packet,BASE), "old branch")
        no(lambda: book.release(oid,RID,packet,alt), "new branch with stale authorization evidence")
        book.sync(oid, snapshot(BASE,30))
        no(lambda: book.release(oid,RID,packet,BASE), "branch ABA restored stale eligibility")
        pin(book, BASE)
    crash("release")
    with Book(dbpath) as book:
        assert book.record(oid,RID)["signed_id"] == signer_identity and book.packet(oid,RID) == packet
        assert book.status(oid)["signed_unconfirmed"] == 90 and book.status(oid)["pinned_uncertain"] == 0
        assert book.release(oid,RID,packet,BASE) == signer_identity
        other_sig = c.assemble(t.network,t.commitment(),t.expiry,0,legs,(sigs[0],sigs[0]))
        no(lambda: book.release(oid,RID,other_sig,BASE), "changed signed packet")
        fork = ident("selected inclusion")
        location = dict(block=fork,height=31,position=1)
        book.sync(oid, snapshot(fork,31,{signer_identity:location}))
        assert book.record(oid,winner)["state"] == "expired" and book.status(oid)["available"] == 10
        assert book.status(oid)["confirmed"] == 90
        assert book.record(oid,RID)["block"] == fork
        no(lambda: book.sync(oid,snapshot(fork,31,{})), "conflicting same-tip membership")
        # Orphan the exact bundle; an alternative packet using the same terms and legs does not settle it.
        alt2 = ident("replacement")
        alt_ident = sha256(other_sig).hexdigest()
        book.sync(oid,snapshot(alt2,31,{alt_ident:dict(block=alt2,height=31,position=0)}))
        record = book.record(oid,RID)
        assert record["state"] == "signed" and record["block"] is None
        assert book.status(oid)["confirmed"] == 0 and book.status(oid)["available"] == 10
        late = ident("late selected tip")
        book.sync(oid,snapshot(late,33))
        assert book.record(oid,RID)["state"] == "expired_signed"
        assert book.status(oid)["signed_unconfirmed"] == 90 and book.status(oid)["pinned_uncertain"] == 0
        assert book.status(oid)["expired_exposure"] == 90 and book.status(oid)["available"] == 10
        no(lambda: reserve(book,ident("unsafe reuse"),20,late,36), "recycled irreversible exposure")
        bad = ident("late inclusion")
        no(lambda: book.sync(oid,snapshot(bad,34,{signer_identity:dict(block=bad,height=34,position=0)})),
           "accepted impossible expired inclusion")
        assert book.status(oid)["tip"] == late, "reconciliation must roll back stale updates"
        book.sync(oid,snapshot(alt2,31,{alt_ident:dict(block=alt2,height=31,position=0)}))
        assert book.record(oid,RID)["state"] == "signed"
        fresh = ident("fresh cancellable request")
        reserve(book,fresh,10,alt2,32)
        book.cancel(oid,fresh)
        book.cancel(oid,fresh)
        no(lambda: reserve(book,fresh,10,alt2,32), "cancelled id revived")
        reserve(book,ident("close reserve"),10,alt2,32)
        book.close(oid)
        book.close(oid)
        assert book.status(oid)["closed"] and book.status(oid)["reserved"] == 0 and book.status(oid)["available"] == 0
        no(lambda: reserve(book,ident("after close"),10,alt2,32), "new fill after closure")
        assert book.record(oid, RID)["state"] == "signed"
        book.sync(oid,snapshot(fork,31,{signer_identity:location}))
        assert book.status(oid)["confirmed"] == 90 and book.status(oid)["exposed"] == 0
        assert book.record(oid,RID)["position"] == 1
    return dict(last_lot_winners=1, pre_release_pin_survived=True, exact_packet_survived=True,
                fork_revival=True, invariant_total=ORDER.total, signature_and_proof_verification="wallet/node scope")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("deployment", type=Path)
    parser.add_argument("--crash", nargs=2, metavar=("STAGE","BOOK"))
    args = parser.parse_args()
    sys.path.insert(0, str(args.deployment.resolve(strict=True)/"devnet"))
    if args.crash:
        deliberate_exit(*args.crash)
    else:
        with tempfile.TemporaryDirectory() as directory:
            print(json.dumps(run(Path(directory)/"inventory.sqlite", args.deployment), sort_keys=True))
