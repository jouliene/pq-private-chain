"""Durable local redemption coordinator and independent simulated-bank ledger."""
import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import sys

CONFIRMATIONS = 3
LIMIT = (1 << 62) - 1


def need(condition, message):
    if not condition:
        raise ValueError(message)


def word(text):
    need(isinstance(text, str) and re.fullmatch("[0-9a-f]{64}", text), "expected canonical 32-byte hex ID")
    return bytes.fromhex(text)


def label(text):
    need(isinstance(text, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", text),
         "request and payee labels must be 1..80 canonical ASCII label characters")
    return text


def open_private(path):
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        mode = os.fstat(fd)
        need(stat.S_ISREG(mode.st_mode) and mode.st_uid == os.geteuid() and not mode.st_mode & 0o077,
             "unsafe redemption database permissions")
    finally:
        os.close(fd)
    db = sqlite3.connect(path, timeout=45)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA synchronous=FULL")
    return db


def bank_key(network, request):
    return hashlib.sha256(b"MNG1/redemption-bank/v1\0" + network + request.encode("ascii")).hexdigest()


class Service:
    def __init__(self, coordinator, bank, network):
        self.db, self.bank, self.network = coordinator, bank, network
        coordinator.executescript("""
            CREATE TABLE IF NOT EXISTS requests(
                request TEXT PRIMARY KEY, network BLOB NOT NULL, treasury TEXT NOT NULL, asset BLOB NOT NULL,
                amount INTEGER NOT NULL, return_tx BLOB NOT NULL, payee TEXT NOT NULL, return_nf BLOB NOT NULL,
                acknowledged TEXT, UNIQUE(network,return_tx), UNIQUE(network,return_nf));
            CREATE TABLE IF NOT EXISTS attempts(
                tx TEXT PRIMARY KEY, request TEXT NOT NULL REFERENCES requests(request),
                first_block TEXT NOT NULL, first_height INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS request_attempts ON attempts(request);
        """)
        bank.execute("""CREATE TABLE IF NOT EXISTS payments(
            business_key TEXT PRIMARY KEY, network BLOB NOT NULL, request TEXT NOT NULL, payee TEXT NOT NULL,
            asset BLOB NOT NULL, amount INTEGER NOT NULL, receipt TEXT UNIQUE NOT NULL,
            UNIQUE(network,request))""")

    def request(self, name):
        row = self.db.execute("SELECT * FROM requests WHERE request=?", (label(name),)).fetchone()
        need(row is not None, "unknown redemption request")
        need(row["network"] == self.network, "redemption request belongs to a different network")
        return row

    def enroll(self, name, treasury, asset, amount, return_tx, payee, open_return):
        name, payee = label(name), label(payee)
        need(type(amount) == int and 0 < amount <= LIMIT and len(asset) == len(return_tx) == 32
             and asset != bytes(32) and return_tx != bytes(32) and all(v < 128 for v in asset[7::8]),
             "invalid redemption quantity, asset or return")
        fields = (self.network, treasury, asset, amount, return_tx, payee)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            existing = self.db.execute("SELECT network,treasury,asset,amount,return_tx,payee FROM requests "
                                       "WHERE request=?", (name,)).fetchone()
            if existing:
                need(tuple(existing) == fields, "request already binds different redemption terms")
                return
            nf = open_return()
            need(isinstance(nf, bytes) and len(nf) == 32, "missing private treasury funding identity")
            try:
                self.db.execute("INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,NULL)", (name, *fields, nf))
            except sqlite3.IntegrityError as err:
                raise ValueError("return already assigned to a redemption request") from err

    def candidate_ids(self, name):
        return [r[0] for r in self.db.execute("SELECT tx FROM attempts WHERE request=? ORDER BY rowid", (name,))]

    def inspect(self, row, ids, observe):
        """All attempts must be observed against the same selected head."""
        for _ in range(4):
            tip = None
            height = None
            matched = {}
            # Empty status uses the selected head without supplying a fake burn ID.
            batches = [ids[i:i+8] for i in range(0, len(ids), 8)] or [[]]
            for batch in batches:
                page = observe(batch)
                word(page["tip"])
                h = page["height"]
                need(type(h) == int and h >= 0 and len(page["events"]) == len(batch), "invalid selected observation")
                if tip is None:
                    tip, height = page["tip"], h
                elif (tip, height) != (page["tip"], h):
                    break
                for tx, event in zip(batch, page["events"], strict=True):
                    if event is None:
                        continue
                    need(event["tx"] == tx and event["op"] == "burn" and event["asset"] == row["asset"].hex()
                         and type(event["quantity"]) == int and event["quantity"] == row["amount"]
                         and isinstance(event["nfs"], list) and len(event["nfs"]) == 2
                         and row["return_nf"] in [word(nf) for nf in event["nfs"]],
                         "selected event does not burn this request's exact return")
                    word(event["block"])
                    need(type(event["height"]) == type(event["confirmations"]) == int and 1 <= event["height"] <= h
                         and event["confirmations"] == h - event["height"] + 1, "invalid selected confirmation depth")
                    matched[tx] = event
            else:
                need(len(matched) <= 1, "multiple selected burns for the same return")
                return tip, height, matched
        raise ValueError("selected chain changed repeatedly while checking redemption attempts")

    def receipt(self, row, *, pay=False):
        """The bank rechecks the immutable terms on every call, including a retry after a crash."""
        key = bank_key(self.network, row["request"])
        terms = (self.network, row["request"], row["payee"], row["asset"], row["amount"])
        created = False
        with self.bank:
            if pay:
                self.bank.execute("BEGIN IMMEDIATE")
                inserted = self.bank.execute("INSERT INTO payments VALUES(?,?,?,?,?,?,?) "
                                             "ON CONFLICT(business_key) DO NOTHING",
                                             (key, *terms, secrets.token_hex(16)))
                created = inserted.rowcount == 1
            receipt = self.bank.execute("SELECT network,request,payee,asset,amount,receipt FROM payments "
                                        "WHERE business_key=?", (key,)).fetchone()
            if receipt is not None:
                need(tuple(receipt)[:5] == terms, "bank receipt binds different redemption terms")
        return (receipt["receipt"] if receipt is not None else None), created

    def reconcile(self, name, observe, candidate=None, crash_after_bank=False):
        row = self.request(name)
        if candidate is not None:
            word(candidate)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            known = self.candidate_ids(name)
            fresh = candidate is not None and candidate not in known
            ids = known + ([candidate] if fresh else [])
            tip, height, matched = self.inspect(row, ids, observe)
            if fresh:
                need(candidate in matched, "candidate burn is absent from the selected chain")
                event = matched[candidate]
                self.db.execute("INSERT INTO attempts VALUES(?,?,?,?)", (candidate, name, event["block"], event["height"]))
        # Persist the verified candidate before any external bank effect. The bank's
        # uniqueness handles concurrent callers after this coordinator commit.
        tx, event = next(iter(matched.items()), (None, None))
        depth = event["confirmations"] if event else 0
        can_pay = candidate is not None and candidate == tx and depth >= CONFIRMATIONS
        receipt, created = self.receipt(row, pay=can_pay)
        if created and crash_after_bank:
            os._exit(75)
        if receipt:
            with self.db:
                self.db.execute("UPDATE requests SET acknowledged=? WHERE request=? AND acknowledged IS NULL",
                                (receipt, name))
                need(self.request(name)["acknowledged"] == receipt, "coordinator and bank disagree on payout receipt")
        paid = row["amount"] if receipt else 0
        return dict(request=name, asset=row["asset"].hex(), amount=row["amount"], tip=tip, height=height,
                    selected_burn=tx, confirmations=depth, threshold=CONFIRMATIONS,
                    paid=paid, owed=row["amount"]-paid, exposure=(paid if tx is None else 0),
                    payout_count=int(receipt is not None), bank_receipt=receipt, attempts=len(ids))


def parse_cli():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("home", type=Path)
    actions = p.add_subparsers(dest="action", required=True)
    for action in ("enroll", "settle", "status"):
        cmd = actions.add_parser(action)
        cmd.add_argument("request")
        cmd.add_argument("--node", choices=list("abcd"), default="c")
        if action == "enroll":
            cmd.add_argument("treasury")
            cmd.add_argument("asset")
            cmd.add_argument("amount", type=int)
            cmd.add_argument("return_tx")
            cmd.add_argument("payee")
        elif action == "settle":
            cmd.add_argument("burn_tx")
            cmd.add_argument("--crash-after-bank", action="store_true")
    return p.parse_args()


def main():
    os.umask(0o077)
    args = parse_cli()
    home = args.home.resolve(strict=True)
    sys.path.insert(0, str(home / "deployment/devnet"))
    from wallet import private_directory
    from wallet_sync import synced_wallet
    from redemption import return_commitment
    from cli import Lab
    from chain import NETWORK
    lab = Lab(home, home/"deployment/runtime")
    directory = private_directory(home/"redemptions", create=True)
    def observe(ids):
        if not ids:
            status = lab.status(args.node)
            return dict(tip=status["tip"], height=status["height"], events=[])
        meta, body = lab.request(args.node, "supply-observation", txs=ids)
        need(not body, "unexpected redemption observation payload")
        return meta
    with closing(open_private(directory/"requests.sqlite")) as local, closing(open_private(directory/"bank.sqlite")) as bank:
        svc = Service(local, bank, NETWORK)
        if args.action == "enroll":
            asset, tx = word(args.asset), word(args.return_tx)
            def open_return():
                with lab.locked_wallet(args.treasury) as private, lab.wallet(args.treasury) as wallet:
                    with synced_wallet(lab, args.node, wallet, private) as (state, _):
                        with state.transaction(False):
                            cm = return_commitment(state.db, tx, asset, args.amount)
                            return state.db.execute("SELECT nf FROM owned WHERE cm=?", (cm,)).fetchone()[0]
            svc.enroll(args.request, args.treasury, asset, args.amount, tx, args.payee, open_return)
        result = svc.reconcile(args.request, observe, getattr(args, "burn_tx", None), getattr(args, "crash_after_bank", False))
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, RuntimeError, sqlite3.Error) as err:
        sys.exit(str(err))
