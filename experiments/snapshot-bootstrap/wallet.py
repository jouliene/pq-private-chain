"""Recover the offline profile-C wallet from a seed and shared selected receipt history."""
import argparse
from contextlib import closing
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
from stat import S_IMODE

import sys


OWNER = "recovered"
MISSING = "snapshot wallet history unavailable"


class Incomplete(Exception):
    """The node lacks the common history required for the requested endpoint."""


def digest(text):
    if len(text) != 64 or bytes.fromhex(text).hex() != text:
        raise ValueError("expected a canonical 32-byte digest")
    return text


def read_only(path):
    return sqlite3.connect(path.resolve(strict=True).as_uri() + "?mode=ro", uri=True)


def wallet_lab(deployment, home, endpoint, target):
    sys.path.insert(0, str(deployment / "devnet"))
    import chain  # The deployment initializes the registered public-role import paths.
    from transport import frame, rpc
    from wallet_c import FundedLab

    class EndpointWallet(FundedLab):
        def request(self, node, op, body=b"", **kwargs):
            if op == "submit":
                # Outbox.prepare has durably bound the exact source and packet. Check
                # the actual journal under the caller's wallet lock before forwarding.
                with closing(read_only(self.walletdir(OWNER) / "mng1-intents.sqlite")) as db:
                    row = db.execute("SELECT i.pinned,a.packet FROM intents i JOIN attempts a "
                                     "ON a.intent=i.id WHERE i.id=? AND a.tx=?",
                                     (self.intent, sha256(body).hexdigest())).fetchone()
                if (row is None or json.loads(row[0]) != [self.source] or row[1] != body
                        or body[:5] != b"MSP3\x01"):
                    raise ValueError("outbox did not pin the expected receipt and C payment")
                if self.status(node)["tip"] != target:
                    raise Incomplete("selected endpoint changed before submission")
                self.submitted = True
            if op not in ("history_head", "history_range", "history_check"):
                return rpc(endpoint, op, body, **kwargs)
            meter = kwargs.pop("meter", {})
            if body:
                raise ValueError("unexpected history request body")
            self.trace.update(frame(dict(op=op, **kwargs)))
            shape = self.shapes.setdefault(op, dict(fields=sorted(kwargs), count=0))
            if shape["fields"] != sorted(kwargs):
                raise ValueError("inconsistent public history request fields")
            shape["count"] += 1
            try:
                meta, raw = rpc(endpoint, op, meter=meter, **kwargs)
            except ValueError as error:
                if op == "history_range" and str(error) == MISSING:
                    raise Incomplete(MISSING) from error
                raise
            finally:
                self.query_B += meter.get("request_B", 0)
                self.reply_B += meter.get("reply_B", 0)
            if op == "history_head" and meta["tip"] != target:
                raise Incomplete("selected endpoint differs from requested tip")
            return meta, raw

    lab = EndpointWallet(home, "C")
    lab.trace, lab.shapes = sha256(), {}
    lab.query_B = lab.reply_B = 0
    lab.submitted = False
    return lab


def checked_inventory(lab, result, target):
    sync = result["sync"]
    if not sync["complete"] or result["tip"] != target:
        raise Incomplete("wallet has not reached the requested endpoint")
    with lab.locked_wallet(OWNER) as directory, closing(read_only(directory / "mng1-wallet-state.sqlite")) as db:
        db.execute("BEGIN")
        row = db.execute("SELECT id,h FROM heads ORDER BY h DESC LIMIT 1").fetchone()
        if row != (bytes.fromhex(target), result["height"]):
            raise Incomplete("wallet moved before reading its receipts")
        receipts = [
            dict(commitment=cm.hex(), creator_tx=creator.hex() if creator else None,
                 creation_height=height, native=amount, token=token, asset_id=asset.hex(),
                 spent_height=spent, spender_tx=spender.hex() if spender else None)
            for cm, creator, height, amount, token, asset, spent, spender in db.execute(
                "SELECT cm,creator,created,amount,token,asset,spent,spender FROM owned "
                "WHERE amount>0 OR token>0 ORDER BY pos")
        ]
    return dict(complete=True, tip=target, height=result["height"], native=result["balance"],
                assets=result["assets"], notes=result["notes"], owned=receipts, sync=sync)


def run(a):
    deployment = a.deployment.resolve(strict=True)
    if not (deployment / "devnet/c-managed.vk").is_file():
        raise ValueError("select the registered profile-C deployment")
    home = a.wallet_home.absolute()
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    if home.is_symlink() or home.stat().st_uid != os.geteuid() or S_IMODE(home.stat().st_mode) != 0o700:
        raise ValueError("expected an owner-only private wallet home")
    target = getattr(a, "tip", None)
    lab = wallet_lab(deployment, home, getattr(a, "socket", None), target)
    if a.action == "init":
        lab.new_wallet(OWNER)
        lab.backup(OWNER, a.backup)
        address = lab.export_address(OWNER, a.address)
        return dict(offline=True, seed_B=a.backup.stat().st_size, address_B=address["bytes"],
                    address_sha256=sha256(a.address.read_bytes()).hexdigest())
    try:
        if a.action == "restore":
            value = lab.restore(OWNER, a.backup, "c")
        else:
            value = lab.balance(OWNER, "c")
        record = checked_inventory(lab, value, target)
        if a.action == "spend":
            live = [row for row in record["owned"] if row["spent_height"] is None]
            if (len(live) != 1 or live[0]["creator_tx"] != a.funding_tx or live[0]["native"] != 17
                    or live[0]["token"] or live[0]["asset_id"] != "00"*32
                    or (record["native"], record["assets"], record["notes"]) != (17, {}, 1)):
                raise ValueError("expected one live 17-native note from the specified funding payment")
            lab.source, lab.intent = live[0]["commitment"], a.intent
            destination = "@" + str(a.address.resolve(strict=True))
            if lab.destination(destination) == lab.address(OWNER):
                raise ValueError("the onward recipient must be a different wallet")
            tx = lab.send(OWNER, destination, 11, "native", 0, "c", a.intent)
            if ((tx["status"], tx["real_inputs"], tx["fee"], tx["change"], tx["input_total"],
                 tx["token_change"]) != ("submitted", 1, 3, 3, 17, 0) or not lab.submitted):
                raise ValueError("the funded C payment did not obtain the expected admission")
            record = {k: tx[k] for k in ("tx", "real_inputs", "fee", "packet_B", "change",
                                        "anchor_height", "proving_wall_s", "prover_cpu_s",
                                        "prover_role_peak_rss_KiB", "submission_frame")}
            record.update(complete=True, tip=target, height=value["height"], source_tx=a.funding_tx,
                          source_cm=lab.source, source_height=live[0]["creation_height"])
    except Incomplete as error:
        status = lab.status("c")
        record = dict(complete=False, reason=str(error), requested=target,
                      tip=status["tip"], height=status["height"])
    record.update(submitted=lab.submitted, public_history_queries_sha256=lab.trace.hexdigest(),
                  public_history_query_shapes=lab.shapes, history_request_B=lab.query_B,
                  history_reply_B=lab.reply_B)
    return record


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("deployment", type=Path)
    parser.add_argument("wallet_home", type=Path)
    actions = parser.add_subparsers(dest="action", required=True)
    init = actions.add_parser("init")
    init.add_argument("--backup", type=Path, required=True)
    init.add_argument("--address", type=Path, required=True)
    rpc_args = argparse.ArgumentParser(add_help=False)
    rpc_args.add_argument("--socket", type=Path, required=True)
    rpc_args.add_argument("--tip", type=digest, required=True)
    restore = actions.add_parser("restore", parents=[rpc_args])
    restore.add_argument("--backup", type=Path, required=True)
    actions.add_parser("balance", parents=[rpc_args])
    spend = actions.add_parser("spend", parents=[rpc_args])
    spend.add_argument("--funding-tx", type=digest, required=True)
    spend.add_argument("--address", type=Path, required=True)
    spend.add_argument("--intent", required=True)
    print(json.dumps(run(parser.parse_args()), sort_keys=True))


if __name__ == "__main__":
    main()
