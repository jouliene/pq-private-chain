"""Restore or spend using one backup, a registered wallet installation and a local node."""
import argparse
import json
import os
from pathlib import Path
from hashlib import sha256
import sys


class Incomplete(Exception):
    """The selected verified history does not currently cover the requested tip."""


def wallet_lab(deployment, home, port, target):
    sys.path.insert(0, str(deployment / "devnet"))
    from transport import frame, rpc
    from upgrade_wallet import FundedLab

    class EndpointWallet(FundedLab):
        def request(self, node, op, body=b"", **kwargs):
            if op == "submit":
                status, _ = rpc(port, "status")
                if status["tip"] != target:
                    raise Incomplete("selected endpoint changed before submission")
            self.requests.append(op)
            if op in ("history_head", "history_range", "history_check"):
                # These requests contain only common public cursors, fixed ranges and tip IDs.
                params = {key: value for key, value in kwargs.items() if key != "meter"}
                self.history_trace.update(frame(dict(op=op, **params)))
                shape = self.history_ops.setdefault(op, {"fields": sorted(params), "count": 0})
                if shape["fields"] != sorted(params):
                    raise ValueError("inconsistent public history request fields")
                shape["count"] += 1
            try:
                meta, raw = rpc(port, op, body, **kwargs)
            except ValueError as error:
                if str(error).lower().startswith("incomplete history"):
                    raise Incomplete(str(error)) from error
                raise
            if op == "history_head" and meta["tip"] != target:
                raise Incomplete("selected verified prefix ends before the requested endpoint")
            return meta, raw

    lab = EndpointWallet(home, "B")
    lab.requests = []
    lab.history_trace = sha256()
    lab.history_ops = {}
    return lab


def public_balance(result):
    sync = result["sync"]
    if not sync["complete"]:
        raise Incomplete("wallet has not reached the selected endpoint")
    return dict(complete=True, tip=result["tip"], height=result["height"],
                native=result["balance"], assets=result["assets"], notes=result["notes"],
                sync={k: sync[k] for k in ("start_height", "end_height", "target_tip", "blocks",
                                           "public_requests", "request_B", "reply_B", "public_body_B",
                                           "receipt_rows", "wall_s", "controller_cpu_s", "controller_peak_rss_KiB",
                                           "wallet_db_B", "native_wallet", "native_hash", "deep_resets",
                                           "rewound_blocks", "witness_B", "frontier_B")})


def run(a):
    home = a.wallet_home.resolve()
    deployment = a.deployment.resolve(strict=True)
    if not (deployment / "devnet/b-managed.vk").is_file():
        raise ValueError("select the registered upgraded deployment")
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    from stat import S_IMODE
    if home.stat().st_uid != os.getuid() or S_IMODE(home.stat().st_mode) != 0o700:
        raise ValueError("select a private wallet home")
    if len(bytes.fromhex(a.target)) != 32 or bytes.fromhex(a.target).hex() != a.target:
        raise ValueError("invalid selected target")
    lab = wallet_lab(deployment, home, a.port, a.target)
    owner = "recovered"
    try:
        if a.action == "restore":
            value = lab.restore(owner, a.seed, "c")
            record = public_balance(value)
        elif a.action in ("balance", "reconcile"):
            record = public_balance(lab.balance(owner, "c"))
        elif a.action == "confirm":
            # Confirm only a previously admitted tx actually present in selected history.
            # Calling resume here could produce or transmit a replacement on a different branch.
            from intents import Outbox
            from wallet_sync import synced_wallet
            with lab.locked_wallet(owner) as directory, Outbox(directory) as out, lab.wallet(owner) as w:
                with synced_wallet(lab, "c", w, directory) as (state, sync):
                    found = [item["tx"] for item in out.attempts(a.intent)
                             if state.has_payment(bytes.fromhex(item["tx"]))]
                    if len(found) != 1 or state.tip.hex() != a.target or not sync["complete"]:
                        raise ValueError("intent has no unique confirmed payment on the selected branch")
                    record = dict(complete=True, tx=found[0], tip=state.tip.hex(), height=state.height,
                                  native=state.inventory()["balance"], assets=state.inventory()["assets"])
        else:
            balance = public_balance(lab.balance(owner, "c"))
            if balance["tip"] != a.target:
                raise Incomplete("wrong wallet endpoint for spend")
            if balance["native"] != 34 or balance["assets"] != {a.asset: 28} or balance["notes"] != 2:
                raise ValueError("expected both genuine funded receipts before authorizing")
            tx = lab.send(owner, "@" + str(a.address.resolve(strict=True)), 28, a.asset, 25, "c", a.intent)
            if tx["status"] != "submitted" or tx["real_inputs"] != 2 or tx["fee"] != 3:
                raise ValueError("restored wallet did not submit the required two-input payment")
            record = {k: tx[k] for k in ("tx", "real_inputs", "fee", "packet_B", "change", "token_change",
                                        "anchor_height", "proving_wall_s", "prover_cpu_s",
                                        "prover_role_peak_rss_KiB", "submission_frame")}
            record.update(complete=True, tip=balance["tip"], height=balance["height"])
        if record["tip"] != a.target:
            raise Incomplete("wallet did not reach requested endpoint")
        record["public_history_queries_sha256"] = lab.history_trace.hexdigest()
        record["public_history_query_shapes"] = lab.history_ops
        return record
    except Incomplete as error:
        status = lab.status("c")
        return dict(complete=False, requested=a.target, reason=str(error), height=status["height"],
                    tip=status["tip"], submitted="submit" in lab.requests)


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("deployment", type=Path)
    p.add_argument("wallet_home", type=Path)
    p.add_argument("port", type=lambda endpoint: int(endpoint) if endpoint.isdecimal() else Path(endpoint),
                   help="loopback TCP port or local Unix socket path")
    p.add_argument("target")
    actions = p.add_subparsers(dest="action", required=True)
    actions.add_parser("restore").add_argument("--seed", type=Path, required=True)
    actions.add_parser("balance")
    actions.add_parser("reconcile")
    actions.add_parser("confirm").add_argument("--intent", required=True)
    spend = actions.add_parser("spend")
    spend.add_argument("--address", type=Path, required=True)
    spend.add_argument("--asset", required=True)
    spend.add_argument("--intent", required=True)
    print(json.dumps(run(p.parse_args()), sort_keys=True))


if __name__ == "__main__":
    main()
