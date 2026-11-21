"""Use the registered wallet selected by candidate height, including managed supply."""
import argparse
import json
import os
from pathlib import Path
import sys

DEV = Path(__file__).resolve().parent
sys.path.insert(0, str(DEV))
import chain
from cli import NODES
from consensus import FIRST_C
from upgrade_rules import FIRST_B, permitted
from wallet_c import FundedLab

SUPPLY = ("issue", "register", "mint", "burn")
SWAP = ("terms", "leg", "authorize", "abort", "combine")


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--home", type=Path, required=True)
    p.add_argument("--node", choices=NODES, default="c")
    p.add_argument("--suite", choices=("auto", "A", "B", "C"), default="auto")
    p.add_argument("action", choices=("send","resume","balance","restore",*SUPPLY,*SWAP))
    p.add_argument("args", nargs=argparse.REMAINDER)
    a = p.parse_args()
    home = a.home.resolve()
    if home/"deployment/devnet" != DEV:
        raise ValueError("wallet deployment mismatch")
    old = FundedLab(home,"A")
    h = old.status(a.node)["height"] + 1
    action = a.action
    supply = action in SUPPLY
    if action not in SWAP:
        arg = argparse.ArgumentParser(prog=action)
        arg.add_argument("owner")
        if action in ("mint","send"):
            arg.add_argument("recipient")
        if action == "send":
            arg.add_argument("native", type=int)
        if action in ("send","mint","burn"):
            arg.add_argument("asset")
        if action in ("send",*SUPPLY):
            arg.add_argument("quantity", type=int)
        if action == "burn":
            arg.add_argument("return_tx")
        if action == "restore":
            arg.add_argument("backup",type=Path)
        if action in ("send","resume",*SUPPLY):
            arg.add_argument("--intent",required=True)
        op = arg.parse_args(a.args)
        if action == "resume":
            from intents import Outbox
            with old.locked_wallet(op.owner) as directory, Outbox(directory) as book:
                supply = book.get(op.intent)["operation"] != "transfer"
    suite = a.suite
    if suite == "auto":
        suite = "C" if h >= FIRST_C else ("A" if supply or h < FIRST_B else "B")
    if action not in ("restore","balance","abort"):
        if (suite=="C") != (h >= FIRST_C) or (supply and suite=="B"):
            raise ValueError("inactive proof suite")
        if suite!="C" and not supply:
            permitted(suite=="B",h)
    lab = FundedLab(home,suite)
    if action in SWAP:
        import importlib
        policy = importlib.import_module({"A":"swap_wallet","B":"swap_b_wallet","C":"swap_c_wallet"}[suite])
        policy.main(home,action,a.args+(["--node",a.node] if action in ("leg","authorize","abort") else []))
        return
    if action == "send":
        result = lab.send(op.owner,op.recipient,op.native,op.asset,op.quantity,a.node,op.intent)
    elif action == "mint":
        result = lab.mint(op.owner,op.recipient,op.asset,op.quantity,a.node,op.intent)
    elif action == "burn":
        result = lab.burn(op.owner,op.asset,op.quantity,op.return_tx,a.node,op.intent)
    elif action in ("register","issue"):
        result = getattr(lab,action)(op.owner,op.quantity,a.node,op.intent)
    elif action == "resume":
        result = lab.resume(op.owner,op.intent,a.node)
    elif action == "restore":
        result = lab.restore(op.owner,op.backup,a.node)
    else:
        result = lab.balance(op.owner,a.node)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
