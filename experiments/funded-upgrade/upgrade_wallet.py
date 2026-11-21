"""Wallet interface for upgraded deployments with branch-height selection and an overlap override."""
import argparse
import json
import os
from pathlib import Path
import sys

DEV = Path(__file__).resolve().parent
sys.path.insert(0, str(DEV))
import chain  # Initialize the installed public-role module paths.
from cli import Lab, NODES
from upgrade_rules import FIRST_B, permitted
from wallet import Wallet


class BWallet(Wallet):
    proof_magic = b"MNG2\x01"

    @staticmethod
    def check_keys(keys):
        key = keys / "managed.vk"
        if (keys.is_symlink() or key.is_symlink() or set(keys.iterdir()) != {key}
                or key.read_bytes() != (DEV / "b-managed.vk").read_bytes()):
            raise ValueError("unapproved B ordinary wallet key")
        return keys


class FundedLab(Lab):
    def __init__(self, home, suite):
        super().__init__(home, DEV.parent / "runtime")
        self.use_b = suite == "B"

    def wallet(self, name, mode="restore"):
        if not self.use_b:
            return super().wallet(name, mode)
        runtime = DEV.parent / "b-runtime"
        binary = runtime / "native"
        if runtime.is_symlink() or binary.is_symlink():
            raise ValueError("unapproved B wallet executable")
        pin = (DEV / "approved-b-native.sha256").read_text().strip()
        return BWallet(binary, pin, DEV.parent / "b-keys", self.walletdir(name), mode)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--node", choices=NODES, default="c")
    parser.add_argument("--suite", choices=("A", "B", "auto"), default="auto")
    parser.add_argument("action", choices=("send", "resume", "restore", "balance", "terms", "leg", "authorize", "abort", "combine"))
    parser.add_argument("args", nargs=argparse.REMAINDER)
    a = parser.parse_args()
    home = a.home.resolve()
    if home / "deployment/devnet" != DEV:
        raise ValueError("wallet installation differs from selected deployment")
    lab = FundedLab(home, "A")
    height = lab.status(a.node)["height"] + 1
    suite = ("B" if height >= FIRST_B else "A") if a.suite == "auto" else a.suite
    if a.action not in ("abort", "balance", "restore", "resume"):
        permitted(suite == "B", height)
    lab.use_b = suite == "B"
    if a.action in ("terms", "leg", "authorize", "combine", "abort"):
        if lab.use_b:
            import swap_b_wallet as policy
        else:
            import swap_wallet as policy
        args = a.args + (["--node", a.node] if a.action in ("leg", "authorize", "abort") else [])
        policy.main(home, a.action, args)
        return
    p = argparse.ArgumentParser(prog=a.action)
    p.add_argument("owner")
    if a.action in ("send", "resume"):
        if a.action == "send":
            p.add_argument("recipient")
            p.add_argument("native", type=int)
            p.add_argument("asset")
            p.add_argument("quantity", type=int)
        p.add_argument("--intent", required=True)
    elif a.action == "restore":
        p.add_argument("backup", type=Path)
    args = p.parse_args(a.args)
    if a.action == "send":
        result = lab.send(args.owner, args.recipient, args.native, args.asset, args.quantity, a.node, args.intent)
    elif a.action == "resume":
        from intents import Outbox
        with lab.locked_wallet(args.owner) as directory, Outbox(directory) as book:
            operation = book.get(args.intent)["operation"]
        if operation == "transfer":
            permitted(lab.use_b, height)
        else:
            if a.suite == "B":
                raise ValueError("registered supply operations require suite A")
            lab.use_b = False
        result = lab.resume(args.owner, args.intent, a.node)
    elif a.action == "restore":
        result = lab.restore(args.owner, args.backup, a.node)
    else:
        result = lab.balance(args.owner, a.node)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
