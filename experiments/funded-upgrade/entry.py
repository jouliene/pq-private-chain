"""Operate an existing scheduled-upgrade wallet on its selected funded network."""
import argparse
import os
from pathlib import Path
import sys


def main():
    p = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    p.add_argument("--home", type=Path)
    args, _ = p.parse_known_args()
    if args.home is None:
        p.error("usage: pqd upgrade --home HOME [--node a|b|c|d] [--suite auto|A|B] COMMAND ...")
    installed = args.home.resolve() / "deployment/devnet/upgrade_wallet.py"
    if not installed.is_file():
        p.error("select a home with the funded upgrade installed")
    os.execv(sys.executable, [sys.executable, "-IB", str(installed), *sys.argv[1:]])


if __name__ == "__main__":
    main()
