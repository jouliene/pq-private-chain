"""Reject mismatched public deployment parameters using isolated copies of real keys."""

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check import LAYERS, check, inspect


def run(registry, approved, stock):
    clean, _ = check(registry, approved)
    failures = {}

    def reject(label, mutation):
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp)
            for name in LAYERS:
                for ext in ("vk", "common", "only"):
                    shutil.copyfile(registry/f"{name}.{ext}", copy/f"{name}.{ext}")
            shutil.copyfile(registry/"profile.json", copy/"profile.json")
            mutation(copy)
            try:
                check(copy, approved)
            except ValueError as e:
                failures[label] = str(e)
            else:
                raise AssertionError(f"accepted {label}")

    def change_cap(copy):
        a = bytearray((copy/"wallet.only").read_bytes())
        a[8] ^= 1
        (copy/"wallet.only").write_bytes(a)
        (copy/"wallet.vk").write_bytes(a+(copy/"wallet.common").read_bytes())

    def substitute_stock(copy):
        raw = stock.read_bytes()
        _, only, common = inspect("wallet", raw, stock=True)
        for ext, data in (("vk",raw),("only",only),("common",common)):
            (copy/f"wallet.{ext}").write_bytes(data)

    def wrong_layout(copy):
        for ext in ("vk", "common", "only"):
            shutil.copyfile(copy/f"outer3.{ext}", copy/f"outer2.{ext}")

    reject("unapproved manifest bytes",
           lambda copy: (copy/"profile.json").write_bytes((copy/"profile.json").read_bytes()+b"\n"))
    reject("stock wallet profile", substitute_stock)
    reject("different circuit-specific cap, coherent files", change_cap)
    reject("substituted arity", wrong_layout)
    reject("mismatched separate common",
           lambda copy: shutil.copyfile(copy/"outer3.common", copy/"outer2.common"))
    try:
        check(registry, "0"*64)
    except ValueError as e:
        failures["incorrect external approval"] = str(e)
    else:
        raise AssertionError("accepted unapproved registry")
    assert check(registry, approved)[0] == clean
    return dict(approved_manifest_sha256=approved, rejected=failures,
                registration_rechecked_after_control=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("registry", type=Path)
    p.add_argument("approved_manifest_sha256")
    p.add_argument("stock", type=Path)
    args = p.parse_args()
    print(json.dumps(run(args.registry, args.approved_manifest_sha256, args.stock),
                     indent=2, sort_keys=True))
