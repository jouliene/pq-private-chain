"""Validate the managed staging, real SQLite journal and request calculations without native proving."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
AST = HERE.parents[1] / "user-assets"
sys.path.insert(0, str(HERE))
from check_return import check as check_return, reject
from stage import stage_wallet


def install_ast(dev_root):
    spec = importlib.util.spec_from_file_location("baseline_ast_install", AST / "stage.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    dev = module.install_sources(dev_root)
    # Staging-only checks use the genuine base key for the base runtime's CLI imports.
    shutil.copyfile(AST / "native/registry/asset.vk", dev / "asset.vk")
    stage_wallet(dev)
    return dev


def check():
    check_return()
    with tempfile.TemporaryDirectory() as temp:
        dev = install_ast(Path(temp))
        for op in ("register", "mint", "burn", "issue", "send", "resume"):
            subprocess.run([sys.executable, "-IB", dev / "cli.py", op, "--help"],
                           stdout=subprocess.DEVNULL, check=True)
        sys.path.insert(0, str(dev))
        from asset_wallet import select_amounts
        from intents import Outbox
        from managed_wallet import BURN, Request, ZERO, bind_parent, change_for, default_id
        from dataclasses import replace
        asset, tx, other = bytes([2])*32, bytes([1])*32, bytes([11])*32
        address = bytes(1601)
        mint = Request(0, asset, 10, 10, "mint", sequence=1, previous=tx)
        reg = Request(0, ZERO, 1000, 1000, "register")
        burn = Request(0, asset, 0, BURN+4, "burn", return_tx=tx)
        assert change_for(burn, 3, 4) == (0, 0)
        assert change_for(burn, 2, 4) is None and change_for(burn, 3, 3) is None
        assert change_for(reg, 25, 0) == (22, 0)
        assert change_for(mint, 7, 0) == (4, 0)
        cm_n, cm_t = bytes([1])*32, bytes([2])*32
        rows = [(cm_n, 10, ZERO, 0), (cm_t, 12, asset, 20)]
        assert select_amounts(rows, mint, lambda _: False) == (cm_n.hex(),)
        reject(select_amounts, rows[1:], mint, lambda _: False)
        reject(Request, 0, asset, 0, BURN, "burn", tx)
        reject(Request, 1, asset, 0, BURN+4, "burn", tx)
        reject(Request, 0, asset, 0, BURN+4, "burn", ZERO)
        reject(Request, 0, asset, 10, 10, "fixed")
        reject(Request, 0, asset, 0, BURN+4, "mint", tx)
        reject(Request, 0, asset, 10, 10, "mint", ZERO, 0, tx)
        assert default_id(address, burn) != default_id(address, replace(burn, return_tx=other))
        assert default_id(address, reg) != default_id(address, Request.issue(1000))
        with Outbox(dev) as book:
            for req in (reg, mint, burn, Request.issue(1000), Request(1, ZERO, 0)):
                book.register(default_id(address, req), address, req)
            reject(book.register, default_id(address, mint), address, replace(mint, sequence=2, previous=other))
            reject(book.register, default_id(address, burn), address, replace(burn, return_tx=other))
        with Outbox(dev) as book:
            ident = default_id(address, mint)
            assert Request.from_row(book.get(ident)) == mint
            # Existing intents must preserve their parent even with no registry connection.
            assert bind_parent(None, None, book, ident, replace(mint, sequence=0, previous=ZERO)) == mint
            assert book.summary(ident)["previous"] == tx.hex()
    print("PASS: ordinary staged CLI, managed/fixed intent separation, persisted authorization parent, return context and burn/fee equations")


if __name__ == "__main__":
    check()
