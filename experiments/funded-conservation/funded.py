"""Repeat the historical two-real-input ordinary payment with independently generated wallet seeds."""
from hashlib import sha256
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from audit import HISTORIC_BLOCK, HISTORIC_TX, inspect
sys.path.insert(0, str(HERE.parent / "partial-fills"))
from prepare import HISTORIC_TIP, agree, cli, load_lab, need


def run(out):
    home = out / "network"
    deployment = home / "deployment"
    lab = load_lab(home)
    from chain import GENESIS, block_id, decode_block

    try:
        lab.start(manual=True)
        tip = bytes.fromhex(HISTORIC_TIP)
        prefix = []
        while tip != GENESIS:
            raw = (out / "history/public/blocks" / (tip.hex()+".bin")).read_bytes()
            need(block_id(raw) == tip, "public history identity")
            prefix.append(raw)
            tip = decode_block(raw).parent
        for raw in reversed(prefix):
            lab.request("a", "publish", raw)
        agree(lab, HISTORIC_TIP)
        database = home / "nodes/c/chain.sqlite"
        original = inspect(deployment, database, HISTORIC_TX)
        need(original["block"] == HISTORIC_BLOCK and original["height"] == 25, "fixed historical selection")
        for owner in ("payer", "payee"):
            lab.new_wallet(owner)
            lab.backup(owner, out / (owner+".backup"))
            lab.export_address(owner, out / (owner+".addr"))

        def mine(count):
            tip = lab.mine("a", count, pay_to="miner-a")["tip"]
            agree(lab, tip)
            return tip

        def confirm(action, sender, label, *args):
            receipt = cli(home, "b", action, sender, *args, "--intent", label)
            tip = mine(1)
            packet, = decode_block(lab.request("c", "block", id=tip)[1]).packets
            need(sha256(packet).hexdigest() == receipt["tx"], "fresh selected packet identity")
            return receipt

        mine(3)
        asset = confirm("issue", "miner-a", "issue-fixture", 100)["asset_id"]
        for cash, quantity in ((20,12), (14,16)):
            confirm("send", "miner-a", f"fund-{quantity}", "@"+str(out/"payer.addr"), cash, asset, quantity)
        payment = confirm("send", "payer", "ordinary-transfer", "@"+str(out/"payee.addr"), 28, asset, 25)
        result = inspect(deployment, database, payment["tx"], (out/"payer.backup", out/"payee.backup"))
        need(result["test_asset"] == asset and result["height"] == 40, "fresh experiment shape")
        for owner, native, quantity in (("payee",28,25), ("payer",3,3)):
            balance = cli(home, "c", "balance", owner)
            need(balance["balance"] == native and balance["assets"] == {asset:quantity}, "selected wallet balances")
        evidence = {"historical_public":original, "fresh_opened":result}
        (out/"result.json").write_text(json.dumps(evidence, indent=2, sort_keys=True)+"\n")
        print(json.dumps(evidence, indent=2, sort_keys=True))
    finally:
        lab.stop()


if __name__ == "__main__":
    os.umask(0o077)
    run(Path(sys.argv[1]).resolve())
