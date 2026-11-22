"""Create a fresh funded two-input partial burn without changing the deployed wallet role or rules."""
from contextlib import closing
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import sys

HERE = Path(__file__).resolve().parent
if __name__ == "__main__":
    sys.path.insert(0, str(Path(sys.argv[1]).resolve()/"network/deployment/devnet"))
    import chain  # Match the deployed wallet's import order before loading historical audit helpers.
sys.path.insert(0, str(HERE.parent / "funded-supply"))
from openings import BURN, NETWORK, TIP, WireReader, check_store, open_inventory, parse_blocks, read_block, reconcile, require
sys.path.insert(0, str(HERE.parent / "partial-fills"))
from prepare import agree, cli, load_lab
from audit import Tree, path_root, public_inputs


def run(out):
    home = out / "network"
    lab = load_lab(home)
    from chain import GENESIS, block_id, decode_block
    from managed_ops_c import wrap
    from managed_wallet import Request
    from wallet_c import FundedLab
    from wallet_sync import path_rows, synced_wallet

    prefix = out / "history/public/blocks"
    suffix = out / "suffix"
    suffix.mkdir(mode=0o700)
    reader = WireReader()

    def mine():
        tip = lab.mine("a", 1, pay_to="miner-a")["tip"]
        agree(lab, tip)
        raw = lab.request("a", "block", id=tip)[1]
        require(block_id(raw).hex() == tip, "fresh block identity")
        (suffix / (tip + ".bin")).write_bytes(raw)
        return decode_block(raw), tip

    def confirm(op, *args, label):
        posted = cli(home, "a", op, "miner-a", *args, "--intent", label)
        block, _ = mine()
        require([sha256(p).hexdigest() for p in block.packets] == [posted["tx"]], "included payment")
        return posted

    try:
        lab.start(manual=True)
        tip = bytes.fromhex(TIP)
        history = []
        while tip != GENESIS:
            raw = (prefix / (tip.hex() + ".bin")).read_bytes()
            require(block_id(raw) == tip, "public funding prefix")
            history.append(raw)
            tip = decode_block(raw).parent
        for raw in reversed(history):
            lab.request("a", "publish", raw)
        agree(lab, TIP)
        lab.new_wallet("holder")
        lab.backup("holder", out / "holder.backup")
        lab.backup("miner-a", out / "issuer.backup")
        for _ in range(4):
            mine()
        asset = confirm("register", 30, label="managed-30")["asset_id"]
        aid = bytes.fromhex(asset)
        confirm("send", "holder", 10, asset, 9, label="holder-first")
        funding = confirm("send", "holder", 7, asset, 7, label="holder-second")
        branch = FundedLab(home, "C")
        with branch.locked_wallet("holder") as directory, branch.wallet("holder") as wallet:
            with synced_wallet(branch, "a", wallet, directory) as (state, _):
                with state.transaction(False):
                    rows = state.db.execute(
                        "SELECT pos,cm,nf,amount,token,origin,path FROM owned "
                        "WHERE asset=? AND token>0 AND spent IS NULL ORDER BY pos", (aid,)).fetchall()
                    require([(r["amount"], r["token"]) for r in rows] == [(10, 9), (7, 7)], "funded notes")
                    sources = [(r["origin"], path_rows(r["path"])) for r in rows]
                    request = Request(0, aid, 0, BURN + 12, "burn", return_tx=bytes.fromhex(funding["tx"]))
                    inner = wallet.compact_payment(state.header, request, aid, wallet.address, sources)
        packet = wrap(inner, "burn", NETWORK)
        _, pi = public_inputs(packet)
        database = (home / "nodes/a/chain.sqlite").resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(database, uri=True)) as db:
            height = int.from_bytes(pi[32:40], "little")
            anchor, header, count = db.execute("SELECT ap,header,n FROM sel JOIN blocks USING(id) WHERE sel.h=?",
                                                (height,)).fetchone()
            leaves = [r[0] for r in db.execute("SELECT cm FROM outs WHERE h<=? ORDER BY pos", (height,))]
            tree = Tree(leaves)
            require(anchor == pi[:32] and tree.root == header[-32:] and tree.count == count and
                    len(tree.path(0)) == int.from_bytes(pi[-8:], "little") and
                    len(set(r["nf"] for r in rows)) == 2, "anchor, root, depth and unique identities")
            for i, row in enumerate(rows):
                require(leaves[row["pos"]] == row["cm"] and
                        path_root(row["cm"], tree.path(row["pos"]), tree.count) == tree.root and
                        pi[40+32*i:72+32*i] == row["nf"] and
                        not db.execute("SELECT 1 FROM spent WHERE nf=?", (row["nf"],)).fetchone(),
                        "selected, unspent owner-opened input")
        require(pi[208:240] == aid and int.from_bytes(pi[240:248],"little") == BURN+12, "burn statement")
        lab.request("a", "submit", packet)
        fixed = cli(home, "a", "issue", "miner-a", 5, "--intent", "separate-fixed")
        block, tip = mine()
        require({sha256(p).hexdigest() for p in block.packets} ==
                {sha256(packet).hexdigest(), fixed["tx"]} and block.amount == 106, "two accepted fees")
        balance = cli(home, "a", "balance", "holder")
        require(balance["assets"] == {asset:4} and balance["balance"] == 14, "post-burn holder balance")
        # This signs the actual row written by the burn. All new private receipts are reopenable.
        confirm("mint", "holder", asset, 2, label="mint-after-burn")
        end = lab.status("a")
        graph = parse_blocks(suffix)
        opened = open_inventory(home / "deployment", graph.values(),
                                [out / "holder.backup", out / "issuer.backup"])
        parsed = read_block((suffix / (tip+".bin")).read_bytes(), bytes.fromhex(tip), NETWORK, reader)
        burn, = [s for s in parsed.slots if s.op == 4]
        out_notes = [opened[c] for c in burn.commitments]
        in_notes = [opened[r["cm"]] for r in rows]
        require([n[1] for n in in_notes] == list(burn.nullifiers) and
                [(n[2], n[4]) for n in in_notes] == [(10,9),(7,7)], "backup-opened funded inputs")
        require(sum(n[2] for n in out_notes) == 14 and sum(n[4] for n in out_notes) == 4 and
                all(n[3] == aid for n in in_notes+out_notes if n[4]) and
                any(n[2] == 14 and n[4] == 4 and n[5] == "change" for n in out_notes), "encrypted change")
        # Private handoff to the optional Lean residual check for this individual proof.
        # True output nullifiers and funding links never enter the CI artifact allowlist.
        projection = dict(asset=asset,
                          inputs=[dict(cm=row["cm"].hex(), cash=n[2], qty=n[4], real=True)
                                  for row,n in zip(rows,in_notes,strict=True)],
                          outputs=[dict(true_nf=n[1].hex(), cash=n[2], qty=n[4]) for n in out_notes])
        (out/"burn-opening.private.json").write_text(json.dumps(projection))
        ordered = sorted(graph.values(), key=lambda b: b.height)
        events, live = reconcile(ordered, opened)
        require(live == {asset:20, fixed["asset_id"]:5} and len(events) == 4, "all four opened supply effects")
        complete = parse_blocks(prefix) | graph
        sql = [check_store(home/"nodes"/node/"chain.sqlite", complete) for node in "abc"]
        require(all(s == sql[0] and s["tip"] == end["tip"] for s in sql), "three selected stores vs wire replay")
        result = dict(tip=end["tip"], height=end["height"], burn_block=tip, burn_height=block.height, opened_events=events,
                      burn_tx=sha256(packet).hexdigest(), asset=asset,
                      funded_inputs=2, token_inputs=16, token_change=4, burned=12, native_inputs=17,
                      native_change=14, fee=3, block_reward=106, separate_fixed_asset=fixed["asset_id"],
                      selected_notes=tree.count, eligible_anchor=anchor.hex(), tree_root=tree.root.hex())
        (out/"funding.json").write_text(json.dumps(result, indent=2)+"\n")
        print(json.dumps(result), flush=True)
    finally:
        lab.stop()


if __name__ == "__main__":
    os.umask(0o077)
    run(Path(sys.argv[1]).resolve())
