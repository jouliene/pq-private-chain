"""Submit one genuinely funded H11-anchored B proof on both sides of activation."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys


def need(ok, message):
    if not ok:
        raise ValueError(message)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("home", type=Path)
    p = parser.parse_args()
    home = p.home.resolve()
    sys.path.insert(0, str(home / "deployment/devnet"))
    from upgrade_wallet import FundedLab
    from chain import GENESIS, block_id, decode_block
    from managed_wallet import Request, ZERO
    from wallet_sync import synced_wallet
    public = home / "public"
    report = json.loads((public / "PREFIX.json").read_bytes())
    common = report["tips"]["common"]
    need(common["height"] == 12, "expected the original funded H12")
    history = []
    tip = bytes.fromhex(common["tip"])
    while tip != GENESIS:
        raw = (public / "blocks" / (tip.hex() + ".bin")).read_bytes()
        need(block_id(raw) == tip, "public prefix digest mismatch")
        history.append(raw)
        tip = decode_block(raw).parent
    history.reverse()
    need(len(history) == 12, "funded public prefix length")
    run = home / "early-home"
    dest = public / "early"
    need(not run.exists() and not dest.exists(), "use an unused early control home")
    run.mkdir(mode=0o700)
    lab = FundedLab(run, "B")
    lab.initialize()
    (run / "nodes/a/peers.json").write_text("[]")
    try:
        lab.launch("a")
        for raw in history[:11]:
            lab.request("a", "publish", raw)
        parent = lab.status("a")
        need(parent["height"] == 11 and parent["tip"] == decode_block(history[11]).parent.hex(), "wrong first parent")
        # The backup is the fixture holder's own seed from before it received the sole A note.
        recovered = lab.restore("holder", home / "owner-backups/conflict", "a")
        need((recovered["balance"], recovered["notes"]) == (20, 1), "early control funding")
        lab.new_wallet("recipient")
        request = Request(7, ZERO, 0)
        # An offline prover can form its statement on a supported old anchor. The normal
        # wallet command's height preference is deliberately bypassed only for creation.
        with lab.locked_wallet("holder") as directory, lab.wallet("holder") as wallet:
            with synced_wallet(lab, "a", wallet, directory) as (state, _):
                pinned = state.select(request)
                packet = state.pay(request, lab.address("recipient"), pinned)
                need(state.height == 11 and len(pinned) == 1, "wrong source selection")
        def snapshot():
            state = lab.status("a")
            fields = ("tip", "height", "work", "anchor", "issued", "fees", "notes", "spent", "spent_set_sha256")
            return {k: state[k] for k in fields}
        before = snapshot()
        pool = lab.request("a", "pending")[0]
        try:
            lab.request("a", "submit", packet)
        except ValueError as error:
            need(str(error) == "inactive proof suite", "incorrect reason at candidate H12")
        else:
            raise ValueError("H12 accepted B")
        need(before == snapshot() and pool == lab.request("a", "pending")[0] == [], "early rejection mutated state")
        lab.request("a", "publish", history[11])
        eligible = snapshot()
        need(eligible["tip"] == common["tip"] and lab.balance("holder", "a")["balance"] == 20, "H12 lost funding")
        txid = sha256(packet).hexdigest()
        offer, _ = lab.request("a", "submit", packet)
        need(offer["id"] == txid and lab.request("a", "pending")[0] == [txid], "H13 admission mismatch")
        lab.mine("a")
        after = snapshot()
        block = lab.request("a", "block", id=after["tip"])[1]
        mined = decode_block(block)
        need(tuple(mined.packets) == (packet,) and after["height"] == 13 and mined.parent.hex() == common["tip"]
             and after["fees"] == eligible["fees"] + 3 and after["spent"] == eligible["spent"] + 2
             and lab.balance("recipient", "a")["balance"] == 7 and lab.balance("holder", "a")["balance"] == 10,
             "eligible block, fee or settlement mismatch")
        dest.mkdir()
        (dest / "B.bin").write_bytes(packet)
        (dest / "BLOCK.bin").write_bytes(block)
        result = dict(anchor_height=11, packet_sha256=txid, packet_B=len(packet), early_parent=before,
                      refused_candidate=12, refusal="inactive proof suite", state_and_pool_unchanged=True,
                      eligible_parent=eligible, included=after, fee=3, native_paid=7, native_change=10,
                      packet_in_mined_block_identical=True)
        (dest / "RESULT.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(json.dumps(dict(anchor=11, refused=12, accepted=13, packet_B=len(packet))))
    finally:
        lab.stop()


if __name__ == "__main__":
    main()
