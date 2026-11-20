"""Single-wallet subprocess adapter to the registered SWP1 wallet and its private journal."""
import json
from pathlib import Path
import sys
from types import SimpleNamespace


def run(home, name, node, op, folder, incoming=None):
    dev = home / "deployment/devnet"
    sys.path[:0] = [str(Path(__file__).resolve().parents[1] / "atomic-swap/wallet"), str(dev)]
    import swap_wallet as sw
    from cli import Lab
    from chain import NETWORK
    from intents import Outbox
    from swap_wire import digest

    lab = Lab(home, home / "deployment/runtime")
    if op == "combine":
        return sw.combine(SimpleNamespace(terms=folder/"terms",leg_a=folder/"leg-a",leg_b=folder/"leg-b",
                                          sig_a=folder/"sig-a",sig_b=folder/"sig-b",output=folder/"packet"))
    if op == "info":
        return dict(network=NETWORK.hex(), height=lab.status(node)["height"], address=lab.address(name).hex())
    terms = sw.term_file(folder / "terms")
    side = 0 if folder.parent.name == "taker" else 1
    mine, peer = terms.parties[side], terms.parties[1-side]
    sw.need(mine.address == lab.address(name), "wrong local wallet")
    args = SimpleNamespace(wallet=name, node=node, side="ab"[side], terms=folder/"terms",
                           leg_a=folder/"leg-a", leg_b=folder/"leg-b",
                           sig_a=folder/"sig-a", sig_b=folder/"sig-b")
    if op == "leg":
        def currency(p):
            return p.give.hex() if p.token else "native"
        args.give_id, args.take_id = currency(mine), currency(peer)
        args.give_qty, args.take_qty = mine.qty, peer.qty
        args.expiry, args.fee = terms.expiry, terms.fee(side)
        args.counterparty = "@" + str(folder/"peer.addr")
        args.output = (args.leg_a, args.leg_b)[side]
        return sw.make_leg(lab,args)
    if op == "authorize":
        args.output = (args.sig_a,args.sig_b)[side]
        return sw.permit(lab,args)
    if op == "peer":
        # Validate the complete proposed leg and its exact spend-key-owned primary output.
        # The maker additionally checks the taker's signature before committing its own consent.
        raw = (incoming/"leg").read_bytes()
        with lab.locked_wallet(name) as directory, sw.actor("verify") as verifier, sw.actor("wallet",directory) as worker:
            sw.need(worker.get() == mine.address, "unexpected local spending key")
            effect = sw.verify(verifier,raw)
            sw.need(effect.fee == terms.fee(1-side),"wrong peer fee")
            sw.opened(worker,effect,0,peer.native,peer.give,peer.token)
            from wallet_sync import synced_wallet
            with lab.wallet(name) as normal, synced_wallet(lab,node,normal,directory) as (state,_):
                sw.eligible(state,terms,(effect,))
            if side == 1:
                sig = (incoming/"sig").read_bytes()
                message = digest(NETWORK,terms.commitment(),terms.expiry,terms.payer,(raw,args.leg_b.read_bytes()))
                sw.need(len(sig) == sw.SIGNATURE and verifier.call(b"V"+effect.public+message+sig) == b"1",
                        "missing valid taker authorization")
        return {"valid":True}
    if op in ("abort","journal"):
        with lab.locked_wallet(name) as directory, Outbox(directory) as book:
            row = sw.get_session(book,terms.commitment(),side)
            if row is None:
                return {"state":"empty"}
            state = row["state"]
            if row["signature"] is not None:
                # Restore the exact prior signature after a crash between signing and application acknowledgment.
                sw.emit((args.sig_a,args.sig_b)[side],row["signature"])
                return {"state":"released"}
        if op == "journal" or state == "aborted":
            return {"state":state}
        args.release_after_expiry = False
        return sw.abort(lab,args)
    raise ValueError("unknown local wallet operation")


if __name__ == "__main__":
    import os
    os.umask(0o077)
    home, name, node, op, directory, *extra = sys.argv[1:]
    result = run(Path(home),name,node,op,Path(directory),Path(extra[0]) if extra else None)
    print(json.dumps(result,sort_keys=True))
