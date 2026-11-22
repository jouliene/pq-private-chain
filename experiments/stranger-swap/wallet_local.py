"""Single-wallet subprocess adapter to the registered SWP1 wallet and its private journal."""
import json
from pathlib import Path
import sys
from types import SimpleNamespace


def run(home, name, node, op, folder, incoming=None, *, partial=False):
    dev = home / "deployment/devnet"
    sys.path[:0] = [str(Path(__file__).resolve().parents[1] / "atomic-swap/wallet"), str(dev)]
    if partial:
        sys.path.insert(0,str(dev))
        from chain import NETWORK  # Bootstrap the deployed consensus and native wire module paths.
        from consensus import FIRST_C
        from wallet_c import FundedLab
        import swap_c_wallet as sw
        lab=FundedLab(home,"C")
        if op not in ("abort","journal","selected") and lab.status(node)["height"]+1 < FIRST_C:
            raise ValueError("profile C is inactive")
    else:
        import swap_wallet as sw
        from cli import Lab
        lab=Lab(home, home / "deployment/runtime")
    from chain import NETWORK
    from intents import Outbox
    from swap_wire import digest

    if op == "combine":
        return sw.combine(SimpleNamespace(terms=folder/"terms",leg_a=folder/"leg-a",leg_b=folder/"leg-b",
                                          sig_a=folder/"sig-a",sig_b=folder/"sig-b",output=folder/"packet"))
    if op == "info":
        return dict(network=NETWORK.hex(), height=lab.status(node)["height"], address=lab.address(name).hex())
    terms = sw.term_file(folder / "terms")
    side = 0 if folder.parent.name in ("taker","partial-taker") else 1
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
    if op == "selected":
        # The receiving wallet already signed this exact pair. Scan common public swap blocks and
        # authenticate the counter-signature without signing or querying a maker or receipt index.
        from hashlib import sha256
        from tempfile import TemporaryDirectory
        from chain import block_id, decode_block
        import swap_wire_c as c
        sys.path.append(str(Path(__file__).resolve().parent))
        from partial_chain import snapshot
        legs=(args.leg_a.read_bytes(),args.leg_b.read_bytes())
        own_sig=(args.sig_a,args.sig_b)[side].read_bytes()
        snap=snapshot(home,node)
        blocks={}
        for bundle_id,loc in snap["bundles"].items():
            blocks.setdefault(loc["block"],[]).append((bundle_id,loc))
        match=None
        for ident in sorted(blocks):
            raw=lab.request(node,"block",id=ident)[1]
            sw.need(block_id(raw).hex()==ident,"inconsistent selected block")
            block=decode_block(raw)
            for bundle_id,loc in blocks[ident]:
                pos=loc["position"]
                packet=c.bundle(block.packets[pos:pos+2])
                sw.need(sha256(packet).hexdigest()==bundle_id and loc["height"]==block.height,
                        "inconsistent selected transaction")
                pair=c.pair(c.split(packet))
                if (tuple(f.leg for f in pair)!=legs or pair[side].signature!=own_sig or
                    pair[0].terms!=terms.commitment() or pair[0].network!=terms.network or
                    pair[0].expiry!=terms.expiry or pair[0].payer!=terms.payer):
                    continue
                sw.need(match is None,"multiple selected copies of signed fill")
                match=(packet,bundle_id,loc,pair[1-side].signature)
        sw.need(lab.status(node)["tip"]==snap["tip"],"selected branch changed during recovery")
        observed={"selected_tip":snap["tip"],"selected_height":snap["height"],"active_c":snap["height"]+1>=FIRST_C}
        if match is None:
            return dict(observed,found=False)
        packet,bundle_id,loc,peer_sig=match
        with TemporaryDirectory(dir=folder) as temp:
            tmp=Path(temp)
            peer=tmp/"peer.sig"
            sw.emit(peer,peer_sig)
            check=SimpleNamespace(terms=folder/"terms",leg_a=args.leg_a,leg_b=args.leg_b,
                                  sig_a=args.sig_a if side==0 else peer,sig_b=peer if side==0 else args.sig_b,
                                  output=tmp/"packet")
            sw.combine(check)
            sw.need(check.output.read_bytes()==packet,"unrecognized signed packet")
        sw.need(lab.status(node)["tip"]==snap["tip"],"selected branch changed before wallet recovery")
        sw.emit((args.sig_a,args.sig_b)[1-side],peer_sig)
        sw.emit(folder/"packet",packet)
        return dict(observed,found=True,id=bundle_id,height=loc["height"],block=loc["block"])
    if op == "recheck":
        from wallet_sync import synced_wallet
        legs=tuple(path.read_bytes() for path in (args.leg_a,args.leg_b))
        with lab.locked_wallet(name) as directory, Outbox(directory) as book:
            row=sw.get_session(book,terms.commitment(),side)
            sw.need(row is not None and row["state"]!="aborted" and row["leg"]==legs[side],"lost funding pin")
            with lab.wallet(name) as normal, synced_wallet(lab,node,normal,directory) as (state,_), sw.actor("verify") as verifier:
                effects=tuple(sw.verify(verifier,leg) for leg in legs)
                sw.check_pair(effects,terms)
                state.synchronize(lab,node)
                sw.eligible(state,terms,effects)
                sw.need(all(v=="unspent" for v in state.input_status(json.loads(row["pins"])).values()),
                        "own sources spent or detached")
        return {"valid":True}
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
    partial = op.startswith("partial-")
    result = run(Path(home),name,node,op.removeprefix("partial-"),Path(directory),
                 Path(extra[0]) if extra else None,partial=partial)
    print(json.dumps(result,sort_keys=True))
