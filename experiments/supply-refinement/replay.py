"""Trace unmodified public Chain.accept and compare verifier I/O to committed selected rows."""
from contextlib import closing, contextmanager
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import sys

HERE = Path(__file__).resolve().parent
# Import as the node entry point does, before any historical audit helper can load an
# identically named, earlier Python module from the repository.
if __name__ == "__main__":
    staged = Path(sys.argv[1]).resolve()
    sys.path.insert(0, str(staged/"devnet"))
    import chain
    import runtime
    from run import Resources
    import wire
    if Path(wire.__file__).resolve() != staged/"experiments/advancing-payments/wire.py":
        raise RuntimeError("unexpected wire module in public validation path")
sys.path.insert(0, str(HERE.parent / "funded-supply"))
from openings import BURN, NETWORK, chain_to, check_store, parse_blocks, require
from conformance import public_inputs

OPS = ("transfer", "fixed", "register", "mint", "burn")


def h(data):
    return sha256(data).digest()


def json_row(row):
    if row is None:
        return None
    return {k: (v.hex() if isinstance(v, bytes) else v) for k, v in dict(row).items()}


def latest(db):
    return {r["id"]: json_row(r) for r in db.execute("SELECT * FROM assets ORDER BY sequence")}


@contextmanager
def public_calls():
    # Observe Python return events only inside the public validator. Never replace the role or its verdict.
    from wire import Role
    calls = {}
    def observe(frame, event, reply):
        if event == "return" and frame.f_code is Role.call.__code__:
            messages = frame.f_locals["frames"]
            if len(messages) == 1 and messages[0].startswith((b"MNG3", b"V")):
                calls.setdefault(messages[0], []).append(reply)
    prior = sys.getprofile()
    sys.setprofile(observe)
    try:
        yield calls
    finally:
        sys.setprofile(prior)


def trace_event(where, packet, e, depth, calls, old, actual):
    signed = e.op in (2, 3)
    inner = packet[17166:] if signed else packet[6:]
    tag, pi = public_inputs(packet)
    require(tag == "MNG3" and pi[208:240] == e.asset, "C supply statement and key")
    (reply,) = calls[inner]
    require(reply == b"1"+pi[:36]+pi[40:176]+inner[-3584:]+pi[208:-8]+bytes([depth]) and
            int.from_bytes(pi[-8:], "little") == depth, "verified public vector, receipts, depth")
    where.mkdir()
    (where/"packet.bin").write_bytes(packet)
    (where/"reply.bin").write_bytes(reply)
    if signed:
        digest = h(b"MNG3/supply-auth/v1\0" + NETWORK + bytes([e.op]) + e.issuer +
                   e.sequence.to_bytes(8, "little") + e.prior + h(inner))
        request = b"V" + e.issuer + digest + packet[78:17166]
        require(calls.get(request) == [b"1"], "actual issuer authorization for these exact bytes")
        (where/"v-request.bin").write_bytes(request)
        (where/"v-reply.bin").write_bytes(b"1")

    qty = e.delta - BURN if e.op == 4 else e.delta
    amount = (old["supply"] if old else 0) + (-qty if e.op == 4 else qty)
    require(amount == actual["supply"] and 0 < qty < BURN and 0 <= amount < BURN and
            actual["tx"] == h(packet).hex() and actual["id"] == e.asset.hex(), "registry quantity, key and transaction")
    if e.op in (1, 2):
        require(old is None and not e.sequence and e.prior == bytes(32) and actual["sequence"] == 1 and
                actual["mode"] == ("fixed" if e.op == 1 else "managed") and
                actual["authority"] == e.issuer.hex(), "first registry row")
    else:
        require(old and actual["mode"] == old["mode"] == "managed" and
                actual["authority"] == old["authority"] and actual["sequence"] == old["sequence"]+1,
                "selected registry predecessor")
        if e.op == 3:
            require((e.issuer.hex(), e.sequence, e.prior.hex()) ==
                    (old["authority"], old["sequence"], old["tx"]), "mint signer and selected revision")
    (where/"prior.json").write_text(json.dumps(old)+"\n")
    expected = dict(op=OPS[e.op], pk=e.issuer.hex(), seq=e.sequence, previous=e.prior.hex(),
                    inner_sha256=h(inner).hex(), tx_sha256=h(packet).hex(), anchor=e.anchor.hex(), height=e.born,
                    nf0=e.nullifiers[0].hex(), nf1=e.nullifiers[1].hex(),
                    cm0=e.commitments[0].hex(), cm1=e.commitments[1].hex(), fee=e.fee,
                    public_id=e.asset.hex(), word=e.delta, high=e.op == 4, magnitude=qty, depth=depth)
    (where/"observed.json").write_text(json.dumps(dict(fields=expected, row=actual), indent=2)+"\n")
    return dict(operation=OPS[e.op], height=actual["h"], packet_sha256=h(packet).hex(),
                inner_sha256=h(inner).hex(), reply_sha256=h(reply).hex(), packet_bytes=len(packet),
                previous_supply=old["supply"] if old else None, committed_supply=amount,
                revision=actual["sequence"], issuer_verification=signed, fee=e.fee)


def run(deployment, prefix, suffix, tip, out):
    # No wallet database, seed or owner-provided decoder is an input to this replay.
    sys.path.insert(0, str(deployment / "devnet"))
    from chain import Chain, decode_block, packet_vector, reward_context
    import runtime
    from run import Resources
    from reference import reward, tree_depth
    graph = parse_blocks(prefix) | parse_blocks(suffix)
    directory = out / "public-trace"
    directory.mkdir()
    dbfile = directory / "chain.sqlite"
    resources = Resources(runtime.config(deployment/"runtime"))
    records = []
    try:
        ledger = Chain(dbfile, resources.backend)
        try:
            with closing(sqlite3.connect(dbfile.as_uri()+"?mode=ro", uri=True)) as inspector:
                inspector.row_factory = sqlite3.Row
                fees = 0
                for block in chain_to(graph, bytes.fromhex(tip)):
                    name = block.id.hex()+".bin"
                    raw = ((suffix/name) if (suffix/name).is_file() else (prefix/name)).read_bytes()
                    parsed = decode_block(raw)
                    active = [s for s,p in zip(block.slots, parsed.packets, strict=True)
                              if p.startswith(b"MSP3\x01") and s.op]
                    pre = latest(inspector)
                    old_notes = inspector.execute("SELECT COUNT(*) FROM outs").fetchone()[0]
                    anchors = {s.txid:inspector.execute("SELECT ap,n FROM sel JOIN blocks USING(id) WHERE sel.h=?",
                                                         (s.born,)).fetchone() for s in active}
                    if active:
                        public = dict(height=block.height-1,
                                      cms=[r[0].hex() for r in inspector.execute("SELECT cm FROM outs ORDER BY pos")],
                                      spent=[r[0].hex() for r in inspector.execute("SELECT nf FROM spent ORDER BY nf")])
                        require(len(public["cms"]) == old_notes, "pre-block commitment coverage")
                    with public_calls() as calls:
                        accepted = ledger.accept(raw)
                    require(accepted["changed"] and accepted["selected"] and accepted["tip"] == block.id.hex(),
                            "committed from the selected parent")
                    after = latest(inspector)
                    if active:
                        events = {s.asset:s for s in active}
                        require(len(events) == len(active) and set(after) == set(pre) | events.keys() and
                                all(after[k] == v for k,v in pre.items() if k not in events), "other registry rows")
                        additions = list(inspector.execute("SELECT * FROM assets WHERE h=?", (block.height,)))
                        require(len(additions) == len(active) and
                                all(after[r["id"]] == json_row(r) for r in additions), "all committed event rows")
                        expected_nfs = [nf for s in block.slots for nf in s.nullifiers]
                        spent = [r[0] for r in inspector.execute("SELECT nf FROM spent WHERE h=?", (block.height,))]
                        require(len(spent) == len(expected_nfs) == len(set(expected_nfs)) and
                                set(spent) == set(expected_nfs), "committed spent identities")
                        outputs = list(inspector.execute("SELECT pos,cm,ct,reward FROM outs WHERE h=? ORDER BY pos",
                                                         (block.height,)))
                        require(len(outputs) == 2*len(block.slots)+1 and outputs[0]["pos"] == old_notes,
                                "committed ordered outputs")
                        for i, (p,s) in enumerate(zip(parsed.packets,block.slots,strict=True)):
                            require(ledger.tx(s.txid) == p and h(p) == s.txid, "selected original bytes")
                            for j,cm in enumerate(s.commitments):
                                r = outputs[2*i+j]
                                require(r["cm"] == cm and r["ct"] == s.receipts[1792*j:1792*(j+1)]
                                        and r["reward"] is None, "committed ciphertext and commitment")
                            if s.txid in anchors:
                                anchor, count = anchors[s.txid]
                                require(s.anchor == anchor and 1 <= block.height-s.born <= 8, "eligible anchor")
                                rec = trace_event(directory/s.txid.hex(),p,s,tree_depth(count),calls,
                                                  pre.get(s.asset),after[s.asset])
                                state = dict(public, anchors=[dict(height=s.born, ap=anchor.hex(), count=count)])
                                (directory/s.txid.hex()/"state.json").write_text(json.dumps(state)+"\n")
                                records.append(rec)
                        ctx = reward_context(parsed.parent, parsed.height, parsed.pk, packet_vector(parsed.packets))
                        credited = reward(ctx,parsed.pk,parsed.amount)
                        require(parsed.amount == 100+sum(s.fee for s in block.slots) and credited.token == 0
                                and outputs[-1]["cm"] == parsed.reward_cm == credited.commitment
                                and outputs[-1]["reward"] == ctx+parsed.pk+parsed.amount.to_bytes(8,"little")+parsed.reward_cm,
                                "native-only reward credit")
                    fees += sum(s.fee for s in block.slots)
                    require(ledger.status()["fees"] == fees, "selected cumulative fees")
        finally:
            ledger.close()
    finally:
        resources.close()
    readback = check_store(dbfile, graph)
    require(readback["tip"] == tip and readback["fees"] == fees, "full selected store vs public wire replay")
    require({r["operation"] for r in records} == set(OPS[1:]), "all supply operations")
    (out/"trace.json").write_text(json.dumps(records,indent=2)+"\n")
    print(json.dumps(dict(verified_tip=tip, traced_events=len(records), selected_fees=fees)),flush=True)


if __name__ == "__main__":
    deployment, prefix, suffix, tip, out = sys.argv[1:]
    run(Path(deployment).resolve(),Path(prefix),Path(suffix),tip,Path(out).resolve())
