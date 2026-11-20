"""Replay a completed capture into an offline disposable ledger and check joint admission boundaries."""
import argparse
from contextlib import closing
from hashlib import sha256
from itertools import combinations
import json
from pathlib import Path
import sys
import tempfile


def need(ok, message):
    if not ok:
        raise ValueError(message)


def snapshot(ledger):
    pool = tuple(tuple(r) for r in ledger.db.execute("SELECT seq,tx,nf0,nf1,cm0,cm1 FROM pool ORDER BY seq"))
    links = tuple(tuple(r) for r in ledger.db.execute("SELECT id,a,b FROM swap_pool ORDER BY id"))
    return ledger.status(), pool, links


def refusal(ledger, operation, reasons):
    before = snapshot(ledger)
    try:
        operation()
    except ValueError as error:
        need(str(error) in reasons, "unexpected rejection: "+str(error))
        need(snapshot(ledger) == before, "candidate rejection changed selected state or pool rows")
        return str(error)
    raise ValueError("invalid joint candidate accepted")


def fifo(ledger, public, pk, bundle):
    """Try only genuine archived singleton packets that would actually enter this prefix's pool."""
    from chain import decode_block
    packets = []
    capacity = public/"capacity"
    required = capacity.is_dir()
    candidates = [capacity/(str(i)+".bin") for i in range(3)] if required else sorted((public/"packets").glob("*.bin"))
    with ledger._transaction():
        head = ledger._head()
        for f in candidates:
            raw = f.read_bytes()
            if not raw.startswith((b"MSP1", b"AST1")):
                need(not required, "capacity fixture is not an ordinary packet")
                continue
            try:
                ledger._effects(raw, head)
            except ValueError as err:
                need(not required, "capacity fixture was not eligible on the common prefix: "+str(err))
                need(str(err) in {"anchor age","anchor branch","spent nullifier","asset already registered",
                                  "previous commitment","stale issuer state"},
                     "archived ordinary payment failed outside branch eligibility: "+str(err))
                continue
            packets.append(raw)
    for triple in combinations(packets, 3):
        with ledger._transaction(True):
            ledger.db.execute("SAVEPOINT fifo_fixture")
            try:
                for p in (*triple, bundle):
                    _,duplicate = ledger._enqueue(p,ledger._head())
                    need(not duplicate, "capture repeats a capacity test payment")
            except ValueError as err:
                need(str(err) == "pool conflict", "unexpected FIFO preparation failure: "+str(err))
                ledger.db.execute("ROLLBACK TO fifo_fixture")
                ledger.db.execute("RELEASE fifo_fixture")
                continue
            ledger.db.execute("RELEASE fifo_fixture")
        template = ledger.template(pk)
        # Decode only the unsigned template. The tested boundary is candidate packing.
        need(decode_block(template+bytes(8)).packets == triple, "FIFO candidate split the following atomic pair")
        ordinary_ids = [sha256(p).hexdigest() for p in triple]
        group_id = sha256(bundle).hexdigest()
        need(ledger.pending() == ordinary_ids+[group_id], "template construction changed the pending FIFO order")
        with ledger._transaction(True):
            ledger._refresh([], {bytes.fromhex(t) for t in ordinary_ids})
        from swap_wire import split
        need(ledger.pending() == [group_id] and decode_block(ledger.template(pk)+bytes(8)).packets == split(bundle),
             "removing the first three packets left a partial swap proposal")
        with ledger._transaction(True):
            ledger.db.execute("DELETE FROM pool")
        return dict(executed=True,slots=3,swap_deferred_in_full=True,
                    ordinary_ids=ordinary_ids,subsequent_queue_template_slots=2)
    need(not required,"no complete 3+2 FIFO test could be constructed from the required capacity fixtures")
    return dict(executed=False, eligible_ordinary_candidates=len(packets),
                reason="Capture contains no three simultaneously queueable ordinary payments ahead of the genuine swap at its common prefix.")


def run(home):
    home = Path(home).resolve(strict=True)
    public = home/"public"
    run = json.loads((public/"RUN.json").read_text())
    sys.path.insert(0,str(home/"deployment/devnet"))
    import runtime
    from chain import Chain, GENESIS, block_id, decode_block
    from run import Resources
    from swap_wire import assemble, pair, split
    raw = (public/"SWAP.bin").read_bytes()
    frames = split(raw)
    a, b = pair(frames)
    common = run["tips"]["common"]
    rival_id = run["ordinary"]["competing-ordinary"]["tx"]
    rival = (public/"packets"/(rival_id+".bin")).read_bytes()
    need(sha256(rival).hexdigest() == rival_id, "competing packet identity")
    actual_id = run["tips"]["swap_included"]["tip"]
    actual = (public/"blocks"/(actual_id+".bin")).read_bytes()
    parsed = decode_block(actual)
    need(block_id(actual).hex() == actual_id and parsed.parent.hex() == common["tip"] and parsed.packets == frames,
         "capture lacks the genuine directly extending joint block")
    prefix = []
    tip = common["tip"]
    while tip != GENESIS.hex():
        blob = (public/"blocks"/(tip+".bin")).read_bytes()
        need(block_id(blob).hex() == tip, "saved common-prefix identity")
        prefix.append(blob)
        tip = decode_block(blob).parent.hex()
    with tempfile.TemporaryDirectory(prefix="swp-admission-") as tmp, closing(Resources(runtime.config(home/"deployment/runtime"))) as roles:
        with closing(Chain(Path(tmp)/"chain.sqlite",roles.backend)) as ledger:
            for blk in reversed(prefix):
                need(ledger.accept(blk)["selected"], "replayed common-prefix block not selected")
            base = ledger.status()
            need(all(base[k] == v for k,v in common.items()), "fresh replay differs from selected common state")
            tests = {}
            candidate = lambda packets: ledger.template(parsed.pk,packets=packets)
            for role_name,frame in zip(("a","b"),frames,strict=True):
                tests["isolated_"+role_name] = refusal(ledger,lambda:candidate((frame,)),{"incomplete atomic swap"})
            tests["reversed"] = refusal(ledger,lambda:candidate(frames[::-1]),{"unmatched atomic swap"})
            tests["interrupted"] = refusal(ledger,lambda:candidate((frames[0],rival,frames[1])),
                                          {"swap frame length or version"})
            # The alternate signature bytes are genuine, but the wrong role did not authorize that leg.
            for index in range(2):
                signed = [a.signature,b.signature]
                signed[index] = (b.signature,a.signature)[index]
                wrong = assemble(a.network,a.terms,a.expiry,a.payer,(a.leg,b.leg),signed)
                tests["signature_role_"+str(index)] = refusal(ledger,lambda:ledger.offer(wrong),{"invalid swap authorization"})
            incorrect_link = bytearray(frames[0])
            incorrect_link[75] ^= 1
            tests["cross_reference"] = refusal(ledger,lambda:candidate((bytes(incorrect_link),frames[1])),
                                               {"unmatched atomic swap"})
            packing = fifo(ledger, public, parsed.pk, raw)
            swap_id = sha256(raw).hexdigest()
            need(ledger.offer(raw) == dict(id=swap_id,duplicate=False), "genuine pair not admitted to empty pool")
            need(ledger.pending() == [swap_id], "pair exposed as individual pending transactions")
            ar, br = [sha256(f).digest() for f in frames]
            aa = ledger.db.execute("SELECT nf0,nf1 FROM pool WHERE tx=?", (ar,)).fetchone()
            bb = ledger.db.execute("SELECT nf0,nf1 FROM pool WHERE tx=?", (br,)).fetchone()
            rival_slot, = ledger.backend.verify(rival)
            need(set(rival_slot.nfs).isdisjoint(aa) and not set(rival_slot.nfs).isdisjoint(bb),
                 "fixture does not isolate a second-leg conflict")
            with ledger._transaction(True):
                restored, rejected = ledger._refresh([rival],set())
                need(restored == [rival_id] and rejected == [dict(id=swap_id,reason="pool conflict")],
                     "refresh did not catch the expected second-leg pool conflict")
            now, rows, links = snapshot(ledger)
            need({k:v for k,v in now.items() if k != "mempool"} == {k:v for k,v in base.items() if k != "mempool"}
                 and now["mempool"] == 1 and len(rows) == 1 and rows[0][1].hex() == rival_id
                 and not links and ledger.pending() == [rival_id],
                 "refresh committed a partial swap, changed coin state or lost the ordinary payment")
            need(ledger.accept(actual)["selected"], "original fully sealed joint block rejected")
            end = ledger.status()
            trusted = run["tips"]["swap_included"]
            need(all(end[k] == v for k,v in trusted.items()) and end["fees"] == base["fees"]+3
                 and end["spent"] == base["spent"]+4 and end["notes"] == base["notes"]+5,
                 "full joint block failed exact effects after pending conflict")
            return dict(common_tip=base["tip"], common_height=base["height"], common_blocks_replayed=len(prefix),
                        preseal_candidates=tests, second_leg_refresh=dict(status="passed",surviving_ordinary=rival_id,
                        stranded_rows=0,stranded_groups=0,selected_fee_delta=0),fifo_three_then_pair=packing,
                        original_pow_block=dict(tip=end["tip"],height=end["height"],fee_delta=3,spent_delta=4,
                                                funded_leaf_delta=5), invalid_blocks_mined=0)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("home",type=Path)
    print(json.dumps(run(p.parse_args().home),sort_keys=True,indent=2))
