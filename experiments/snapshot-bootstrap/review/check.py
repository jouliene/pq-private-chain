"""Check released wallet-history origins and optional selected public node databases against original wire bytes."""
import argparse
from collections import Counter
from contextlib import closing
from dataclasses import dataclass, field
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "managed-assets/review"))
from chain_audit import advance_asset, read_block
from events import Event, ZERO, ast1

NETWORK = ast1.sha(b"AST1/PoW/network/v1\0" + bytes.fromhex(ast1.VK) + ast1.RULES)
GENESIS = ast1.sha(b"AST1/PoW/genesis/v1\0" + NETWORK)
GENESIS_STATE = ast1.counted_hash(b"dev-genesis-state", NETWORK)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


class WireReader:
    """Read the public inputs and the two original receipts from a physical signed frame."""

    def packet(self, raw):
        version = raw[:4]
        require(raw[4:5] == b"\x01", "frame version")
        swap = version in (b"SWF1", b"SWF2", b"SWF3")
        legacy = version == b"AST1"
        op, issuer, sequence, previous = 0, b"", 0, ZERO
        if swap:
            inner = raw[17195:]
            expected = b"SLG" + version[-1:]
        elif legacy:
            inner, expected = raw, version
        else:
            require(version in (b"MSP1", b"MSP2", b"MSP3"), "managed frame type")
            op = raw[5]
            require(0 <= op <= 4, "managed operation")
            if op in (2, 3):
                issuer, sequence, previous = raw[6:38], ast1.U64.unpack_from(raw, 38)[0], raw[46:78]
                inner = raw[17166:]
            else:
                inner = raw[6:]
            expected = b"MNG" + version[-1:]
        require(inner[:5] == expected + b"\x01", "inner registered suite")
        count = (34 if swap else 31) + int(version[-1:] == b"3")
        end = 9 + ast1.U32.unpack_from(inner, 5)[0]
        require(len(inner) == end + 3584 and end > 9 + (count + 1) * 8, "proof/receipts framing")
        length, *words = struct.unpack_from(f"<{count + 1}Q", inner, end - (count + 1) * 8)
        require(length == count and all(x < ast1.P for x in words), "public proof inputs")
        pi = inner[end - count * 8:end]
        asset, delta = (ZERO, 0) if swap else (pi[208:240], words[30])
        if legacy:
            op = int(bool(delta))
        return Event(ast1.sha(raw), op, issuer, sequence, previous, words[4], pi[:32],
                     (pi[40:72], pi[72:104]), (pi[104:136], pi[136:168]),
                     words[21], asset, delta, inner[end:], legacy)


def compact(block, header):
    require(len(header) == 132, "wallet header length")
    tail = (ast1.U32.pack(block.height) + block.state
            + ast1.counted_hash(b"dev-seal", NETWORK, block.id) + block.root)
    require(header[32:] == tail, "wallet header vs original block")
    body = bytearray(ast1.U32.pack(block.height) + block.id + block.parent + header
                     + block.reward_record + bytes([len(block.slots)]))
    for slot in block.slots:
        first, second = slot.commitments
        body.extend(slot.txid + b"".join(slot.nullifiers) + first + slot.receipts[:1792]
                    + second + slot.receipts[1792:] + slot.asset + ast1.U64.pack(slot.delta))
        body.append(2 if slot.fee == 0 else int(not slot.legacy))
    return bytes(body)


def chain_to(blocks, tip):
    result = []
    while tip != GENESIS:
        b = blocks[tip]
        require(not result or result[-1].height == b.height + 1, "original body ancestry")
        result.append(b)
        tip = b.parent
    result.reverse()
    require(result and result[0].height == 1, "genesis coverage")
    return result


@dataclass
class Ledger:
    outputs: list = field(default_factory=list)
    spends: dict = field(default_factory=dict)
    changes: list = field(default_factory=list)
    assets: dict = field(default_factory=dict)
    counts: dict = field(default_factory=dict)


def selected_ledger(blocks):
    ledger = Ledger()
    fees, previous_state = 0, GENESIS_STATE
    commitments = set()
    for b in blocks:
        for s in b.slots:
            for nf in s.nullifiers:
                require(nf not in ledger.spends, "selected nullifier uniqueness")
                ledger.spends[nf] = b.height
            for i, cm in enumerate(s.commitments):
                require(cm not in commitments, "selected commitment uniqueness")
                commitments.add(cm)
                ledger.outputs.append((len(ledger.outputs), cm, b.height, s.receipts[1792*i:1792*(i+1)], None))
            if s.op:
                updated = advance_asset(ledger.assets.get(s.asset), s, b.height)
                ledger.assets[s.asset] = updated
                ledger.changes.append(updated.row(s.asset))
            fees += s.fee
        require(b.reward not in commitments, "selected reward uniqueness")
        commitments.add(b.reward)
        ledger.outputs.append((len(ledger.outputs), b.reward, b.height, None, b.reward_record))
        n = len(ledger.outputs)
        ledger.counts[b.id] = n, fees
        state = ast1.counted_hash(b"dev-state", NETWORK, previous_state, ast1.U64.pack(n),
                                  ast1.U64.pack(100 * b.height), ast1.U64.pack(fees), b.reward_record,
                                  b"".join(s.transition() for s in b.slots))
        require(b.state == state, "original selected funded transition")
        previous_state = state
    return ledger


def check_checkpoint(fixture, pin_path, prefix, origins):
    raw = (fixture / "state.bin").read_bytes()
    pin = json.loads(pin_path.read_bytes())
    manifest = json.loads((fixture / "manifest.json").read_bytes())
    require(raw.startswith(b"SNPSTAT1") and pin == manifest and pin["state_sha256"] == ast1.sha(raw).hex(),
            "operator pin vs archive state and manifest")
    doc = json.loads(raw[8:])
    normalized = json.dumps(doc, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    tip = prefix[-1]
    expected = dict(version=1, network=NETWORK.hex(), genesis=GENESIS.hex(), rules=pin["rules"],
                    height=tip.height, tip=tip.id.hex(), work=tip.height * (1 << 22))
    require(raw[8:] == normalized and all(doc[k] == pin[k] == v for k, v in expected.items()),
            "canonical state or checkpoint identity")
    ledger = selected_ledger(prefix)
    leaves = [[cm.hex(), h] for _, cm, h, _, _ in ledger.outputs]
    spent = [[nf.hex(), h] for nf, h in sorted(ledger.spends.items())]
    events = [[asset.hex(), rev, mode, pk.hex(), supply, h, tx.hex()]
              for asset, rev, mode, pk, supply, h, tx in sorted(ledger.changes)]
    require((doc["leaves"], doc["spent"], doc["assets"]) == (leaves, spent, events), "checkpoint monetary rows")
    previous = None
    for b, anchor in zip(prefix, doc["anchors"], strict=True):
        bid, ap, header, fees, count, _, record_hash = anchor
        record = origins[b.id]
        require(bid == b.id.hex() and header == record[68:200].hex() and ast1.sha(record).hex() == record_hash,
                "checkpoint ordered receipt commitment")
        require(previous is None or header[:64] == previous, "checkpoint header ancestry")
        require((count, fees) == ledger.counts[b.id], "checkpoint count or cumulative fees")
        previous = ap
    return dict(state_sha256=pin["state_sha256"], state_B=len(raw))


def check_store(path, blocks):
    with closing(sqlite3.connect(path.resolve(strict=True).as_uri() + "?mode=ro", uri=True)) as db:
        require(db.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "node database integrity")
        selected = db.execute("SELECT h,id FROM sel ORDER BY h").fetchall()
        selected_blocks = chain_to(blocks, selected[-1][1])
        require(selected == [(0, GENESIS)] + [(b.height, b.id) for b in selected_blocks], "selected ancestry")
        ledger = selected_ledger(selected_blocks)
        for b in selected_blocks:
            count, fees = ledger.counts[b.id]
            header, parent_anchor, n, dbfees, work = db.execute(
                "SELECT c.header,p.ap,c.n,c.fees,c.work FROM blocks c JOIN blocks p ON p.id=c.parent WHERE c.id=?",
                (b.id,)).fetchone()
            require((header[:32], n, dbfees, work) == (parent_anchor, count, fees, b.height * (1 << 22)),
                    "selected header parent, output count, fees, or work")
            row = db.execute("SELECT record FROM wallet_history_v2 WHERE bid=?", (b.id,)).fetchone()
            require(row == (compact(b, header),), "selected node compact history vs mined bytes")
        require(db.execute("SELECT pos,cm,h,ct,reward FROM outs ORDER BY pos").fetchall() == ledger.outputs,
                "selected original outputs and reward origins")
        require(dict(db.execute("SELECT nf,h FROM spent")) == ledger.spends, "selected spent state")
        require(db.execute("SELECT id,sequence,mode,authority,supply,h,tx FROM assets ORDER BY id,sequence").fetchall()
                == sorted(ledger.changes), "selected registry and revisions")
        modes = db.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name='snapshot_mode'").fetchall()
        mode = "original"
        if modes:
            mode, = db.execute("SELECT mode FROM snapshot_mode WHERE id=1").fetchone()
            require(mode == "full" and db.execute("SELECT count(*) FROM snapshot_prefix").fetchone() == (0,),
                    "final receipt and consensus audit requires a fully replayed node")
        for table, first in (("funded_upgrade_blocks", 13), ("funded_c_blocks", 25)):
            rows = db.execute(f"SELECT sel.h FROM sel JOIN {table} USING(id) ORDER BY sel.h").fetchall()
            require(rows == [(b.height,) for b in selected_blocks if b.height >= first],
                    "selected verification markers after full replay")
        return dict(height=selected[-1][0], tip=selected[-1][1].hex(), fees=fees, subsidy=100*len(selected_blocks),
                    validation_mode=mode, selected_compact_rows=len(selected_blocks),
                    outputs=len(ledger.outputs), spent=len(ledger.spends), registry_events=len(ledger.changes), assets=len(ledger.assets),
                    registry_supplies=sorted((v.mode, v.supply) for v in ledger.assets.values()))


def check_branches(blocks, case):
    branches = {}
    for name in ("main", "fork"):
        ids = case[name]
        branch = chain_to(blocks, bytes.fromhex(ids[-1]))
        require([b.id.hex() for b in branch] == ids, "published inventory differs from actual ancestry")
        branches[name] = branch
    original, winning = branches["main"], branches["fork"]
    common = next((i for i, (a, b) in enumerate(zip(original, winning)) if a.id != b.id), None)
    require(common == case["fork_height"] == case["base_height"] - 1 and len(winning) > len(original),
            "preferred branch must fork before the checkpoint")
    require(set(blocks) == {b.id for b in (*original, *winning)}, "published branch coverage")
    require(original[common - 1].id.hex() == case["funding_block"] and
            case["funding"] in {s.txid.hex() for s in original[common - 1].slots}, "shared funding block")
    old_tx, win_tx = (bytes.fromhex(case[k]) for k in ("spend", "winning_spend"))
    ledgers = [{s.txid: s for b in branch for s in b.slots} for branch in (original, winning)]
    require(old_tx in ledgers[0] and old_tx not in ledgers[1] and
            win_tx in ledgers[1] and win_tx not in ledgers[0], "branch-local receipt spends")
    a, b = ledgers[0][old_tx], ledgers[1][win_tx]
    overlap = len(set(a.nullifiers).intersection(b.nullifiers))
    require(overlap == 1 and a.fee == b.fee == 3 and a.anchor != b.anchor, "shared funded spend and fresh anchor")
    return dict(common_height=common, original_height=len(original), winning_height=len(winning),
                original_tip=original[-1].id.hex(), winning_tip=winning[-1].id.hex(),
                shared_spend_nullifiers=overlap, anchor_heights=[a.born, b.born], selected_fee=b.fee)


def verify(fixture, stores, pin_path):
    reader = WireReader()
    blocks, origins, sizes = {}, {}, Counter()
    for source in sorted((fixture / "blocks").glob("*.bin")):
        ident = bytes.fromhex(source.stem)
        require(source.stem == ident.hex(), "original file name")
        raw = source.read_bytes()
        blocks[ident] = read_block(raw, ident, NETWORK, reader)
        sizes["original_B"] += len(raw)
    require(bool(blocks), "empty original fixture")
    for source in sorted((fixture / "records").glob("*.bin")):
        ident, raw = bytes.fromhex(source.stem), source.read_bytes()
        require(source.stem == ident.hex() and ident in blocks, "compact record origin")
        b = blocks[ident]
        require(compact(b, raw[68:200]) == raw, "detached receipt record differs from its mined original")
        origins[ident] = raw
        sizes.update(compact_B=len(raw), receipts_compared=2*len(b.slots), reward_origins_compared=1)
    case = json.loads((fixture / "case.json").read_bytes())
    require(set(origins) == set(blocks), "missing original-derived compact history in published fixture")
    branches = check_branches(blocks, case)
    base = bytes.fromhex(case["base"])
    prefix = chain_to(blocks, base)
    require(case["base_height"] == len(prefix) and all(b.id in origins for b in prefix), "checkpoint history coverage")
    digest = sha256()
    for b in prefix:
        raw = origins[b.id]
        digest.update(ast1.U32.pack(len(raw)) + raw)
    registration = check_checkpoint(fixture, pin_path, prefix, origins)
    return dict(**registration, branches=branches, original_blocks=len(blocks), compact_records=len(origins), checkpoint_height=len(prefix),
                checkpoint=base.hex(), checkpoint_ordered_compact_sha256=digest.hexdigest(), **sizes,
                selected_stores=[check_store(p, blocks) for p in stores])


if __name__ == "__main__":
    if not __debug__:
        raise SystemExit("run with Python assertions enabled for the historical wire reader")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("stores", nargs="*", type=Path)
    parser.add_argument("--pin", type=Path, help="independently expected pin, defaults to fixture/pin.json")
    args = parser.parse_args()
    print(json.dumps(verify(args.fixture, args.stores, args.pin or args.fixture / "pin.json"), indent=2, sort_keys=True))
