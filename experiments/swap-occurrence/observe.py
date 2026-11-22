#!/usr/bin/env python3
"""Trace two live profile-C fills and export only fixture quantities and counts."""

import argparse
from contextlib import ExitStack, closing
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
from select import select
import signal
import sqlite3
import struct
import subprocess
import sys


HERE = Path(__file__).resolve().parent
EXPERIMENTS = HERE.parent
ROOT = EXPERIMENTS.parent
sys.path[:0] = [str(EXPERIMENTS / name) for name in
                ("partial-fills", "stranger-swap", "funded-membership", "funded-conservation")]
from audit import opened
from conformance import NETWORK, public_inputs
from lab_hosts import free_ports
from prepare import agree, cli, load_lab
from reference import P, Tree, ZERO, hash_fields, need, path_root, reward, tree_depth, words

CT = 1792
SIGNATURE = 17088
SIG_END = 107 + SIGNATURE
BOUNDS = 262144


def digest(data):
    return sha256(data).digest()


def le(raw):
    return int.from_bytes(raw, "little")


def db_read(path):
    return closing(sqlite3.connect(path.resolve(strict=True).as_uri() + "?mode=ro", uri=True))


def node_db(home, node="c"):
    return home / "nodes" / node / "chain.sqlite"


def wallet_folder(home, actor):
    return home / "participants" / actor / "wallets" / actor


def start_service(stack, *args):
    p = subprocess.Popen([ROOT / "pqd", "market", *map(str, args)], stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)

    def stop():
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGTERM)
            try:
                p.wait(8)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait()
        p.stdout.close()

    stack.callback(stop)
    need(bool(select([p.stdout], [], [], 75)[0]), "market service readiness timeout")
    row = json.loads(p.stdout.readline(65537))
    need(isinstance(row, dict) and row.get("ready"), "market service readiness")
    return row


def market(home, actor, action, *args):
    cmd = [ROOT / "pqd", "market", "--home", home / "participants" / actor, action, actor, *map(str, args)]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=300)
    except subprocess.TimeoutExpired:
        raise ValueError(f"market {action} timed out") from None
    need(result.returncode == 0, f"market {action} failed")
    return json.loads(result.stdout)


def market_offer(home, funding, stack):
    relay_ports = [f"127.0.0.1:{p}" for p in free_ports(3)]
    relays, endpoint = relay_ports[:2], relay_ports[2]
    for address in relays:
        start_service(stack, "relay", "--listen", address)
    for actor in ("seller", "buyer-one", "buyer-two"):
        path = home / "participants" / actor / "network.json"
        config = json.loads(path.read_bytes())
        config["market_relays"] = relays
        path.write_text(json.dumps(config))
    policy = ("--give", funding["asset_a"], "--take", funding["asset_b"], "--lot", 10, "--price", 1, "--fee", 3)
    offer = start_service(stack, "--home", home / "participants/seller", "offer", "seller",
                          *policy, "--total", 100, "--endpoint", endpoint)
    need(all(row["ok"] for row in offer["discovery"]), "offer registration")
    return offer, policy


def sign_fill(home, buyer, offer, policy):
    need(offer["advert"] in market(home, buyer, "discover", "--partial")["makers"], "offer discovered")
    args = ("--offer", offer["offer"], *policy, "--quantity", 50)
    quote = market(home, buyer, "reserve", offer["advert"], *args)
    need((quote["quantity"], quote["payment"], quote["payer"]) == (50, 5, "a"), "fill economics")
    fill = market(home, buyer, "fill", quote["quote"], *args, "--expiry", quote["expiry_height"], "--sign-only")
    packet = Path(fill["packet"])
    need(packet.is_file(), "signed fill did not materialize its packet")
    return packet.read_bytes()


@dataclass(frozen=True)
class Effect:
    anchor: bytes
    height: int
    nfs: tuple
    cms: tuple
    fee: int
    cts: tuple
    key: bytes
    depth: int


def verify_bundle(raw, candidate_height):
    from consensus import role

    need(raw.startswith(b"SWB3\x01"), "signed C bundle tag")
    frames = []
    off = 5
    for side in range(2):
        need(off + 4 <= len(raw), "frame length prefix")
        width, = struct.unpack_from("<I", raw, off)
        off += 4
        need(SIG_END < width <= BOUNDS and off + width <= len(raw), "frame length")
        frame = raw[off:off+width]
        need(frame.startswith(b"SWF3\x01" + bytes([side])), "frame profile and order")
        need(frame[SIG_END:].startswith(b"SLG3\x01"), "leg registration")
        frames.append(frame)
        off += width
    need(off == len(raw), "exact bundle boundary")
    left, right = frames
    payer, expiry = struct.unpack_from("<BI", left, 6)
    terms = left[43:75]
    need(left[6:75] == right[6:75] and left[11:43] == NETWORK and terms != ZERO
         and payer == 0 and 25 <= candidate_height <= expiry, "paired network, payer, terms and expiry")
    legs = [frame[SIG_END:] for frame in frames]
    leg_hashes = list(map(digest, legs))
    need([frame[75:107] for frame in frames] == leg_hashes[::-1], "reciprocal leg digests")
    joint = digest(b"SWP3/joint-authorization/v1\0" + NETWORK + terms + struct.pack("<IB", expiry, payer)
                   + b"".join(leg_hashes))

    output = {"bundle.bin": raw, "network.bin": NETWORK}
    effects = []
    worker = role("swap")
    try:
        for side, (frame, leg) in enumerate(zip(frames, legs, strict=True)):
            tag, pi = public_inputs(leg)
            fields = struct.unpack("<35Q", pi)
            need(tag == "SLG3" and all(v < P for v in fields) and fields[4] < 2**32
                 and all(v < 2**32 for v in fields[26:34]) and 1 <= fields[34] <= 20, "SLG3 public words")
            key = struct.pack("<8I", *fields[26:34])
            reply = worker.call(leg)
            need(reply == b"1" + pi[:36] + pi[40:176] + leg[-2*CT:] + key + bytes([fields[34]]),
                 "public-only proof and exact native reply")
            request = b"V" + key + joint + frame[107:SIG_END]
            sig_reply = worker.call(request)
            need(sig_reply == b"1", "public-only authorization over both ordered legs")
            effect = Effect(reply[1:33], le(reply[33:37]), (reply[37:69], reply[69:101]),
                            (reply[101:133], reply[133:165]), le(reply[165:173]),
                            (reply[173:173+CT], reply[173+CT:173+2*CT]), key, reply[-1])
            effects.append(effect)
            output.update({f"reply{side}.bin": reply, f"request{side}.bin": request,
                           f"sigreply{side}.bin": sig_reply})
        worker.close()
    finally:
        worker.abort()
    need(effects[0].key != effects[1].key and [e.fee for e in effects] == [3, 0], "distinct signers and single fee")
    return tuple(frames), effects, joint, output


def header_id(header):
    limbs = lambda raw: tuple(v % P for v in struct.unpack("<4Q", raw))
    return hash_fields((*words(header[:32]), le(header[32:36]), *limbs(header[36:68]),
                        *limbs(header[68:100]), *words(header[100:]), *([0] * 27), 65536))


def flatten(effects, field):
    return tuple(v for effect in effects for v in getattr(effect, field))


def parent_guards(home, effects, status):
    height, tip = status["height"], bytes.fromhex(status["tip"])
    with db_read(node_db(home)) as db:
        db.execute("BEGIN")
        need(db.execute("SELECT h,id FROM sel ORDER BY h DESC LIMIT 1").fetchone() == (height, tip), "selected parent SQL tip")
        outs = tuple(db.execute("SELECT pos,cm,h,ct FROM outs ORDER BY pos"))
        spent = frozenset(row[0] for row in db.execute("SELECT nf FROM spent"))
        cms = tuple(row[1] for row in outs)
        nfs_new, cms_new = (flatten(effects, field) for field in ("nfs", "cms"))
        need(len(spent) == status["spent"] and len(cms) == status["notes"], "complete parent view")
        need(len(set(nfs_new)) == len(set(cms_new)) == 4 and ZERO not in cms_new
             and not spent.intersection(nfs_new) and not set(cms).intersection(cms_new), "block-wide effect guards")
        anchors = {}
        for h, ap, header, count in db.execute(
            "SELECT sel.h,ap,header,n FROM sel JOIN blocks USING(id) WHERE sel.h BETWEEN ? AND ? ORDER BY sel.h",
            (height - 7, height),
        ):
            prefix = [cm for _, cm, born, _ in outs if born <= h]
            tree = Tree(prefix)
            need(le(header[32:36]) == h and tree.count == count and tree.root == header[100:] and header_id(header) == ap,
                 "independently reconstructed selected header and tree")
            anchors[h] = (ap, tree)
        for effect in effects:
            need(1 <= height + 1 - effect.height <= 8, "anchor age")
            ap, tree = anchors[effect.height]
            need(ap == effect.anchor and tree_depth(tree.count) == effect.depth, "selected-branch funded depth")
        case = dict(height=height, cms=list(map(le, cms)), spent=list(map(le, sorted(spent))),
                    anchors=[dict(height=h, ap=le(ap), count=tree.count) for h, (ap, tree) in anchors.items()])
        return case, anchors, outs


def durable_state(home):
    tables = {"blocks": "id", "sel": "h", "outs": "pos", "spent": "nf", "assets": "id,sequence",
              "pool": "seq", "swap_pool": "id", "swap_archive": "id,bid", "txloc": "tx,bid",
              "funded_c_blocks": "id", "funded_upgrade_blocks": "id", "wallet_history_v2": "bid", "metrics": "id"}
    with db_read(node_db(home)) as db:
        db.execute("BEGIN")
        return {table: tuple(db.execute(f"SELECT * FROM {table} ORDER BY {order}")) for table, order in tables.items()}


def reject(lab, op, raw, reason):
    try:
        lab.request("c", op, raw)
    except ValueError as exc:
        need(str(exc) == reason, "node rejected at an unexpected guard")
    else:
        raise ValueError("node accepted an invalid control")


def invalid_block(lab, status, frames):
    from chain import BITS, MAGIC, block_id, decode_block, mine, packet_vector

    parent = bytes.fromhex(status["tip"])
    prefix = MAGIC + NETWORK + bytes([BITS]) + parent + struct.pack("<I", status["height"] + 1)
    pk = lab.address("miner-a")[1:33]
    # Canonical placeholders pass physical parsing. The grouping guard runs before reward and state comparison.
    template = prefix + pk + struct.pack("<Q", 103) + bytes(96) + packet_vector(frames)
    raw = mine(template)
    need(decode_block(raw).packets == tuple(frames) and int.from_bytes(block_id(raw), "big") < 1 << (256-BITS),
         "physical parsing and valid PoW for rejected block")
    return raw


def settle(lab, home, raw, frames, effects, parent):
    ident = digest(raw)
    reply, _ = lab.request("c", "submit", raw)
    need(reply == {"id": ident.hex(), "duplicate": False} and lab.request("c", "pending")[0] == [ident.hex()],
         "complete pair jointly enqueued")
    with db_read(node_db(home)) as db:
        txs = tuple(map(digest, frames))
        need(tuple(db.execute("SELECT tx,packet,nf0,nf1,cm0,cm1,asset FROM pool ORDER BY seq")) ==
             tuple((tx, frame, *e.nfs, *e.cms, None) for tx, frame, e in zip(txs, frames, effects, strict=True))
             and tuple(db.execute("SELECT id,a,b FROM swap_pool")) == ((ident, *txs),), "atomic pool rows")
    selected = lab.mine("c", 1, pay_to="miner-a")
    agree(lab, selected["tip"])
    need(selected["height"] == parent["height"] + 1 and selected["fees"] == parent["fees"] + 3,
         "selected fee and height")
    return bytes.fromhex(selected["tip"])


def committed(home, node, ident, parent, parent_input, raw, frames, effects, registry):
    from chain import block_id, decode_block
    from history import MAGIC, decode_range
    from wire import digest as transition_digest

    with db_read(node_db(home, node)) as db:
        db.execute("BEGIN")
        bid, born, height, sealed, fees, count, header = db.execute(
            "SELECT id,parent,sel.h,raw,fees,n,header FROM sel JOIN blocks USING(id) ORDER BY sel.h DESC LIMIT 1").fetchone()
        block = decode_block(sealed)
        need(bid == ident == block_id(sealed) and born.hex() == parent["tip"] and block.parent == born
             and block.height == height == parent["height"] + 1 and block.packets == frames
             and fees == parent["fees"] + 3 and count == parent["notes"] + 5, "durable selected envelope and fee")
        need(tuple(db.execute("SELECT * FROM assets ORDER BY id,sequence")) == registry, "entire registry unchanged")
        txs = tuple(map(digest, frames))
        need(tuple(db.execute("SELECT tx,idx FROM txloc WHERE bid=? ORDER BY idx", (bid,))) == tuple(zip(txs, (0, 1)))
             and tuple(db.execute("SELECT id,idx FROM swap_archive WHERE bid=?", (bid,))) == ((digest(raw), 0),)
             and db.execute("SELECT 1 FROM funded_c_blocks WHERE id=?", (bid,)).fetchone() == (1,), "archive and profile markers")
        marks = tuple(row[0] for row in db.execute("SELECT nf FROM spent WHERE h=? ORDER BY nf", (height,)))
        need(marks == tuple(sorted(flatten(effects, "nfs"))), "exact durable spent marks")
        before = [le(row[0]) for row in db.execute("SELECT nf FROM spent WHERE h<? ORDER BY nf", (height,))]
        need(before == parent_input["spent"], "older spent marks preserved")
        rows = tuple(db.execute("SELECT pos,cm,ct,reward FROM outs WHERE h=? ORDER BY pos", (height,)))
        context = digest(b"PQDEV1/reward-context\0" + NETWORK + sealed[41:77] + block.pk + digest(sealed[213:-8]))
        mint = context + block.pk + struct.pack("<Q", block.amount) + block.reward_cm
        need(block.amount == 103 and reward(context, block.pk, block.amount).commitment == block.reward_cm
             and len(rows) == 5 and rows[-1] == (count - 1, block.reward_cm, None, mint), "one native miner reward")
        expected = tuple((parent["notes"] + i, cm, ct, None)
                         for i, (cm, ct) in enumerate(zip(flatten(effects, "cms"), flatten(effects, "cts"), strict=True)))
        need(rows[:-1] == expected, "four durable outputs in proof order")
        leaves = [row[0] for row in db.execute("SELECT cm FROM outs ORDER BY pos")]
        need(list(map(le, leaves[:-5])) == parent_input["cms"] and len(leaves) == count
             and Tree(leaves).root == block.root == header[100:], "committed output root and parent occurrences")
        transitions = [b"".join((*e.nfs, *e.cms, struct.pack("<Q", e.fee), ZERO, bytes(8), tx))
                       for e, tx in zip(effects, txs, strict=True)]
        state = transition_digest(b"dev-state", NETWORK, bytes.fromhex(parent["header"])[36:68],
                                  struct.pack("<Q", count), struct.pack("<Q", height * 100), struct.pack("<Q", fees),
                                  mint, b"".join(transitions))
        need(state == block.state == header[36:68], "exact ordered public state transition")
        record, = db.execute("SELECT record FROM wallet_history_v2 WHERE bid=?", (bid,)).fetchone()
        view, = decode_range(MAGIC + bytes([1]) + record)
        need(view["id"] == bid and view["parent"] == born and view["header"] == header and view["reward"] == mint
             and len(view["slots"]) == 2, "durable wallet projection header and reward")
        for slot, effect, tx in zip(view["slots"], effects, txs, strict=True):
            need(slot == dict(txid=tx, fee=effect.fee, envelope_digest=tx, nfs=list(effect.nfs), cms=list(effect.cms),
                              cts=list(effect.cts), issue_id=ZERO, supply=0), "durable per-leg projection")
        need(db.execute("SELECT 1 FROM pool LIMIT 1").fetchone() is None and
             db.execute("SELECT 1 FROM swap_pool LIMIT 1").fetchone() is None, "selected pair removed from pool")
        return dict(nfs=list(map(le, flatten(effects, "nfs"))), cms=[le(row[1]) for row in rows[:-1]],
                    fees=[row["fee"] for row in view["slots"]], registryWrites=0, reward=block.amount, blockHeight=height), rows


def compare_wallets(home, buyer, height, frames, effects, joint, anchors, parent_outs, created, assets, seller_qty):
    deployment = home / "deployment"
    roles = (buyer, "seller")
    seeds = [wallet_folder(home, actor) / "seed" for actor in roles]
    expected_assets = assets[::-1]
    born = {cm: h for _, cm, h, _ in parent_outs}
    counts, output_values = [], []
    cases = []
    for side, (e, actor, seed, asset) in enumerate(zip(effects, roles, seeds, expected_assets, strict=True)):
        folder = wallet_folder(home, actor)
        frame = frames[side]
        with db_read(folder / "mng1-intents.sqlite") as db:
            row = db.execute("SELECT state,public,leg,joint,signature,pins FROM swap_sessions WHERE terms=? AND side=?",
                             (frame[43:75], side)).fetchone()
        need(row is not None and row[:5] == ("released", e.key, frame[SIG_END:], joint, frame[107:SIG_END]),
             "both owner journals authorized this exact ordered pair")
        pins = [bytes.fromhex(value) for value in json.loads(row[-1])]
        receipts = [(pos, cm, ct) for pos, cm, h, ct in parent_outs if h <= e.height and ct is not None]
        true_openings = {cm: details for cm, details in opened(deployment, seed, receipts).items() if details[1] in e.nfs}
        need(set(pins) == set(true_openings) and len(pins) == len(set(pins)) and
             tuple(true_openings[cm][1] for cm in pins) == e.nfs[:len(pins)], "seed-only funded real marks and proof positions")
        tree = anchors[e.height][1]
        amounts, wallet_rows = [], []
        with db_read(folder / "mng1-wallet-state.sqlite") as db:
            for cm in pins:
                pos, nf, cash, opened_asset, tokens, _ = true_openings[cm]
                need(tree.levels[0][pos] == cm and path_root(cm, tree.path(pos), tree.count) == tree.root
                     and opened_asset == asset and cash == (3 if side == 0 else 0), "earlier typed opening and funded path")
                detail = db.execute("SELECT creator,created,spent,spender FROM owned WHERE cm=? AND nf=?", (cm, nf)).fetchone()
                need(detail is not None and detail[1:] == (born[cm], height, digest(frame)), "exact wallet birth/debit attribution")
                amounts.append(tokens)
                wallet_rows.append((tokens, cm, detail[0], born[cm]))
        need(sorted(amounts) == ([5] if side == 0 else seller_qty), "exact real inputs in each leg")
        counts.append(len(pins))
        cases.append(wallet_rows)

        # Slot zero belongs to the counterparty, slot one to the spender, including zero-value change.
        indices = (2 * (1-side), 2*side + 1)
        receipts = [created[index][:3] for index in indices]
        hits = opened(deployment, seed, [record[:3] for record in created[:-1]])
        need(set(hits) == {receipt[1] for receipt in receipts}, "exactly two role-specific output openings")
        incoming, change = [hits[cm][2:] for _, cm, _ in receipts]
        expected_in = (0, assets[side], 50 if side == 0 else 5, "incoming")
        qty = sum(seller_qty) - 50 if side == 1 else 0
        expected_change = (0, asset if qty else ZERO, qty, "change")
        need((incoming, change) == (expected_in, expected_change), "receipt amounts and change marker")
        output_values.append([incoming[2], change[2]])
    return counts, output_values, cases


def run(home, case):
    lab = load_lab(home)
    from chain import NETWORK as deployed_network

    need(deployed_network == NETWORK, "released network identity")
    funding = json.loads((home / "funding.json").read_bytes())
    assets = tuple(bytes.fromhex(funding[k]) for k in ("asset_a", "asset_b"))
    need(assets[0] != assets[1], "distinct assets")
    with ExitStack() as stack:
        lab.start(manual=True)
        stack.callback(lab.stop)
        agree(lab, funding["tip"])
        opening = durable_state(home)
        need(not opening["pool"] and not opening["swap_pool"], "fresh prepared chain with an empty pool")
        registry = opening["assets"]
        supplies = {aid: value for aid, _, _, _, value, _, _ in registry}
        need([supplies[aid] for aid in assets] == [200, 20], "funded fixed asset supplies")
        offer, policy = market_offer(home, funding, stack)

        first = {}
        for buyer, seller_qty in (("buyer-one", [90]), ("buyer-two", [10, 40])):
            parent = lab.status("c")
            raw = sign_fill(home, buyer, offer, policy)
            frames, effects, joint, exchange = verify_bundle(raw, parent["height"] + 1)
            parent_input, anchors, parent_outs = parent_guards(home, effects, parent)
            need(lab.request("c", "pending")[0] == [], "signed-only exchange stayed outside pool")
            if first:
                before = durable_state(home)
                reject(lab, "submit", frames[0], "incomplete atomic swap")
                reject(lab, "publish", invalid_block(lab, parent, frames[:1]), "incomplete atomic swap")
                need(durable_state(home) == before and lab.request("c", "pending")[0] == [],
                     "incomplete exchange changed durable state or pool")
                reject(lab, "publish", invalid_block(lab, parent, frames * 2), "duplicate public effect")
                need(durable_state(home) == before, "whole-block duplicate changed durable state")

            tip = settle(lab, home, raw, frames, effects, parent)
            durable = [committed(home, node, tip, parent, parent_input, raw, frames, effects, registry) for node in "abc"]
            need(durable[0] == durable[1] == durable[2] and lab.request("c", "tx", id=digest(raw).hex())[1] == raw,
                 "all validators stored exact selected pair and effects")
            commit, rows = durable[0]
            for actor in (buyer, "seller"):
                try:
                    cli(home / "participants" / actor, "c", "balance", actor)
                except (ValueError, subprocess.TimeoutExpired):
                    raise ValueError("fixture wallet could not synchronize to the selected fill") from None
            counts, values, inputs = compare_wallets(home, buyer, commit["blockHeight"], frames, effects,
                                                      joint, anchors, parent_outs, rows, assets, seller_qty)
            if not first:
                first = dict(height=commit["blockHeight"], seller=digest(frames[1]), change=effects[1].cms[1],
                             counts=counts, values=values)
                continue

            ten, forty = sorted(inputs[1])
            need(ten[0] == 10 and ten[3] < first["height"] and
                 forty == (40, first["change"], first["seller"], first["height"]),
                 "second fill spent the first fill's exact 40 A change and earlier 10 A")
            before = durable_state(home)
            reject(lab, "submit", raw, "spent nullifier")
            need(durable_state(home) == before, "already-spent pair changed durable state")
            bundle_dir = case / "private-wire"
            bundle_dir.mkdir(mode=0o700)
            for name, value in exchange.items():
                (bundle_dir / name).write_bytes(value)
            for name, value in (("parent.json", parent_input), ("committed.json", commit)):
                (bundle_dir / name).write_text(json.dumps(value) + "\n")
            result = dict(selected_nodes=3, confirmed_fills=2, signed_bundle_bytes=len(raw),
                          registered_leg_proofs=2, accepted_owner_authorizations=2,
                          second_parent_height=parent["height"], second_block_height=commit["blockHeight"],
                          second_anchor_depths=[e.depth for e in effects], second_real_inputs_by_leg=counts,
                          first_real_inputs_by_leg=first["counts"], first_opened_incoming_and_change=first["values"],
                          second_opened_incoming_and_change=values, second_seller_input_A=seller_qty,
                          second_seller_uses_exact_first_change=True, second_buyer_input_B=5, second_buyer_input_native=3,
                          durable_added_marks=len(commit["nfs"]), durable_user_outputs=len(commit["cms"]),
                          durable_miner_outputs=1, native_fee_by_leg=commit["fees"], native_miner_credit=commit["reward"],
                          registry_writes=commit["registryWrites"], selected_anchor_and_state_checked=True,
                          incomplete_pool_submission_rejected=True, incomplete_pow_block_rejected=True,
                          block_wide_duplicate_rejected=True, rejected_cases_left_durable_state_unchanged=True,
                          spent_bundle_rejected=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("network", type=Path, help="fresh network prepared by the funded partial-fills walkthrough")
    parser.add_argument("case", type=Path, help="new private directory for the observer and the public aggregate")
    args = parser.parse_args()
    os.umask(0o077)
    args.case.mkdir(mode=0o700)
    result = run(args.network.resolve(strict=True), args.case.resolve(strict=True))
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    (args.case / "observed.json").write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
