"""Read the finished walkthrough's local SQLite files without exporting wallet identifiers or notes."""
import argparse
from contextlib import closing
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from struct import unpack_from


NETWORK = bytes.fromhex("7384e1f6a0114d698310e66965beed74870d394214fc5386421d6d4b339f9eac")
H33 = bytes.fromhex("000003b3161779eafe382ebf82daa4a23769d92dfcb3c104d646313f52320f16")
SIGNATURE_BYTES = 17088
LABELS = ("first", "second_reconfirmed", "full")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def readonly(path):
    return closing(sqlite3.connect(path.resolve(strict=True).as_uri() + "?mode=ro", uri=True))


def digest(data):
    return sha256(data).digest()


@dataclass(frozen=True)
class Pair:
    height: int
    block_id: bytes
    bundle_id: bytes
    terms: bytes
    legs: tuple
    signatures: tuple
    frame_ids: tuple
    frame_sizes: tuple
    packet_bytes: int
    block_bytes: int
    fee: int


def parse_block(raw, block_id, height, fee):
    require(len(raw) >= 222 and raw[:8] == b"ASTPOW01" and raw[8:40] == NETWORK and raw[40] == 22, "block header")
    require(unpack_from("<I", raw, 73)[0] == height, "block height")
    calculated = digest(b"PQDEV1/work\0" + digest(b"PQDEV1/template\0" + raw[:-8]) + raw[-8:])
    require(calculated == block_id and int.from_bytes(calculated, "big") < 1 << 234, "block PoW identifier")
    require(unpack_from("<Q", raw, 109)[0] == 100 + fee, "mining reward or fee")
    end, cursor = len(raw) - 8, 214
    frames = []
    require(raw[213] <= 4, "block slot limit")
    for _ in range(raw[213]):
        require(cursor + 4 <= end, "truncated frame length")
        size = unpack_from("<I", raw, cursor)[0]
        cursor += 4
        require(0 < size <= 262144 and cursor + size <= end, "truncated or oversized frame")
        frames.append(raw[cursor:cursor + size])
        cursor += size
    require(cursor == end, "trailing block bytes")
    if not frames:
        require(fee == 0, "fee on empty comparison block")
        return None
    require(len(frames) == 2 and fee == 3, "expected a single atomic swap")
    legs, signatures = [], []
    for side, frame in enumerate(frames):
        require(frame[:5] == b"SWF3\x01" and frame[5:7] == bytes((side, 0)), "frame version, order or fee payer")
        require(frame[11:43] == NETWORK and unpack_from("<I", frame, 7)[0] >= height, "frame network or expiry")
        signature = frame[107:107 + SIGNATURE_BYTES]
        leg = frame[107 + SIGNATURE_BYTES:]
        require(len(signature) == SIGNATURE_BYTES and len(leg) >= 9 and leg[:5] == b"SLG3\x01", "SLG3 encoding")
        require(len(leg) == 9 + unpack_from("<I", leg, 5)[0] + 3584, "proof or receipt length")
        signatures.append(signature)
        legs.append(leg)
    require(frames[0][6:75] == frames[1][6:75] and frames[0][43:75] != bytes(32), "paired authorization fields")
    require(frames[0][75:107] == digest(legs[1]) and frames[1][75:107] == digest(legs[0]), "peer leg binding")
    # The SWB3 network envelope and the block vector use the same two length-prefixed frames.
    packet = b"SWB3\x01" + raw[214:end]
    return Pair(height, block_id, digest(packet), frames[0][43:75], tuple(legs), tuple(signatures),
                tuple(map(digest, frames)), tuple(map(len, frames)), len(packet), len(raw), fee)


def read_nodes(home, funding):
    selected, orphaned = {}, []
    start = funding["height"]
    for node in "abc":
        with readonly(home / "nodes" / node / "chain.sqlite") as db:
            require(db.execute("SELECT id FROM sel WHERE h=33").fetchone() == (H33,), "historical selected branch")
            parent, fees = db.execute("SELECT b.id,b.fees FROM sel s JOIN blocks b ON s.id=b.id WHERE s.h=?",
                                      (start,)).fetchone()
            require(parent.hex() == funding["tip"] and fees == 78, "funding tip or baseline fees")
            pairs = []
            query = "SELECT b.id,b.h,b.raw,b.fees FROM sel s JOIN blocks b ON s.id=b.id WHERE s.h>? ORDER BY s.h"
            for ident, height, raw, cumulative in db.execute(query, (start,)):
                require(raw[41:73] == parent, "selected ancestry")
                pair = parse_block(raw, ident, height, cumulative - fees)
                if pair is not None:
                    pairs.append(pair)
                parent, fees = ident, cumulative
            require(fees == 87 and len(pairs) == 3, "canonical comparison fees or swap count")
            selected[node] = (parent, pairs)
            if node == "c":
                query = ("SELECT b.id,b.h,b.raw,b.fees - p.fees FROM blocks b JOIN blocks p ON p.id=b.parent "
                         "LEFT JOIN sel s ON s.id=b.id WHERE b.h>? AND s.id IS NULL")
                for ident, height, raw, cost in db.execute(query, (start,)):
                    pair = parse_block(raw, ident, height, cost)
                    if pair is not None:
                        orphaned.append(pair)
    require(selected["a"] == selected["b"] == selected["c"], "validators disagree on selected history")
    tip, pairs = selected["c"]
    require(len(orphaned) == 1 and orphaned[0].bundle_id == pairs[1].bundle_id and
            orphaned[0].block_id != pairs[1].block_id, "second swap orphan and exact reinclusion")
    require(len({p.terms for p in pairs}) == 3 and len({s for p in pairs for s in p.signatures}) == 6,
            "reused terms or signature")
    return tip, pairs, orphaned[0]


def owned_sources(home, role, pair, side):
    directory = home / "participants" / role / "wallets" / role
    with readonly(directory / "mng1-intents.sqlite") as outbox:
        row = outbox.execute("SELECT leg,signature,pins FROM swap_sessions WHERE terms=? AND side=?",
                             (pair.terms, side)).fetchone()
        require(row is not None and row[:2] == (pair.legs[side], pair.signatures[side]), "owner signing journal")
        commitments = [bytes.fromhex(s) for s in json.loads(row[2])]
    with readonly(directory / "mng1-wallet-state.sqlite") as wallet:
        wallet.row_factory = sqlite3.Row
        rows = [wallet.execute("SELECT created,creator,spent,spender,token,asset,amount FROM owned WHERE cm=?",
                               (c,)).fetchone() for c in commitments]
    require(all(r is not None and r["spent"] == pair.height and r["spender"] == pair.frame_ids[side] for r in rows),
            "source was not spent by the exact selected frame")
    return rows


def verify(directory):
    home = directory / "network"
    funding = json.loads((home / "funding.json").read_bytes())
    summary = json.loads((directory / "result.json").read_bytes())
    tip, pairs, orphan = read_nodes(home, funding)
    require(summary["selected"]["tip"] == tip.hex() and summary["fills"]["second_before_reorg"]["block"] ==
            orphan.block_id.hex(), "walkthrough branch reports")
    asset_a, asset_b = (bytes.fromhex(funding[key]) for key in ("asset_a", "asset_b"))
    expected = (("seller", "buyer-one", [90], 5), ("seller", "buyer-two", [10, 40], 5),
                ("full-seller", "full-buyer", [10, 90], 10))
    outputs = {}
    for label, pair, (seller, buyer, quantities, price) in zip(LABELS, pairs, expected, strict=True):
        reported = summary["fills"][label]
        require(reported["bundle_sha256"] == pair.bundle_id.hex() and reported["block"] == pair.block_id.hex()
                and reported["packet_B"] == pair.packet_bytes and reported["block_B"] == pair.block_bytes
                and reported["physical_frames_B"] == list(pair.frame_sizes) and reported["fee"] == pair.fee,
                "published size, fee or inclusion mismatch")
        a = owned_sources(home, seller, pair, 1)
        b = owned_sources(home, buyer, pair, 0)
        require(sorted(r["token"] for r in a) == quantities and all(r["asset"] == asset_a and r["amount"] == 0 for r in a),
                "maker source composition")
        require(len(b) == 1 and (b[0]["token"], b[0]["asset"], b[0]["amount"]) == (price, asset_b, 3),
                "buyer did not fund the exact token amount and native fee")
        if label == "second_reconfirmed":
            change = next(r for r in a if r["token"] == 40)
            require(change["created"] == pairs[0].height and change["creator"] == pairs[0].frame_ids[1],
                    "second fill did not spend the first fill's change")
        outputs[label] = dict(seller_source_A=quantities, buyer_source_B=price, buyer_source_native=3,
                              physical_frame_B=list(pair.frame_sizes), bundle_B=pair.packet_bytes,
                              selected_height=pair.height, fee=pair.fee)
    comparison = {}
    for label, selected in (("two_partial", pairs[:2]), ("one_full", pairs[2:])):
        row = dict(packet_B=sum(p.packet_bytes for p in selected), block_B=sum(p.block_bytes for p in selected),
                   packet_list_B=sum(1 + 8 + sum(p.frame_sizes) for p in selected), fee=sum(p.fee for p in selected))
        require(row == summary["comparison"][label], "comparison did not match independent block parsing")
        comparison[label] = row
    return dict(selected_nodes=3, confirmed_pairs=3, distinct_final_signatures=6, orphaned_pair_reincluded=True,
                second_fill_spent_first_40A_change=True, fills=outputs, comparison=comparison)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="directory produced by the partial-fills walkthrough")
    print(json.dumps(verify(parser.parse_args().directory), indent=2))
