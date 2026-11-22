"""Compare the selected singleton to opened wallet notes, the registered verifier and one miner credit."""
from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path
import shutil
import sqlite3
import sys
from tempfile import TemporaryDirectory

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "funded-membership"))
from conformance import public_inputs
from reference import Tree, ZERO, need, path_root, reward, tree_depth

HISTORIC_TX = "96599833fcd217a37dc07ae078c72bca18ef89bf8b507f545413643f3fc551e3"
HISTORIC_BLOCK = "0000019c59d8c250bd834396eee35bb8a098c6e6c2aa67d97211136d20cf64a8"


def opened(deployment, seedfile, rows):
    """Scan actual ciphertext/commitment pairs using a new C wallet role with this seed only."""
    from wallet_c import CWallet
    binary = deployment / "c-runtime/native"
    pin = (deployment / "devnet/approved-c-native.sha256").read_text().strip()
    need(seedfile.stat().st_size == 32 and seedfile.stat().st_mode & 0o077 == 0, "private test backup")
    with TemporaryDirectory() as temp:
        seed = Path(temp) / "seed"
        shutil.copyfile(seedfile, seed)
        seed.chmod(0o600)
        with CWallet(binary, pin, deployment / "c-keys", seed.parent) as wallet:
            found = {}
            for pos, cm, ct in rows:
                hit = wallet.open_row(cm + ct)
                if hit:
                    nf, native, asset, token, kind = hit
                    need(cm not in found, "one opening per commitment")
                    found[cm] = (pos, nf, native, asset, token, kind)
            return found


def public_proof(packet, pi):
    from consensus import role
    verifier = role("managed")
    try:
        result = verifier.call(packet[6:])
        expected = b"1" + pi[:36] + pi[40:176] + packet[-3584:] + pi[208:-8] + bytes([pi[-8]])
        need(result == expected, "public C verifier effects")
        verifier.close()
    finally:
        verifier.abort()


def inspect(deployment, dbfile, tx_hex, seeds=None):
    sys.path.insert(0, str(deployment / "devnet"))
    from chain import block_id, decode_block, packet_vector, reward_context
    tx = bytes.fromhex(tx_hex)
    with closing(sqlite3.connect(dbfile.resolve().as_uri()+"?mode=ro", uri=True)) as db:
        db.execute("BEGIN")
        row, = db.execute("SELECT raw,id FROM txloc JOIN sel ON bid=id JOIN blocks USING(id) WHERE tx=?", (tx,))
        raw, bid = row
        b = decode_block(raw)
        need(block_id(raw) == bid and len(b.packets) == 1, "one selected mined payment")
        packet, = b.packets
        need(sha256(packet).digest() == tx and packet.startswith(b"MSP3\x01\x00MNG3\x01"), "ordinary C packet")
        tag, pi = public_inputs(packet)
        need(tag == "MNG3" and len(pi) == 256 and pi[208:248] == bytes(40), "zero public issue ID and delta")
        public_proof(packet, pi)
        fee = int.from_bytes(pi[168:176], "little")
        anchor_h = int.from_bytes(pi[32:40], "little")
        anchor_id, header, count = db.execute("SELECT ap,header,n FROM sel JOIN blocks USING(id) WHERE sel.h=?",
                                              (anchor_h,)).fetchone()
        need(1 <= b.height-anchor_h <= 8 and pi[:32] == anchor_id, "selected eligible anchor")
        leaves = [r[0] for r in db.execute("SELECT cm FROM outs WHERE h<=? ORDER BY pos", (anchor_h,))]
        tree = Tree(leaves)
        need(count == tree.count and tree.root == header[-32:] and
             tree_depth(count) == int.from_bytes(pi[-8:], "little"), "independent anchor root, depth and count")
        nfs, cms = (pi[40:72], pi[72:104]), (pi[104:136], pi[136:168])
        spent = list(db.execute("SELECT nf FROM spent WHERE h=?", (b.height,)))
        need(len(spent) == 2 and set(nfs) == {v for (v,) in spent}, "selected nullifier changes")
        rows = list(db.execute("SELECT pos,cm,ct,reward FROM outs WHERE h=? ORDER BY pos", (b.height,)))
        need(len(rows) == 3 and tuple(r[1] for r in rows[:2]) == cms and
             b"".join(r[2] for r in rows[:2]) == packet[-3584:] and rows[-1][2] is None, "selected output rows")
        ctx = reward_context(b.parent, b.height, b.pk, packet_vector(b.packets))
        note = reward(ctx, b.pk, b.amount)
        need(rows[-1][1] == b.reward_cm == note.commitment and note.token == 0 and
             rows[-1][3] == ctx+b.pk+b.amount.to_bytes(8,"little")+b.reward_cm, "funded miner note")
        before, after = [db.execute("SELECT fees FROM blocks WHERE id=?", (v,)).fetchone()[0] for v in (b.parent,bid)]
        need(after-before == fee == b.amount-100 == 3, "single miner fee above subsidy")
        need(not db.execute("SELECT 1 FROM assets WHERE h=?", (b.height,)).fetchone(), "ordinary registry transition")
        result = dict(tx=tx_hex, block=bid.hex(), height=b.height, packet_bytes=len(packet),
                      anchor_height=anchor_h, anchor_count=count, depth=tree_depth(count),
                      spent_added=len(spent), user_output_count=2, reward_output_count=1,
                      cumulative_fees=[before,after], fee=fee, subsidy=100, miner_credit=b.amount,
                      public_issue_delta=0, registered_public_verification=True)
        if seeds is None:
            return result
        funding = list(db.execute("SELECT pos,cm,ct FROM outs WHERE h<=? AND ct IS NOT NULL ORDER BY pos", (anchor_h,)))
        current = [r[:3] for r in rows[:2]]
        payer = opened(deployment, seeds[0], funding+current)
        recipient = opened(deployment, seeds[1], current)
        inputs = [(cm, v) for cm, v in payer.items() if v[1] in nfs]
        need(len(inputs) == 2 and {v[1] for _,v in inputs} == set(nfs), "both real opened funding notes")
        for cm, v in inputs:
            need(leaves[v[0]] == cm and path_root(cm, tree.path(v[0]), count) == tree.root, "selected funded opening")
        payee, = recipient
        change, = set(cms).intersection(payer)
        need({payee, change} == set(cms) and payee != change and
             recipient[payee][5] == "incoming" and payer[change][5] == "change", "two different wallet roles")
        owned = [v for _,v in sorted(inputs, key=lambda item: item[1][0])] + [recipient[payee], payer[change]]
        asset, = {v[3] for v in owned}
        need(asset != ZERO and db.execute("SELECT 1 FROM assets WHERE id=? AND h<?", (asset,b.height)).fetchone(),
             "one previously registered user asset")
        amounts = [[v[2], v[4]] for v in owned]
        need(amounts == [[20,12],[14,16],[28,25],[3,3]], "published funded wallet fixture amounts")
        for i in range(2):
            need(sum(r[i] for r in amounts[:2]) == sum(r[i] for r in amounts[2:]) + (fee if i==0 else 0),
                 "integer projection of opened notes")
        return dict(result, opened_inputs=amounts[:2], opened_outputs=amounts[2:], test_asset=asset.hex(),
                    funded_input_paths_checked=2, seed_only_opening_roles=2)


if __name__ == "__main__":
    # Optional original-owner check. No backup or note opening is included in public evidence.
    deployment, database, payer, recipient = map(Path, sys.argv[1:])
    result = inspect(deployment, database, HISTORIC_TX, (payer, recipient))
    need(result["block"] == HISTORIC_BLOCK, "historical fixture identity")
    print(json.dumps(result, indent=2, sort_keys=True))
