"""Reconcile a selected prefix using funded receipt openings. Keep true note identities local."""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "funded-conservation"))
from audit import opened
sys.path.insert(0, str(HERE.parent / "snapshot-bootstrap/review"))
from check import GENESIS, NETWORK, WireReader, chain_to, check_store, read_block, require, selected_ledger

ZERO = bytes(32)
BURN = 1 << 62
TIP = "000003b3161779eafe382ebf82daa4a23769d92dfcb3c104d646313f52320f16"


def parse_blocks(directory):
    reader = WireReader()
    return {bytes.fromhex(f.stem): read_block(f.read_bytes(), bytes.fromhex(f.stem), NETWORK, reader)
            for f in directory.glob("*.bin")}


def open_inventory(deployment, blocks, wallets):
    """Restore each independent seed separately, try the exact public ciphertext and CM, discard identities at export."""
    sys.path.insert(0, str(deployment / "devnet"))
    records = {}
    for b in blocks:
        for slot in b.slots:
            for i, cm in enumerate(slot.commitments):
                ct = slot.receipts[1792*i:1792*(i+1)]
                require(cm not in records or records[cm] == ct, "inconsistent receipt for a commitment")
                records[cm] = ct
    rows = [(i, cm, ct) for i, (cm, ct) in enumerate(records.items())]
    inventory = {}
    for backup in wallets:
        found = opened(deployment, backup, rows)
        require(not inventory.keys() & found.keys(), "receipt claimed by several wallet keys")
        inventory.update(found)
    require(len(inventory) == len(records), f"opened only {len(inventory)} of {len(records)} receipts")
    true_nfs = [v[1] for v in inventory.values()]
    require(len(set(true_nfs)) == len(true_nfs), "aliased true nullifiers in fixture openings")
    return inventory


def reconcile(blocks, inventory):
    """Seed a disjoint new suffix with zero or reconcile the whole known test roster from genesis."""
    ledger = {}
    live, seen = {}, set()
    observations = []
    for b in blocks:
        for s in b.slots:
            incoming, outgoing = Counter(), Counter()
            for nf in s.nullifiers:
                require(nf not in seen, "duplicate selected nullifier")
                seen.add(nf)
                if nf in live:
                    asset, q = live.pop(nf)
                    incoming[asset] += q
            for cm in s.commitments:
                _, nf, _, asset, q, _ = inventory[cm]
                require(nf not in live and nf not in seen, "new output has spent or aliased fixture NF")
                if q:
                    require(asset != ZERO, "positive amount with zero ID")
                    live[nf] = (asset, q)
                    outgoing[asset] += q
            delta = 0 if s.op == 0 else BURN-s.delta if s.op == 4 else s.delta
            for aid in incoming.keys() | outgoing.keys() | {s.asset}:
                require(outgoing[aid]-incoming[aid] == (delta if aid == s.asset else 0),
                        "opened per-asset effect disagrees with the proved public delta")
            if s.op:
                before = ledger.get(s.asset, 0)
                after = before + delta
                require(0 <= after < BURN, "registry range")
                ledger[s.asset] = after
                observations.append(dict(height=b.height, operation=("ordinary","fixed","register","mint","burn")[s.op],
                                         tx=s.txid.hex(), asset=s.asset.hex(), token_in=incoming[s.asset],
                                         token_out=outgoing[s.asset], encoded_delta=s.delta, delta=delta, before=before, after=after))
        actual = Counter()
        for aid, q in live.values():
            actual[aid] += q
        require(all(actual[aid] == qty for aid,qty in ledger.items()) and not (actual.keys()-ledger.keys()),
                "live opened face values disagree with accumulated supply")
    return observations, {k.hex():v for k,v in sorted(ledger.items())}


def historical(public, deployment=None, original=None):
    doc = json.loads((public/"RUN.json").read_bytes())
    graph = parse_blocks(public/"blocks")
    chain = chain_to(graph, bytes.fromhex(TIP))
    fixture = selected_ledger(chain)
    require(doc["tips"]["final"]["tip"] == TIP and
            {aid.hex():r.public(aid) for aid,r in fixture.assets.items()} == doc["registries"]["final"],
            "public selected registry disagrees with wire replay")
    # Compare owning-wallet disclosures at each captured state, including the sibling H25 branch.
    for stage, info in doc["tips"].items():
        reg = selected_ledger(chain_to(graph, bytes.fromhex(info["tip"]))).assets
        sums = Counter()
        for row in doc["balances"][stage].values():
            sums.update(row["assets"])
        require({aid.hex():r.supply for aid,r in reg.items()} == dict(sums), "published holdings and registry")
    events = [dict(height=b.height, tx=s.txid.hex(), asset=s.asset.hex(), encoded_delta=s.delta)
              for b in chain if b.height>=25 for s in b.slots if s.op]
    require([r["height"] for r in events]==[28,29,30,32], "historical C event coverage")
    report = dict(tip=TIP, selected_blocks=len(chain), captured_stages=len(doc["tips"]), events=events,
                  registry={aid.hex():r.supply for aid,r in fixture.assets.items()})
    if original is not None:
        wallets = [original/"owner-backups"/actor for actor in ("alice","bob","conflict","forward","miner-a","miner-b","offline")]
        wallets.append(original/"membership-negotiation/receiver.backup")
        observed = open_inventory(deployment, graph.values(), wallets)
        for stage, info in doc["tips"].items():
            logged, funds = reconcile(chain_to(graph, bytes.fromhex(info["tip"])), observed)
            require(funds=={k:r["supply"] for k,r in doc["registries"][stage].items()}, "opened selected wallet holdings")
        logged, funds = reconcile(chain, observed)
        report.update(opened_roles=len(wallets), opened_receipt_commitments=len(observed),
                      opened_events=[e for e in logged if e["height"]>=25], opened_final=funds)
    return report


if __name__ == "__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("public",type=Path)
    p.add_argument("--original",type=Path,help="private historical test network home containing the original owner backups")
    p.add_argument("--deployment",type=Path)
    args=p.parse_args()
    require((args.original is None)==(args.deployment is None), "supply both original private home and pinned deployment")
    print(json.dumps(historical(args.public,args.deployment,args.original),indent=2,sort_keys=True))
