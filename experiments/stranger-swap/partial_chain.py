"""Reconcile off-chain fills against exact SWB3 packets selected by the wallet's own validating node."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys


def snapshot(home, node):
    home = Path(home).resolve(strict=True)
    sys.path.insert(0, str(home/"deployment/devnet"))
    from chain import GENESIS, NETWORK, block_id, decode_block
    from cli import Lab
    from swap_wire import bundle, groups
    from swap_wire_c import FRAME

    lab = Lab(home, home/"deployment/runtime")
    cache = sqlite3.connect(home/"market-public-history.sqlite", timeout=60)
    try:
        cache.execute("""CREATE TABLE IF NOT EXISTS blocks
            (id BLOB PRIMARY KEY, parent BLOB NOT NULL, height INTEGER NOT NULL, swaps TEXT NOT NULL)""")
        # A common block request only. No order, note, terms, nullifier or wallet address leaves this adapter.
        for attempt in range(5):
            head = lab.status(node)
            tip, height = bytes.fromhex(head["tip"]), head["height"]
            at, h = tip, height
            found = {}
            with cache:
                while h:
                    row = cache.execute("SELECT parent,height,swaps FROM blocks WHERE id=?",(at,)).fetchone()
                    if row is None:
                        raw = lab.request(node,"block",id=at.hex())[1]
                        b = decode_block(raw)
                        if block_id(raw)!=at or b.height!=h:
                            raise ValueError("inconsistent selected block")
                        position, swaps = 0, []
                        for group in groups(b.packets):
                            if group[0].startswith(FRAME):
                                swaps.append((hashlib.sha256(bundle(group)).hexdigest(),position))
                            position += len(group)
                        row = b.parent,b.height,json.dumps(swaps)
                        cache.execute("INSERT OR IGNORE INTO blocks VALUES(?,?,?,?)",(at,*row))
                    if row[1]!=h:
                        raise ValueError("inconsistent selected height")
                    for ident,pos in json.loads(row[2]):
                        if ident in found:
                            raise ValueError("repeated bundle on selected chain")
                        found[ident] = dict(height=h,block=at.hex(),position=pos)
                    at,h = row[0],h-1
            if at!=GENESIS:
                raise ValueError("wrong funding genesis")
            if lab.status(node)["tip"]==tip.hex():
                return dict(network=NETWORK.hex(),tip=tip.hex(),height=height,bundles=found)
        raise ValueError("selected head changed during observation")
    finally:
        cache.close()


if __name__=="__main__":
    os.umask(0o077)
    home,node = sys.argv[1:]
    print(json.dumps(snapshot(home,node)))
