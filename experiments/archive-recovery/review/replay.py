"""Independently verify the A/B public graph and compare the home node's durable state."""
import argparse
from contextlib import closing, ExitStack
import json
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'funded-upgrade/review'))
from public import MANAGED, PINS, Reader, mount, read_graph, selected_summary
sys.path.insert(0, str(HERE))
from economics import reconcile
from chain_audit import compare_db
from wallet_joins import block_packets


def common_height(left, right):
    return next((h - 1 for h, (a, b) in enumerate(zip(left.ids, right.ids)) if a != b),
                min(len(left.ids), len(right.ids)) - 1)


def receipt_record(block, state):
    body = bytearray(struct.pack('<I', block.height) + block.id + block.parent + state.header +
                     block.reward_record + bytes([len(block.slots)]))
    for event in block.slots:
        body.extend(event.txid + b''.join(event.nullifiers))
        for i, cm in enumerate(event.commitments):
            body.extend(cm + event.receipts[i * 1792:(i + 1) * 1792])
        flag = 2 if event.fee == 0 else int(not event.legacy)
        body.extend(event.asset + struct.pack('<QB', event.delta, flag))
    return bytes(body)


def inspect_home(store, window, public, states, blocks, state, reader):
    checks = compare_db(store, state)
    height = len(state.ids) - 1
    assert 0 < window < height
    pruned, retained = set(), set()
    with closing(sqlite3.connect(store.resolve(strict=True).as_uri() + '?mode=ro', uri=True)) as db:
        rows = db.execute('SELECT id,h,raw FROM blocks WHERE h>0 ORDER BY h').fetchall()
        assert [(bid,h) for bid,h,_ in rows] == [(bid,h) for h,bid in enumerate(state.ids) if h]
        assert db.execute('PRAGMA foreign_key_check').fetchall() == []
        for bid, h, raw in rows:
            captured = (public / 'blocks' / (bid.hex() + '.bin')).read_bytes()
            if h > height - window:
                assert raw == captured
                retained.update(block_packets(captured))
            else:
                assert raw == b''
                pruned.update(block_packets(captured))
        actual = dict(db.execute('SELECT bid,record FROM wallet_history_v2'))
        expected = {bid: receipt_record(blocks[bid], states[bid]) for bid in state.ids[1:]}
        assert actual == expected
        swaps = sorted((key, state.locations[bytes.fromhex(group['frames'][0])])
                       for key,group in reader.groups.items()
                       if bytes.fromhex(group['frames'][0]) in state.locations)
        assert sorted(db.execute('SELECT id,bid FROM swap_archive')) == swaps
    # Inspect every regular file in the stopped home role, including free pages and SQLite journals.
    # Use an interior proof fragment for each physically pruned nonempty frame.
    for bid in blocks.keys() - set(state.ids):
        captured = (public / 'blocks' / (bid.hex() + '.bin')).read_bytes()
        pruned.update(block_packets(captured))
    samples = {frame[len(frame)//2:len(frame)//2 + 96] for frame in pruned - retained}
    assert samples
    disk_bytes = sqlite_bytes = files_checked = 0
    sidecars = {store.name + suffix for suffix in ('-wal', '-shm', '-journal')}
    for path in store.parent.rglob('*'):
        assert not path.is_symlink(), 'unexpected indirect home storage'
        if not path.is_file():
            continue
        size = path.stat().st_size
        disk_bytes += size
        if path == store or path.name in sidecars:
            sqlite_bytes += size
        files_checked += 1
        previous = b''
        with path.open('rb') as file:
            while chunk := file.read(1024 * 1024):
                segment = previous + chunk
                assert not any(sample in segment for sample in samples), 'old proof fragment left in home storage'
                previous = segment[-95:]
    return dict(**checks, retained_full_blocks=window, physically_pruned_blocks=height-window,
                old_proof_samples_absent=len(samples), sqlite_and_sidecars_B=sqlite_bytes,
                home_files_checked=files_checked, home_files_B=disk_bytes,
                receipt_history_records_compared=len(expected), exact_selected_asset_and_nullifier_state=True)


def replay(public, deployment, helpers, node, store=None, window=None):
    with ExitStack() as stack:
        roles = {name: mount(stack, deployment, name, *params)[0] for name,params in PINS.items()}
        reader = Reader(roles, helpers, node)
        states, blocks, tips, best = read_graph(public, reader, helpers)
        signatures = sorted(reader.authorizations | set(reader.historical.sigs))
        assert signatures and subprocess.check_output([node, MANAGED / 'verify_slh.mjs'],
            input=b''.join(signatures), timeout=60) == b'1' * len(signatures)
        state = states[best]
        summary = selected_summary(state, reader)
        assert sorted((v.mode, v.supply) for v in state.assets.values()) == [('fixed', 80), ('managed', 100)]
        assert summary['atomic_swaps'] >= 1 and reader.calls['MNG1'] and reader.calls['MNG2'] and reader.calls['SLG2']
        assert len(tips) >= 2
        divergent = [(common_height(states[t], state), len(states[t].ids)-1, t) for t in tips if t != best]
        assert any(fork == 14 and tip-fork > 8 for fork,tip,_ in divergent)
        miner_fees = {}
        for bid in state.ids[1:]:
            block = blocks[bid]
            miner = block.miner.hex()
            miner_fees[miner] = miner_fees.get(miner, 0) + block.amount - 100
        assert sum(miner_fees.values()) == state.fees
        result = dict(genesis=state.ids[0].hex(), network=reader.network.hex(), captured_blocks=len(blocks),
                      public_proof_calls=dict(reader.calls), public_signatures_checked=len(signatures),
                      selected=summary, selected_miner_fees=miner_fees,
                      branches=[dict(common_height=h, detached_tip=selected_summary(states[t], reader))
                                for h,_,t in sorted(divergent)], signed_swaps=len(reader.groups))
        scenario = json.loads((public / 'SCENARIO.json').read_bytes())
        outcome = json.loads((public / 'OUTCOME.json').read_bytes())
        result['disclosed_fixture'] = reconcile(scenario, outcome, states, blocks, reader, best)
        if store is not None:
            result['home'] = inspect_home(store, window, public, states, blocks, state, reader)
        return result


if __name__ == '__main__':
    if not __debug__:
        sys.exit('Python assertions must be enabled')
    p = argparse.ArgumentParser(description=__doc__)
    for arg in ('public','deployment','helpers','node'):
        p.add_argument(arg, type=Path)
    p.add_argument('--store', type=Path, help='stopped pruned node database')
    p.add_argument('--window', type=int)
    args = p.parse_args()
    if (args.store is None) != (args.window is None):
        p.error('--store and --window must appear together')
    print(json.dumps(replay(**vars(args)), sort_keys=True, indent=2))
