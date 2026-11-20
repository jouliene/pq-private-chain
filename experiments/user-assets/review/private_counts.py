"""Compare local participant-owned rows against the selected public proof effects; export only counts."""
from collections import Counter, defaultdict
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sqlite3

ZERO = bytes(32)


def check(home, replay):
    run = json.loads((home/'public/RUN.json').read_bytes())
    reviewed = json.loads(replay.read_bytes())
    selected = reviewed['disclosures']['selected_action_order']['final']
    expected = run['payments']
    owned_inputs,owned_outputs = defaultdict(list),defaultdict(list)
    wallet_count = 0
    final = run['balances']['final']
    issuer_keys = set()
    for label in ('issuer-a','issuer-b'):
        exported = (home/(label+'.addr')).read_bytes()
        assert len(exported)==1673 and exported[:40] == b'PQDADDR1'+bytes.fromhex(reviewed['network'])
        assert exported[40]==1 and exported[-32:] == sha256(exported[:-32]).digest()
        issuer_keys.add(exported[41:73])
    assert len(issuer_keys)==2
    source = home/'wallets/offline'
    assert not (source/'ast1-wallet-state.sqlite').exists()
    assert (home/'offline-backup').stat().st_size == 32
    for name,balance in final.items():
        owner = 'recovered' if name == 'offline' else name
        database = home/'wallets'/owner/'ast1-wallet-state.sqlite'
        db = sqlite3.connect(database.resolve(strict=True).as_uri()+'?mode=ro',uri=True)
        try:
            tip, = db.execute('SELECT id FROM heads ORDER BY h DESC LIMIT 1').fetchone()
            assert tip.hex() == reviewed['selected']['tip']
            totals = Counter()
            for cm,nf,n,asset,t,kind,created,spent in db.execute(
                    'SELECT cm,nf,amount,asset,token,kind,creator,spender FROM owned'):
                assert (asset == ZERO) == (t == 0)
                if created is not None:
                    owned_outputs[created].append((cm,name,kind,n,asset,t))
                if spent is not None:
                    owned_inputs[spent].append((nf,name,kind,n,asset,t))
                else:
                    totals['native'] += n
                    totals[asset.hex()] += t
            assert totals['native'] == balance['native']
            assert {k:v for k,v in totals.items() if k != 'native' and v} == balance['assets']
            wallet_count += 1
        finally:
            db.close()
    checked_outputs = checked_inputs = 0
    for name in selected:
        r = expected[name]
        tid = bytes.fromhex(r['tx'])
        raw = (home/'public/packets'/(tid.hex()+'.bin')).read_bytes()
        assert sha256(raw).digest() == tid
        end = 9+int.from_bytes(raw[5:9],'little')
        pi = raw[end-248:end]
        assert len(pi)==248
        rows = owned_outputs[tid]
        assert len(rows)==2 and {x[0] for x in rows}=={pi[104:136],pi[136:168]}
        asset = bytes.fromhex(r['asset_id'])
        want = [(r['payee'],'incoming',r['amount'],asset if r['token_amount'] else ZERO,r['token_amount']),
                (r['payer'],'change',r['change'],asset if r['token_change'] else ZERO,r['token_change'])]
        assert sorted(x[1:] for x in rows)==sorted(want)
        inputs = owned_inputs[tid]
        assert len(inputs) == r['real_inputs']
        assert len({x[0] for x in inputs}) == len(inputs) and all(x[0] in (pi[40:72],pi[72:104]) for x in inputs)
        assert all(x[1] == r['payer'] for x in inputs)
        reported = [(x['kind'],x['native'],bytes.fromhex(x['asset']),x['token']) for x in r['input_sources']]
        assert sorted(x[2:] for x in inputs) == sorted(reported)
        checked_inputs += len(inputs)
        checked_outputs += len(rows)
    assert set(owned_outputs) == {bytes.fromhex(expected[s]['tx']) for s in selected} == set(owned_inputs)
    return dict(selected_payments=len(selected), distinct_issuer_spend_keys=len(issuer_keys),
                original_offline_store_absent=True, seed_backup_bytes=32, exact_owned_outputs_checked=checked_outputs,
                owned_inputs_checked_against_public_nullifiers=checked_inputs, wallet_inventories=wallet_count)


if __name__ == '__main__':
    if not __debug__:
        raise SystemExit('assertions are required')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('home',type=Path)
    p.add_argument('public_replay_result',type=Path)
    args=p.parse_args()
    print(json.dumps(check(args.home,args.public_replay_result),sort_keys=True,indent=2))
