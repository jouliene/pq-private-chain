"""Match fixture economic disclosures to the effects of independently verified blocks."""
from collections import Counter, defaultdict

BURN_FLAG = 1 << 62


def inspect(doc, states, blocks, best, reader):
    stages = {name:states[bytes.fromhex(row['tip'])] for name,row in doc['tips'].items()}
    assert stages.keys() == doc['balances'].keys() == doc['registries'].keys()
    assert set(doc['operations']) == {'alternate','paid','onward','swap','mint','fixed','register','burn','final'}
    assert set(stages) == {'prefix','alternate','paid','onward','swap','mint','fixed','register','crossed','burn','final'}
    final = stages['final']
    assert final is states[best]
    prefix = stages['prefix']
    assert len(prefix.ids) == 25
    alt = stages['alternate']
    assert alt.ids[:25] == final.ids[:25] == prefix.ids and alt.ids[25] != final.ids[25]
    miners = {blocks[prefix.ids[1]].miner:'miner-a',blocks[prefix.ids[4]].miner:'miner-b'}
    assert len(miners) == 2 and {b.miner for b in blocks.values()} == set(miners)
    fixed, = (aid for aid,r in prefix.assets.items() if r.mode == 'fixed')
    managed, = (aid for aid,r in prefix.assets.items() if r.mode == 'managed')
    new_fixed, = (aid for aid,r in final.assets.items() if r.mode == 'fixed' and aid != fixed)
    new_managed, = (aid for aid,r in final.assets.items() if r.mode == 'managed' and aid != managed)
    plans = {
        7:[('miner-a','miner-a',0,fixed,80,80)],
        8:[('miner-b','miner-b',0,managed,100,100)],
        9:[('miner-a','alice',40,fixed,30,0)],
        10:[('miner-b','bob',24,managed,50,0)],
        11:[('miner-a','conflict',20,None,0,0)],
        12:[('miner-b','offline',20,managed,12,0)],
        13:[('miner-b','offline',14,managed,16,0)],
        14:[('alice','bob',0,fixed,7,0),('bob','alice',0,managed,9,0)],
        15:[('miner-b','forward',0,managed,7,7)],
        25:[('offline','recipient',28,managed,25,0)],
        26:[('recipient','forward',20,managed,16,0)],
        27:[('alice','bob',0,fixed,2,0),('bob','alice',0,managed,3,0)],
        28:[('miner-b','forward',0,managed,6,6)],
        29:[('miner-a','miner-a',0,new_fixed,13,13)],
        30:[('miner-a','miner-a',0,new_managed,15,15)],
        32:[('forward','forward',0,managed,0,-16)],
        33:[('recipient','forward',1,managed,1,0)],
    }
    effects = {e.txid:e for b in blocks.values() for e in b.slots}
    for name,entry in doc['operations'].items():
        tx = bytes.fromhex(entry['tx'])
        block = blocks[bytes.fromhex(entry['block'])]
        assert block.height == entry['height']
        if tx in reader.groups:
            assert [e.txid.hex() for e in block.slots] == reader.groups[tx]['frames']
        else:
            assert tx in [e.txid for e in block.slots]
    paid, rival = (bytes.fromhex(doc['operations'][k]['tx']) for k in ('paid','alternate'))
    assert paid != rival and set(effects[paid].nullifiers) == set(effects[rival].nullifiers)
    assert paid in final.locations and rival not in final.locations and paid not in alt.locations
    result = {}
    for name,state in stages.items():
        summary = state.summary() | {'header':state.header.hex()}
        assert all(summary[k] == v for k,v in doc['tips'][name].items())
        assert state.supply() == doc['registries'][name]
        accounts = defaultdict(Counter)
        for bid in state.ids[1:]:
            b = blocks[bid]
            rows = plans.get(b.height, [])
            if bid == alt.ids[25]:
                rows = [('offline','forward',27,managed,24,0)]
            for e, (payer,payee,cash,asset,qty,issued) in zip(b.slots, rows, strict=True):
                delta = BURN_FLAG - e.delta if e.op == 4 else e.delta
                assert delta == issued and (issued == 0 or asset == e.asset)
                accounts[payer]['native'] -= cash + e.fee
                accounts[payee]['native'] += cash
                if asset:
                    accounts[payer][asset.hex()] += issued - qty
                    accounts[payee][asset.hex()] += qty
                assert all(v >= 0 for v in accounts[payer].values())
            accounts[miners[b.miner]]['native'] += b.amount
        assert sum(a['native'] for a in accounts.values()) == summary['issued']
        for aid,reg in state.assets.items():
            assert sum(a[aid.hex()] for a in accounts.values()) == reg.supply
        checked = {}
        assert set(doc['balances'][name]) == {'miner-a','miner-b','alice','bob','conflict','forward','offline','recipient'}
        for owner, claimed in doc['balances'][name].items():
            key = owner.removesuffix('-restored')
            account = accounts[key]
            normalized = dict(native=account['native'], assets={k:v for k,v in account.items() if k!='native' and v})
            assert all(claimed[k] == v for k,v in normalized.items()), (name,owner)
            checked[key] = normalized
        result[name] = dict(fees=state.fees, native=summary['issued'], spent=len(state.spent), wallets_checked=checked)
    return result
