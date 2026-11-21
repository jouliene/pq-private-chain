"""Reconcile the numerical fixture independently of the wallet's balances and labels."""
from collections import Counter, defaultdict


# Amounts and participants were disclosed for this research run. They are not decoded from ciphertexts.
def balances(state, blocks, names, miners, plan):
    accounts = defaultdict(Counter)
    for bid in state.ids[1:]:
        block = blocks[bid]
        for e in block.slots:
            payer, payee, native, tag, quantity, issuance = plan[names[e.txid]]
            assert e.delta == issuance and (not issuance or e.asset.hex() == tag)
            accounts[payer]['native'] -= native + e.fee
            accounts[payee]['native'] += native
            if tag:
                accounts[payer][tag] += issuance - quantity
                accounts[payee][tag] += quantity
            assert all(v >= 0 for v in accounts[payer].values())
        accounts[miners[block.miner]]['native'] += block.amount
    assert sum(a['native'] for a in accounts.values()) == 100 * (len(state.ids) - 1)
    for tag, rec in state.assets.items():
        assert sum(a[tag.hex()] for a in accounts.values()) == rec.supply
    return accounts


def audit(doc, states, blocks, reader, winner):
    final = states[winner]
    assert doc['network'] == reader.network.hex() and doc['genesis'] == final.ids[0].hex()
    miners = {blocks[final.ids[1]].miner:'miner-a', blocks[final.ids[4]].miner:'miner-b'}
    assert len(miners) == 2 and set(miners) == {b.miner for b in blocks.values()}
    fixed, managed = doc['asset_ids']['fixed'], doc['asset_ids']['managed']
    # Sender, receiver, native payment, private asset, private quantity and public issuance.
    plan = {
        'issue-fixed': ('miner-a','miner-a',0,fixed,80,80),
        'register-managed': ('miner-b','miner-b',0,managed,100,100),
        'fund-fixed': ('miner-a','alice',40,fixed,30,0),
        'fund-managed': ('miner-b','bob',24,managed,50,0),
        'fund-conflict': ('miner-a','conflict',20,'',0,0),
        'fund-offline': ('miner-b','offline',20,managed,12,0),
        'a-conflict': ('conflict','rival',8,'',0,0),
        'b-conflict': ('conflict','recipient',9,'',0,0),
        'restored-a-to-b': ('offline','forward',12,managed,8,0),
        'b-to-b': ('forward','recipient',5,managed,6,0),
    }
    assert set(plan) == set(doc['ordinary'])
    names = {bytes.fromhex(row['tx']):key for key,row in doc['ordinary'].items()}
    for tx, label in names.items():
        assert reader.bytes_by_id[tx] == doc['ordinary'][label]['packet_B']
    group, = reader.groups.values()
    plan.update({'swap-a':('alice','bob',0,fixed,7,0), 'swap-b':('bob','alice',0,managed,9,0)})
    names.update({bytes.fromhex(frame):name for frame,name in zip(group['frames'], ('swap-a','swap-b'), strict=True)})
    assert len(names) == len(plan) and group['fee_by_leg'] == [3,0]
    by_stage = {name:states[bytes.fromhex(tip['tip'])] for name,tip in doc['tips'].items()}
    assert final is by_stage['final']
    common, a, b = [by_stage[k] for k in ('common','a_overlap','b_overlap')]
    assert a.ids[:-1] == b.ids[:-1] == common.ids and a.ids != b.ids
    settled, detached = by_stage['b_settled'], by_stage['b_detached']
    assert a.ids == detached.ids[:len(a.ids)] and b.ids == settled.ids[:len(b.ids)]
    assert settled.ids == final.ids[:len(settled.ids)] and len(settled.ids) < len(detached.ids) < len(final.ids)
    assert (common.fees, a.fees, b.fees, settled.fees, detached.fees, final.fees) == (18,21,21,30,21,30)
    assert (len(common.spent), len(settled.spent), len(detached.spent)) == (12,22,14)
    receipts = {}
    for label, st in by_stage.items():
        claimed = doc['tips'][label]
        summary = st.summary() | {'header':st.header.hex()}
        assert all(summary[k] == v for k,v in claimed.items())
        if label in doc['registries']:
            assert st.supply() == doc['registries'][label]
        accounts = balances(st, blocks, names, miners, plan)
        checked = {}
        for owner, reported in doc['balances'].get(label, {}).items():
            inv = accounts[owner.removesuffix('-restored')]
            actual = dict(native=inv['native'], assets={k:v for k,v in inv.items() if k!='native' and v})
            assert actual == reported, (label,owner)
            checked[owner] = actual
        receipts[label] = dict(height=len(st.ids)-1, fees=st.fees, wallets=checked)
    return receipts
