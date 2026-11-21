"""Reconcile disclosed fixture amounts with byte-verified public effects on each branch."""
from fixture_amounts import balances


def reconcile(scenario, outcome, states, blocks, reader, best):
    # The private transfer amounts and participant labels are experiment disclosures.
    # Issuance deltas, fee credits, transaction identities and selection are public.
    fixed, managed = (scenario['asset_ids'][key] for key in ('fixed','managed'))
    plan = {
        'issue-fixed': ('miner-a','miner-a',0,fixed,80,80),
        'register-managed': ('miner-b','miner-b',0,managed,100,100),
        'fund-fixed': ('miner-a','alice',40,fixed,30,0),
        'fund-managed': ('miner-b','bob',24,managed,50,0),
        'fund-conflict': ('miner-a','conflict',20,'',0,0),
        'fund-offline': ('miner-b','offline',20,managed,12,0),
        'fund-offline-b': ('miner-b','offline',14,managed,16,0),
        'branch-mint': ('miner-b','forward',0,managed,7,7),
    }
    assert set(plan) == scenario['ordinary'].keys()
    names = {bytes.fromhex(row['tx']):label for label,row in scenario['ordinary'].items()}
    group, = reader.groups.values()
    names.update({bytes.fromhex(frame):name for frame,name in zip(group['frames'], ('swap-a','swap-b'), strict=True)})
    plan.update({'swap-a':('alice','bob',0,fixed,7,0), 'swap-b':('bob','alice',0,managed,9,0)})
    attempts = [bytes.fromhex(outcome[name]) for name in ('initial_spend','final_spend')]
    for i,tx in enumerate(attempts):
        names[tx] = f'recovered-{i}'
        plan[names[tx]] = ('offline','forward',28,managed,25,0)
    assert len(names) == len(plan)
    initial = states[bytes.fromhex(scenario['tips']['initial']['tip'])]
    fork = states[bytes.fromhex(scenario['tips']['fork']['tip'])]
    old = states[bytes.fromhex(outcome['initial_settled'])]
    new = states[bytes.fromhex(outcome['reorganized'])]
    final = states[bytes.fromhex(outcome['final'])]
    assert states[best] is final
    assert old.ids[:len(initial.ids)] == initial.ids
    assert len(fork.ids) == 15 and old.ids[:15] == new.ids[:15] == fork.ids
    assert old.ids[15] != new.ids[15] and final.ids[:len(new.ids)] == new.ids
    state_fees = [s.fees for s in (fork,initial,old,new,final)]
    assert state_fees == [24,27,30,24,27]
    assert [s.supply()[managed]['supply'] for s in (fork,initial,old,new,final)] == [100,107,107,100,100]
    spend_events = []
    for tx,expected in zip(attempts,(old,final), strict=True):
        block = blocks[expected.locations[tx]]
        assert block.height < len(expected.ids) - 1
        event, = [e for e in block.slots if e.txid == tx]
        spend_events.append(event)
    assert set(spend_events[0].nullifiers) == set(spend_events[1].nullifiers)
    assert all(not set(attempts).issubset(s.locations) for s in states.values())
    assert not any(nf in new.spent for nf in spend_events[0].nullifiers)
    miners = {blocks[final.ids[1]].miner:'miner-a', blocks[final.ids[4]].miner:'miner-b'}
    assert len(miners) == 2
    for block in blocks.values():
        miners.setdefault(block.miner, 'miner-' + block.miner.hex())

    stages = {k:states[bytes.fromhex(v['tip'])] for k,v in scenario['tips'].items()}
    stages.update(initial_settled=old,reorganized=new,final=final)
    claims = dict(scenario['balances'])
    claims.update(outcome['balances'])
    result = {}
    for label, state in stages.items():
        if label in scenario['tips']:
            snapshot = state.summary() | {'header':state.header.hex()}
            assert all(snapshot[k] == v for k,v in scenario['tips'][label].items())
        if label in scenario['registries']:
            assert state.supply() == scenario['registries'][label]
        if label in outcome['balances']:
            assert set(claims[label]) == {'offline','forward','miner-a','miner-b','alice','bob','conflict'}
        accounts = balances(state, blocks, names, miners, plan)
        def normalized(account):
            return dict(native=account['native'], assets={k:v for k,v in account.items() if k != 'native' and v})
        for owner, reported in claims[label].items():
            expected = normalized(accounts[owner.removesuffix('-restored')])
            assert all(reported[k] == v for k,v in expected.items()), (label,owner)
        result[label] = dict(height=len(state.ids) - 1, issued=100 * (len(state.ids) - 1), fees=state.fees,
                             managed_supply=state.supply()[managed]['supply'] if managed in state.supply() else 0,
                             balances={k:normalized(v) for k,v in sorted(accounts.items())})
    return result
