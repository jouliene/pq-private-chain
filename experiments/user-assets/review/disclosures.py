"""Reconcile disclosed participant flows against independently verified issuance, fees and branch selection."""
from collections import Counter
import json
from pathlib import Path


def account_rows(balances):
    return {name:dict(native=values['native'], assets={asset:n for asset,n in sorted(values.items())
                                                      if asset != 'native' and n}) for name,values in sorted(balances.items())}


def check(public, reader, blocks, branches, winner, observations):
    run = json.loads((public/'RUN.json').read_bytes())
    registry = run['registries']
    tips = {k:branches[bytes.fromhex(v['tip'])] for k,v in run['tips'].items()}
    a,b = (run['asset_ids'][k] for k in 'AB')
    assert a != b
    final = tips['final']
    assert final is branches[winner]
    common,loser,win = (tips[k] for k in ('common','loser','winner'))
    fork = len(common.ids)
    assert loser.ids[:fork] == win.ids[:fork] == common.ids and loser.ids[fork] != win.ids[fork]
    assert final.ids[:len(win.ids)] == win.ids and len(win.ids) > len(loser.ids)
    assert [set(tips[k].summary()['registry']) for k in ('common','loser','winner','final')] == [{a},{a,b},{a},{a,b}]
    for label,state in tips.items():
        summary = state.summary()
        for key in ('tip','height','work','fees','issued','notes','spent','spent_set_sha256','anchor'):
            assert run['tips'][label][key] == summary[key], (label,key)
        assert run['tips'][label]['header'] == state.header.hex()
        expected = {asset:dict(id=asset,supply=r['cap'],height=r['height'],tx=r['tx'])
                    for asset,r in summary['registry'].items()}
        assert registry[label] == expected
    pay = run['payments']
    by_tx = {}
    for name,r in pay.items():
        tid = bytes.fromhex(r['tx'])
        assert tid not in by_tx
        by_tx[tid] = name
        effect = reader.effects[tid]
        assert (r['issue_supply'],r['fee']) == (effect.cap,effect.fee)
        if effect.cap:
            assert r['asset_id'] == effect.issue.hex()
        else:
            assert effect.issue == bytes(32)
        sources = r['input_sources']
        assert 1 <= len(sources) == r['real_inputs'] <= 2
        assert r['input_total'] == sum(v['native'] for v in sources) == r['amount']+r['fee']+r['change']
        assert r['token_input_total'] == sum(v['token'] for v in sources)
        assert r['token_input_total']+effect.cap == r['token_amount']+r['token_change']
        for src in sources:
            assert src['asset'] == (r['asset_id'] if src['token'] else bytes(32).hex())
        raw = (public/'packets'/(r['tx']+'.bin')).stat().st_size
        assert raw == r['packet_B']
    for name in ('issue-a','branch-issue-b','issue-b'):
        assert pay[name]['issue_supply'] > 0
    assert pay['issue-a']['payer'] != pay['issue-b']['payer']
    assert pay['branch-issue-b']['asset_id'] == pay['issue-b']['asset_id'] == b
    assert pay['issue-a']['asset_id'] == a
    assert registry['common'][a] == registry['loser'][a] == registry['winner'][a] == registry['final'][a]
    stale, replacement = [reader.effects[bytes.fromhex(pay[k]['tx'])] for k in ('branch-issue-b','issue-b')]
    assert stale.cap == replacement.cap and stale.issue == replacement.issue
    assert stale.txid != replacement.txid and stale.nullifiers[0] == replacement.nullifiers[0]
    assert {by_tx[t] for t in loser.locations.keys()-common.locations.keys()} == {'branch-issue-b','branch-deliver-b'}
    assert not (win.locations.keys()-common.locations.keys())
    assert {'issue-b','deliver-b','spend-a','spend-b','onward-a','onward-b'} <= {
        by_tx[t] for t in final.locations.keys()-win.locations.keys()}
    assert all(bytes.fromhex(pay[k]['tx']) not in final.locations for k in ('branch-issue-b','branch-deliver-b'))
    orphan_effects = [reader.effects[t] for t in loser.locations.keys()-common.locations.keys()]
    orphan_outputs = {cm for effect in orphan_effects for cm in effect.commitments}
    assert orphan_outputs.isdisjoint({row[0] for row in final.outputs})
    assert stale.anchor not in win.anchors and replacement.anchor in final.anchors
    assert run['duplicate_issuance'] == 'asset already issued'
    assert 'insufficient compatible funds' in run['wallet_wrong_asset']

    participants = set(run['balances']['final'])
    miners = {bytes.fromhex(pk):label for label,pk in run['miner_keys'].items()}
    assert len(miners) == len(run['miner_keys'])
    independent = {}
    branch_labels = {}
    for label,state in tips.items():
        holdings = {name:Counter() for name in participants}
        actions = []
        for bid in state.ids[1:]:
            block = blocks[bid]
            for effect in block.slots:
                name = by_tx[effect.txid]
                actions.append(name)
                if label == 'final' and name == 'spend-a':
                    assert account_rows({'offline': holdings['offline']})['offline'] == run['offline_restore']
                r = pay[name]
                payer, payee, asset = r['payer'], r['payee'], r['asset_id']
                holdings[payer]['native'] -= effect.fee+r['amount']
                holdings[payee]['native'] += r['amount']
                holdings[payer][asset] += effect.cap-r['token_amount']
                holdings[payee][asset] += r['token_amount']
                assert all(n >= 0 for n in holdings[payer].values())
            holdings[miners[block.miner]]['native'] += block.amount
        assert sum(v['native'] for v in holdings.values()) == state.summary()['issued']
        total = Counter()
        for row in holdings.values():
            total.update({k:n for k,n in row.items() if k != 'native' and n})
        assert dict(total) == {key.hex():data[0] for key,data in state.registry.items()}
        expected = account_rows(holdings)
        for name,row in run['balances'][label].items():
            assert row == expected[name], (label,name)
        independent[label] = expected
        branch_labels[label] = actions
    assert independent['final'] == run['balances']['final']
    assert all(independent['final']['offline']['assets'][asset] > 0 for asset in (a,b))
    double = {}
    for suffix, asset in [('a',a),('b',b)]:
        tag = 'spend-'+suffix
        r = pay[tag]
        onward = pay['onward-'+suffix]
        assert r['payer'] == 'offline' and r['asset_id'] == asset and r['real_inputs'] == 2
        assert r['token_amount'] > 0 and r['token_change'] > 0 and r['change'] > 0
        assert onward['payer'] == r['payee'] and onward['asset_id'] == asset and onward['token_amount'] > 0
        assert sorted((v['kind'], bool(v['native']), bool(v['token'])) for v in r['input_sources']) == [
            ('incoming',False,True),('incoming',True,False)]
        packet = r['packet_B']
        double[tag] = dict(real_inputs=2,proved_slots=2,outputs=2,external_native=r['amount'],
                           external_token=r['token_amount'],native_change=r['change'],token_change=r['token_change'],
                           separate_asset_outputs_minimum=3+int(r['amount']>0),packet_B=packet,proof_B=packet-3593,
                           receipt_B=3584,proving_wall_s=r['proving_wall_s'])
        for metric in ('prover_cpu_s','prover_role_peak_rss_KiB'):
            double[tag][metric] = r[metric]
    result = dict(balances_by_tip=independent, selected_action_order=branch_labels, double_change=double,
                  same_issue_id_after_reorg=True,same_first_nf_after_reorg=True)
    if observations:
        result['peer_samples'] = check_samples(observations,tips,branches)
    return result


def check_samples(file,tips,branches):
    data = json.loads(Path(file).read_bytes())
    assert data['returncode'] == 0 and set(data['nodes']) == set('abcd')
    summary = {}
    final = tips['final'].ids[-1].hex()
    for n,samples in data['nodes'].items():
        observed = {}
        matched = 0
        for i,entry in enumerate(samples):
            info = entry['status']
            observed.setdefault(info['tip'],i)
            state = branches.get(bytes.fromhex(info['tip']))
            if state is None:
                continue
            matched += 1
            expect = state.summary()
            assert all(info[k] == expect[k] for k in ('height','work','issued','fees','notes','spent','spent_set_sha256','anchor'))
            assert info['registry'] == [dict(id=key,supply=r['cap'],height=r['height'],tx=r['tx'])
                                        for key,r in expect['registry'].items()]
        assert final in observed
        genesis = tips['common'].ids[0].hex()
        milestones = {k:observed.get(s.ids[-1].hex()) for k,s in tips.items()}
        summary[n] = dict(changed_samples=len(samples),samples_matching_retained_blocks=matched,
                          genesis_sample=observed.get(genesis), milestone_sample_indices=milestones)
    d = summary['d']
    assert d['genesis_sample'] is not None and d['genesis_sample'] < d['milestone_sample_indices']['final']
    return summary
