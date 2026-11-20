"""Reconstruct per-tip cash and in-chain asset balances from disclosed synthetic flows."""
from collections import Counter
import json
from pathlib import Path

from events import ZERO, BURN


def balances(rows):
    return {name:dict(native=v['native'],assets={k:n for k,n in sorted(v.items()) if k!='native' and n})
            for name,v in sorted(rows.items())}


def reconcile(run, reader, states, blocks, winner, *, observations=None):
    tips={k:states[bytes.fromhex(st['tip'])] for k,st in run['tips'].items()}
    assert {'common','loser','winner','final'}<=set(tips) and tips['final'] is states[winner]
    common,loser,win,final=(tips[k] for k in ('common','loser','winner','final'))
    off=len(common.ids)
    assert loser.ids[:off]==win.ids[:off]==common.ids and loser.ids[off]!=win.ids[off]
    assert len(win.ids)>len(loser.ids) and final.ids[:len(win.ids)]==win.ids
    pay=run['payments']
    byid={bytes.fromhex(v['tx']):k for k,v in pay.items()}
    assert len(byid)==len(pay)
    required={'fund-treasury','fixed','fixed-pay','register','mint','deliver','return','branch-burn','burn'}
    assert required==set(pay)
    assert set(byid)<=set(reader.events)
    event={k:reader.events[bytes.fromhex(p['tx'])] for k,p in pay.items()}
    assert event['register'].delta==1000 and event['mint'].delta==300
    assert event['branch-burn'].delta==event['burn'].delta==BURN+200
    asset=event['register'].asset
    fixed=event['fixed'].asset
    assert event['fixed'].delta==17 and event['fixed'].legacy and not event['fixed-pay'].legacy and asset!=fixed
    assert event['register'].nullifiers[0]!=event['mint'].nullifiers[0]
    assert all(event[k].asset==asset for k in ('mint','branch-burn','burn'))
    assert set(loser.locations.keys()-common.locations)=={event['branch-burn'].txid}
    assert set(win.locations)==set(common.locations) and set(final.locations.keys()-win.locations)=={event['burn'].txid}
    assert event['branch-burn'].txid!=event['burn'].txid
    assert event['branch-burn'].anchor not in win.anchors and event['burn'].anchor in final.anchors
    assert not set(event['branch-burn'].commitments).intersection(row[0] for row in final.outs)
    assert event['branch-burn'].nullifiers[0]==event['burn'].nullifiers[0]
    for name,expected in [('common',1300),('loser',1100),('winner',1300),('final',1100)]:
        snap=tips[name]
        assert len(snap.assets)==2 and snap.assets[asset].supply==expected and snap.assets[fixed].supply==17
        assert (snap.assets[asset].mode,snap.assets[asset].authority)==('managed',event['register'].issuer)
        assert snap.assets[fixed]==common.assets[fixed] and snap.assets[fixed].mode=='fixed'
        assert snap.assets[asset].revision==(3 if name in ('loser','final') else 2)
        assert run['registries'][name]==snap.supply()
        for key in ('tip','height','work','anchor','issued','notes','spent','spent_set_sha256','fees'):
            assert run['tips'][name][key]==snap.summary()[key]
    upgrade=tips['upgrade']
    assert event['fixed'].txid in upgrade.locations and len(upgrade.locations)==1 and set(upgrade.assets)=={fixed}
    assert run['legacy_tip']==upgrade.ids[-1].hex() and upgrade.ids==common.ids[:len(upgrade.ids)]
    assert event['fixed-pay'].txid in common.locations and run['offline_restore']=={'native':12,'assets':{asset.hex():400}}
    assert final.fees==24 and len(final.locations)==8
    actors=set(run['balances']['final'])
    miner={bytes.fromhex(pk):k for k,pk in run['miner_keys'].items()}
    assert len(miner)==len(run['miner_keys'])
    records={}
    for name,st in tips.items():
        rows={actor:Counter() for actor in actors}
        for bid in st.ids[1:]:
            b=blocks[bid]
            for e in b.slots:
                r=pay[byid[e.txid]]
                payer,payee = ('recovered' if s=='offline' else s for s in (r['payer'],r['payee']))
                tag=r['asset_id']
                minted,burned=(e.delta if e.op in (1,2,3) else 0),(e.delta-BURN if e.op==4 else 0)
                assert e.fee==r['fee'] and minted==r['minted'] and burned==r['burned']
                assert r['input_total']==r['amount']+r['change']+e.fee
                assert r['token_input_total']+minted==r['token_amount']+r['token_change']+burned
                if e.op:
                    assert tag==e.asset.hex()
                rows[payer]['native']-=r['amount']+e.fee
                rows[payee]['native']+=r['amount']
                rows[payer][tag]+=minted-burned-r['token_amount']
                rows[payee][tag]+=r['token_amount']
                assert min(rows[payer].values())>=0
            rows[miner[b.miner]]['native']+=b.amount
        expected=balances(rows)
        assert sum(v['native'] for v in expected.values())==st.summary()['issued']
        assert {aid.hex():sum(v['assets'].get(aid.hex(),0) for v in expected.values()) for aid in st.assets}=={
            aid.hex():s.supply for aid,s in st.assets.items()}
        for actor,v in run['balances'][name].items():
            assert expected[actor]==v,(name,actor)
        records[name]=expected
    result=dict(balances_by_tip=records,managed_id=asset.hex(),fixed_id=fixed.hex(),
                asset_supply_by_tip={k:(st.assets[asset].supply if asset in st.assets else 0) for k,st in tips.items()},
                branch_burn_removed=True,reattached_burn_same_first_nullifier=True,
                selected_payments=[byid[tx] for tx in final.locations],
                dropped_burn_id=event['branch-burn'].txid.hex(),winning_burn_id=event['burn'].txid.hex())
    if observations:
        seen={}
        trace=json.loads(Path(observations).read_bytes())
        assert trace['returncode']==0
        for peer,rows in trace['nodes'].items():
            idx={}; checked=0
            for i,row in enumerate(rows):
                idx.setdefault(row['tip'],i)
                st=states.get(bytes.fromhex(row['tip']))
                if st:
                    checked+=1
                    summary=st.summary()
                    assert all(summary[k]==row[k] for k in ('tip','height','work','anchor','issued','notes','spent','spent_set_sha256','fees'))
                    assert row['assets']==list(st.supply().values())
            assert final.ids[-1].hex() in idx
            seen[peer]=dict(samples=len(rows),compared_to_retained_history=checked,genesis=idx.get(final.ids[0].hex()),
                            tips={k:idx.get(s.ids[-1].hex()) for k,s in tips.items()})
        result['peer_samples']=seen
    return result
