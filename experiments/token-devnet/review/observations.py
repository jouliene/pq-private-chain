"""Compare lab disclosures and read-only live peer samples with independently replayed public state."""
from pathlib import Path
import json


def check(public, branches, blocks, verifier, winner, observations):
    run=json.loads((public/'RUN.json').read_bytes())
    tips={k:branches[bytes.fromhex(v['tip'])] for k,v in run['tips'].items()}
    assert tips['final'] is branches[winner]
    for tag,b in tips.items():
        expected=b.summary()
        for key in ('tip','height','work','fees','issued','notes','spent','spent_set_sha256','anchor','token_issued'):
            assert run['tips'][tag][key]==expected[key]
        assert run['tips'][tag]['header']==b.header.hex()
    common,loser,win,final=(tips[k] for k in ('common','loser','winner','final'))
    depth=len(common.ids)
    assert loser.ids[:depth]==win.ids[:depth]==common.ids and loser.ids[depth]!=win.ids[depth]
    assert final.ids[:len(win.ids)]==win.ids and len(win.ids)>len(loser.ids)
    pay=run['payments']
    a,b=[verifier.checked[pay[k]['tx']] for k in ('branch-first','branch-retry')]
    pre = run.get('pre_confirmation_retry', pay['branch-retry'])
    pending = verifier.checked[pre['tx']]
    ordered=['token-only','native-only','combined','onward']
    amounts=[(0,70),(23,0),(9,45),(4,13)]
    def cash(x):
        return x['native'],x['token']
    for tag,(native,token) in zip(ordered,amounts):
        r=pay[tag]
        assert (r['amount'],r['token_amount'])==(native,token)
        assert r['tx'] in common.locations
    for tag,r in pay.items():
        totals=tuple(sum(cash(x)[i] for x in r['input_sources']) for i in range(2))
        assert totals==(r['input_total'],r['token_input_total'])==(r['change']+r['fee']+r['amount'],r['token_amount']+r['token_change'])
        assert r['fee']==3 and r['real_inputs']==len(r['input_sources'])
    assert all(x['kind']=='reward' and x['token']==0 for x in pay['native-only']['input_sources'])
    assert sorted((v['kind'],*cash(v)) for v in pay['combined']['input_sources'])==[('incoming',0,70),('incoming',23,0)]
    assert set(loser.locations)-set(common.locations)=={a.txid}
    assert win.locations==common.locations and set(final.locations)-set(win.locations)=={b.txid}
    assert a.nullifiers[0]==b.nullifiers[0] and set(a.nullifiers)&set(b.nullifiers)=={a.nullifiers[0]}
    assert not(set(a.commitments)&set(b.commitments)) and a.receipt_pair!=b.receipt_pair
    assert a.anchor not in win.anchors and b.anchor==final.anchors[b.height]
    assert pending.anchor==win.anchors[pending.height]
    if pending.txid!=b.txid:
        assert pending.txid not in final.locations and pending.anchor!=b.anchor
    assert set(a.nullifiers)&set(pending.nullifiers)=={a.nullifiers[0]}
    if b.txid!=pending.txid:
        assert set(b.nullifiers)&set(pending.nullifiers)=={a.nullifiers[0]}
    assert all(x not in {r[0] for r in final.outs} for x in a.commitments)
    assert run['duplicate']==dict(id=pending.txid,duplicate=True)
    assert cash(run['offline_restore'])==(0,70)
    expected={'mira-restored':(5,18),'next-restored':(2,32),'payee':(4,13),'shop':(3,7),'fork-miner':(0,0)}
    assert all(cash(run['wallets'][name])==amount for name,amount in expected.items())
    assert tuple(sum(cash(row)[i] for row in run['wallets'].values()) for i in range(2))==(final.summary()['issued'],240)
    detached_miner=bytes.fromhex(run['miner_keys']['fork-miner'])
    def miner_credits(state):
        return sum(blocks[bid].amount for bid in state.ids[1:] if blocks[bid].miner==detached_miner)
    assert cash(run['losing_miner_before'])==(miner_credits(loser),0) and cash(run['losing_miner_after'])==(miner_credits(win),0)==(0,0)
    before_retry_age=len(win.ids)-a.height
    report=dict(duplicate_exercised_packet=pending.txid, settled_packet=b.txid, orphan_age_at_winning_next=before_retry_age,orphan_expired_by_age=before_retry_age>8,
                orphan_anchor_on_winning_chain=False,losing_branch_paid_to_named_miner=miner_credits(loser),
                winning_branch_paid_to_named_miner=miner_credits(win),native_reward_origin_disclosed=True,
                two_disclosed_incoming_notes_checked=True,offline_recovered_token=70,
                selected_fee_total=final.fees,orphan_payment_side_block=loser.locations[a.txid].hex(),
                replacement_in_selected_block=final.locations[b.txid].hex(),duplicate_receiving_node='a')
    if observations:
        live=json.loads(Path(observations).read_bytes())
        assert live['returncode']==0
        tips_seen={name:[entry[1]['tip'] for entry in rows] for name,rows in live['nodes'].items()}
        assert all(final.ids[-1].hex() in s for s in tips_seen.values())
        phases=[s.ids[-1].hex() for s in (branches[common.ids[0]],loser,win,final)]
        cold=tips_seen['d']
        snapshot_keys=('height','work','issued','fees','notes','spent_set_sha256','anchor','token_issued')
        for name,rows in live['nodes'].items():
            for _,snap,_ in rows:
                branch=branches.get(bytes.fromhex(snap['tip']))
                if branch is not None:
                    assert all(snap[k]==branch.summary()[k] for k in snapshot_keys)
        captured_positions=[cold.index(t) if t in cold else None for t in phases]
        observed_pending={n:any(pending.txid in row[2] for row in rows) for n,rows in live['nodes'].items()}
        report['public_observer']=dict(changed_state_samples={k:len(v) for k,v in tips_seen.items()},
            cold_genesis_loser_winner_final_observed=[x is not None for x in captured_positions],
            cold_sequence_in_order=[v for v in captured_positions if v is not None]==sorted(v for v in captured_positions if v is not None),
            retry_pending_observed=observed_pending,
            sampled_distinct_node_a_pids=len({row[1]['pid'] for row in live['nodes']['a']}))
    return report
