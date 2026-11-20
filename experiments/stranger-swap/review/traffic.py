"""Recalculate directory frames, encrypted traffic, abandonment and mined admission from separate observations."""
import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import sys
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from adverts import NETWORK,canonical


def check(public,settlement):
    run=json.loads((public/'RUN.json').read_bytes());ledger=json.loads(settlement.read_bytes())
    assert run['network']==NETWORK and run['genesis']==ledger['genesis'] and run['scenario']=='stranger-token-for-native-v1'
    ads=run['ads'];q_by_price={q['native']:q for q in run['quotes']}
    assert set(q_by_price)=={7,8} and len(ads)==2
    assert {q['advert'] for q in q_by_price.values()}==set(ads)
    assert all((q['quantity'],q['payer'],q['fee'])==(20,'b',3) for q in q_by_price.values())
    for ident,row in ads.items():
        assert sha256(canonical(row)).hexdigest()==ident
    dir_tx=dir_rx=0
    meters=run['meter']
    stages=meters['discovery']
    assert [v['operation'] for v in stages]==['register','register','discover']
    group0,group1,discovery=stages
    relays=[r['relay'] for r in discovery['endpoints']]
    assert len(set(relays))==2 and [r['ok'] for r in discovery['endpoints']]==[False,True]
    for group in stages:
        rows=group['endpoints']
        assert [r['relay'] for r in rows]==relays
        if group['operation']=='register':
            price={'maker':8,'other':7}[group['maker']]
            ident=q_by_price[price]['advert'];req={'op':'register','ad':ads[ident]};reply={'ok':True,'id':ident}
            assert all(r['ok'] for r in rows)
        else:
            req={'op':'list','network':NETWORK,'service':'token-for-native'}
            reply={'ok':True,'ads':[ads[k] for k in sorted(ads)]}
        for r in rows:
            expect=(4+len(canonical(req)),4+len(canonical(reply))) if r['ok'] else (0,0)
            assert (r['request_B'],r['reply_B'])==expect
            dir_tx+=r['request_B'];dir_rx+=r['reply_B']
    totals=meters['totals']
    assert (dir_tx,dir_rx)==(totals['directory_sent_B'],totals['directory_received_B'])
    counters={}
    encrypted=[]
    forwarded=[]
    matching_authenticated=0
    partial=[]
    for op in meters['negotiation']:
        calls=op['calls'];key=op['operation']
        assert key not in counters
        counters[key]=dict(private_requests=len(calls))
        for field in ('request_B','reply_B','wire_request_B','wire_reply_B'):
            counters[key][field]=sum(c[field] for c in calls)
        for c,tap in zip(calls,op['forwarder'],strict=True):
            pair=(c['wire_request_B'],c['wire_reply_B']);encrypted.append(pair)
            observed=(tap['to_maker_B'],tap['to_taker_B']);forwarded.append(observed)
            if c['authenticated']:
                assert pair==observed
                matching_authenticated+=1
                assert c['group']=='X25519MLKEM768' and c['protocol']=='TLSv1.3' and c['cipher']=='TLS_AES_256_GCM_SHA384'
                assert c['cert_pinned'] and pair[0]>c['request_B']>0 and pair[1]>c['reply_B']>0
            else:
                assert (c['request_B'],c['reply_B'])==(0,0)
                partial.append(dict(operation=key,client=pair,forwarder=observed))
    taps=[(r['to_maker_B'],r['to_taker_B']) for seq in meters['encrypted_link_observer'].values() for r in seq]
    assert Counter(forwarded)==Counter(taps) and len(taps)==len(encrypted)
    assert meters['all_socket_and_forwarder_counts_agree']==(Counter(encrypted)==Counter(taps))
    sent,received=map(sum,zip(*encrypted,strict=True))
    link_sent,link_received=map(sum,zip(*taps,strict=True))
    assert (sent,received)==(totals['private_TCP_sent_B'],totals['private_TCP_received_B'])
    assert counters['substituted-endpoint']['request_B']==0 and counters['substituted-endpoint']['wire_reply_B']>0
    assert counters['maker-disconnect']['request_B']==0 and counters['maker-disconnect']['private_requests']>=1
    assert counters['expired-approval']['request_B']==0
    assert all(counters[k]['reply_B']>143251 for k in ('firm-0','firm-1','stale-firm'))
    assert counters['selected-settlement']['private_requests']>=2
    submission=run['settlement']
    bundle=ledger['swap'];ordinary=ledger['ordinary']
    assert (submission['bundle_id'],submission['frame_ids'],submission['wire_B'],submission['height'])==(
        bundle['id'],bundle['leg_txids'],bundle['complete_upload_B'],ledger['swap_height'])
    assert submission['selection_to_observed_inclusion_s']>=submission['submit_to_observed_inclusion_s']>=0
    assert submission['block_B']==(public/'blocks'/(submission['block']+'.bin')).stat().st_size
    rpc=meters['wallet_node_rpc'];submits=[r for r in rpc if r['op']=='submit']
    before=run['checks']['before_settle'];prefix=before['wallet_rpc_rows']
    assert 0<prefix<len(rpc) and all(r['op']!='submit' for r in rpc[:prefix])
    assert before['pending']==dict(a=0,b=0,c=0)
    assert [v['id'] for v in submits]==[bundle['id'],ordinary['tx']]
    assert all((r['request_B'],r['packet_B'])==(n+8+len(b'{"op":"submit"}'),n) for r,n in
               zip(submits,[bundle['complete_upload_B'],ordinary['bytes']],strict=True))
    assert (submits[0]['request_B'],submits[0]['reply_B'])==(totals['settlement_submit_sent_B'],totals['settlement_submit_received_B'])
    assert {v['tx'] for v in run['ordinary'].values()}|set(bundle['leg_txids'])==set(ledger['winning_public_physical_txids'])
    assert set(run['ordinary'])=={'managed','fund-maker','fund-other','fund-taker','restored-payment'}
    assert set(ledger['all_public_physical_txids'])==set(ledger['winning_public_physical_txids'])
    assert all(sha256(p.read_bytes()).hexdigest()==p.stem for p in (public/'packets').iterdir())
    assert {p.stem for p in (public/'packets').iterdir()}==set(ledger['winning_public_physical_txids'])
    # Independent raw block walk across every intervening height, covering abandoned negotiations.
    funded,abandoned=run['branch']['funded'],run['branch']['abandoned']
    tip=abandoned['tip'];empty=0
    while tip!=funded['tip']:
        raw=(public/'blocks'/(tip+'.bin')).read_bytes()
        assert raw[213]==0 and len(raw)==222
        tip=raw[41:73].hex();empty+=1
        assert empty<=abandoned['height']-funded['height']
    assert empty==abandoned['height']-funded['height'] and empty>0
    assert funded['fees']==abandoned['fees']==12 and funded['spent_set_sha256']==abandoned['spent_set_sha256']
    assert ledger['selected']['fees']==18 and ledger['selected']['logical_payments']==6
    assert run['branch']['final']['tip']==ledger['selected']['tip']
    return dict(directory_request_B=dir_tx,directory_reply_B=dir_rx,hybrid_TLS_TCP_sent_B=sent,hybrid_TLS_TCP_received_B=received,
                logical_private_JSON_sent_B=sum(r['request_B'] for r in counters.values()),
                logical_private_JSON_received_B=sum(r['reply_B'] for r in counters.values()),operation_counters=counters,
                gateway_submit_rows=submits,zero_frames_in_abandoned_blocks=empty,successfully_registered_to_relays=4,
                reachable_relays_during_discovery=1,simultaneous_compare_prices=[7,8],selected_terms=[20,8,3],
                settlement_incremental_block_B=bundle['complete_in_block_B'],block_bytes=submission['block_B'],
                selection_to_observed_inclusion_s=submission['selection_to_observed_inclusion_s'],
                submit_to_observed_inclusion_s=submission['submit_to_observed_inclusion_s'],
                two_user_fees=6,abandonment_checked_wallet_RPC_prefix_rows=prefix,confirmed_empty_mempools=before['pending'],
                matching_authenticated_TCP_sessions=matching_authenticated,failed_session_observations=partial,
                forwarder_TCP_sent_B=link_sent,forwarder_TCP_received_B=link_received)


if __name__=='__main__':
    if not __debug__:sys.exit('enable assertions')
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('public',type=Path);p.add_argument('settlement',type=Path)
    a=p.parse_args();print(json.dumps(check(a.public,a.settlement),indent=2,sort_keys=True))
