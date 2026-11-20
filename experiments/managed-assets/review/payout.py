"""Compare durable simulated payments and redemption observations to independently reconstructed branches."""
from hashlib import sha256
import json
from pathlib import Path
import sqlite3


def check(run,states,reader,observations=None):
    payout=run['payout']
    cases=('enrolled','one_confirmation','paid','retried','after_reorg','recovered')
    assert payout['crash']==dict(bank_paid=200,exit=75,local_ack=False,rows=1)
    expected_paid=(0,0,200,200,200,200)
    expected_exposure=(0,0,0,0,200,0)
    paid_receipt=None
    burns={bytes.fromhex(run['payments'][k]['tx']) for k in ('branch-burn','burn')}
    result={}
    for name,expected,exposure in zip(cases,expected_paid,expected_exposure,strict=True):
        row=payout[name]
        assert row['request']=='redemption-001' and row['amount']==200 and row['threshold']==3
        assert row['paid']==expected and row['exposure']==exposure and row['owed']==200-expected
        assert row['payout_count']==int(bool(expected))
        if expected:
            paid_receipt=paid_receipt or row['bank_receipt']
            assert bool(paid_receipt) and row['bank_receipt']==paid_receipt
        else:
            assert row['bank_receipt'] is None
        branch=states[bytes.fromhex(row['tip'])]
        assert len(branch.ids)-1==row['height']
        seen=set(branch.locations)&burns
        assert len(seen)<=1
        if seen:
            tid,=seen
            bid=branch.locations[tid]
            depth=len(branch.ids)-branch.ids.index(bid)
            effect=reader.events[tid]
            assert effect.op==4 and effect.asset.hex()==row['asset']
            assert row['selected_burn']==tid.hex() and row['confirmations']==depth
            if name=='one_confirmation':
                assert depth==1
            if name in ('paid','retried','recovered'):
                assert depth>=3
        else:
            assert row['selected_burn'] is None and row['confirmations']==0
        assert row['exposure']==(row['paid'] if not seen else 0)
        result[name]={k:row[k] for k in ('tip','height','paid','owed','payout_count','exposure','confirmations','attempts')}
    assert payout['enrolled']['attempts']==0 and payout['one_confirmation']['attempts']==1
    assert payout['after_reorg']['attempts']==1 and payout['recovered']['attempts']==2
    result['same_receipt_at_all_paid_observations']=True
    if observations:
        journal=json.loads(Path(observations).read_bytes())['simulated_bank_samples']
        assert journal
        paid=[s['counts']['paid'] for s in journal]
        assert 0 in paid and paid[-1]==200 and paid==sorted(paid)
        assert all(s['counts']['bank_rows'] in (0,1) for s in journal)
        assert journal[-1]['counts']['bank_rows']==1
        assert all(s['counts']['paid']==s['counts']['bank_rows']*200 for s in journal)
        result['independent_journal_samples']=journal
        result['observed_bank_commit_before_ack']=any(s['counts']['bank_rows']==1 and s['counts']['acknowledged']==0 for s in journal)
    return result


def private_receipt(home,run,network,return_nf):
    args=run['payout']['recovered']
    amount=args['amount']; aid=bytes.fromhex(args['asset']); name=args['request']; receipt=args['bank_receipt']
    db=sqlite3.connect((home/'redemptions/requests.sqlite').resolve(strict=True).as_uri()+'?mode=ro',uri=True)
    try:
        requests=db.execute('SELECT network,request,treasury,asset,amount,return_tx,payee,return_nf,acknowledged FROM requests').fetchall()
        row,=requests
        ret=run['payments']['return']
        assert row[:6]==(network,name,ret['payee'],aid,amount,bytes.fromhex(ret['tx']))
        payee=row[6]
        assert row[7:]==(return_nf,receipt)
        attempts=db.execute('SELECT tx,request,first_block,first_height FROM attempts').fetchall()
        assert len(attempts)==2 and {x[0] for x in attempts}=={run['payments'][k]['tx'] for k in ('branch-burn','burn')}
        assert all(x[1]==name for x in attempts)
        for tx,_,bid,h in attempts:
            raw=(home/'public/blocks'/(bid+'.bin')).read_bytes()
            assert int.from_bytes(raw[73:77],'little')==h
            ptr=214; ids=[]
            for _ in range(raw[213]):
                n=int.from_bytes(raw[ptr:ptr+4],'little');ptr+=4
                ids.append(sha256(raw[ptr:ptr+n]).hexdigest());ptr+=n
            assert ptr==len(raw)-8 and tx in ids
    finally:
        db.close()
    db=sqlite3.connect((home/'redemptions/bank.sqlite').resolve(strict=True).as_uri()+'?mode=ro',uri=True)
    try:
        actual=db.execute('SELECT business_key,network,request,payee,asset,amount,receipt FROM payments').fetchall()
        key=sha256(b'MNG1/redemption-bank/v1\0'+network+name.encode('ascii')).hexdigest()
        assert actual==[(key,network,name,payee,aid,amount,receipt)]
    finally:
        db.close()
    return dict(retained_requests=1,recorded_burn_attempts=2,durable_bank_payments=1,
                durable_mock_fiat_units=amount,matches_return_and_registered_business_terms=True,
                receipt_matches_coordinator_acknowledgment=True)
