"""Local disposable-wallet check of the returned note under both accepted burns; report counts only."""
from collections import Counter
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from payout import private_receipt

ZERO=bytes(32)


def proof_row(public,r):
    tx=bytes.fromhex(r['tx']); envelope=(public/'packets'/(tx.hex()+'.bin')).read_bytes()
    assert hashlib.sha256(envelope).digest()==tx
    if envelope[:5]==b'AST1\x01':
        inner=envelope
    else:
        assert envelope[:5]==b'MSP1\x01'
        inner=envelope[17166:] if envelope[5] in (2,3) else envelope[6:]
    end=9+int.from_bytes(inner[5:9],'little')
    assert inner[:5] in (b'MNG1\x01',b'AST1\x01') and len(inner)==end+3584
    return inner[end-248:end]


def audit(home,replay):
    run=json.loads((home/'public/RUN.json').read_bytes())
    by=run['payments']; ret=by['return']
    burn=by['burn']; detached=by['branch-burn']
    assert ret['payee']==burn['payer']==detached['payer']
    result=json.loads(replay.read_bytes())
    public_liability=result['monetary']['balances_by_tip']['final']
    local=home/'wallets'
    by_address={}
    for path in local.glob('*/mng1-wallet-state.sqlite'):
        db=sqlite3.connect(path.resolve(strict=True).as_uri()+'?mode=ro',uri=True)
        try:
            owner,=db.execute('SELECT owner FROM identity').fetchone()
        finally:
            db.close()
        assert owner not in by_address
        by_address[owner]=path
    checked=0
    treasury_result=None
    legacy_match=0
    for name,want in public_liability.items():
        label='offline' if name=='recovered' else name
        address=(home/(label+'.addr')).read_bytes()
        assert len(address)==1673 and address[:40]==b'PQDADDR1'+bytes.fromhex(result['network'])
        assert address[-32:]==hashlib.sha256(address[:-32]).digest()
        db=sqlite3.connect(by_address[address[40:-32]].resolve(strict=True).as_uri()+'?mode=ro',uri=True)
        try:
            totals=Counter()
            for n,asset,t in db.execute('SELECT amount,asset,token FROM owned WHERE spent IS NULL'):
                assert (asset==ZERO)==(t==0)
                totals['native']+=n
                totals[asset.hex()]+=t
            assert totals['native']==want['native'] and {k:n for k,n in totals.items() if k!='native' and n}==want['assets']
            checked+=1
            if name==by['fixed']['payee']:
                old,spend=by['fixed'],by['fixed-pay']
                sources=db.execute('SELECT cm,nf,token FROM owned WHERE creator=? AND spender=? AND token>0',
                                   (bytes.fromhex(old['tx']),bytes.fromhex(spend['tx']))).fetchall()
                (fixed_cm,fixed_nf,fixed_units),=sources
                old_pi=proof_row(home/'public',old)
                new_pi=proof_row(home/'public',spend)
                assert fixed_units==17 and fixed_cm in (old_pi[104:136],old_pi[136:168])
                assert fixed_nf in (new_pi[40:72],new_pi[72:104])
                legacy_match+=1
            if name!=ret['payee']:
                continue
            rows=db.execute("SELECT cm,nf,amount,asset,token,spender FROM owned WHERE creator=? AND kind='incoming'",
                            (bytes.fromhex(ret['tx']),)).fetchall()
            assert len(rows)==1
            cm,nf,native,asset,qty,spender=rows[0]
            assert qty==200 and asset.hex()==result['monetary']['managed_id'] and spender==bytes.fromhex(burn['tx'])
            assert not db.execute('SELECT 1 FROM owned WHERE spender=? LIMIT 1',(bytes.fromhex(ret['tx']),)).fetchone()
            ret_pi=proof_row(home/'public',ret)
            assert cm in (ret_pi[104:136],ret_pi[136:168])
            for action in (burn,detached):
                pi=proof_row(home/'public',action)
                assert nf==pi[40:72] and pi[208:240]==asset and int.from_bytes(pi[240:],'little')==(1<<62)+200
            spent=db.execute('SELECT nf,asset,token FROM owned WHERE spender=?',(spender,)).fetchall()
            assert sum(t for _,_,t in spent)==200 and all(a==ZERO and t==0 for x,a,t in spent if x!=nf)
            treasury_result=private_receipt(home,run,bytes.fromhex(result['network']),nf)
            selected_pi=proof_row(home/'public',burn)
            assert all(x in (selected_pi[40:72],selected_pi[72:104]) for x,_,_ in spent)
        finally:
            db.close()
    assert treasury_result and legacy_match==1
    return dict(old_fixed_outputs_spent_by_upgraded_proof=legacy_match,durable_simulated_settlement=treasury_result,checked_final_inventories=checked,matched_external_return_commitments=1,
                matched_first_public_nullifiers_across_both_burns=2,returned_and_consumed_units=200,
                winning_burn_real_inputs=len(spent),real_inputs_with_positive_asset=1)


if __name__=='__main__':
    if not __debug__:
        raise SystemExit('assertions are required')
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('home',type=Path);p.add_argument('replay',type=Path)
    a=p.parse_args()
    print(json.dumps(audit(a.home,a.replay),sort_keys=True,indent=2))
