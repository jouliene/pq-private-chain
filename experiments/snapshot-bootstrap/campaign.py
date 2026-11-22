"""Exercise independently pinned snapshot bootstrap, receipt recovery, replay and a below-base fork."""
from contextlib import ExitStack, closing
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from funding import agree, capture, load_lab, need, save
from roles import Measure, Role, call, command, wallet
from stage import install


def checked(role,op,**args):
    result=role.rpc(op,**args)
    need(result['ok'],str((op,result.get('reason'))))
    return result


def fails(role,op,word,**fields):
    result=role.rpc(op,**fields)
    need(not result['ok'] and word in result['reason'],f"expected {word} during {op}: "+str(result.get('reason')))
    return result


def public_view(role):
    data=role.rpc('readback')
    st=data['status']
    return dict(**{k:st[k] for k in ('network','genesis','tip','height','work','anchor','issued','fees',
                                     'notes','spent','spent_set_sha256')},
                state_sha256=data['state_sha256'],registry=data['registry'])


def compact_wallet(row):
    keys=('complete','reason','submitted','tip','height','native','assets','notes','tx','real_inputs','change','fee',
          'packet_B','source_height','process_elapsed_s','proving_wall_s','history_request_B','history_reply_B')
    return {k:row[k] for k in keys if k in row}


def copy_records(source,fixture):
    with closing(sqlite3.connect(source.resolve().as_uri()+'?mode=ro',uri=True)) as db:
        for ident,raw in db.execute('SELECT bid,record FROM wallet_history_v2'):
            if (fixture/'blocks'/(ident.hex()+'.bin')).is_file():
                (fixture/'records'/(ident.hex()+'.bin')).write_bytes(raw)


def seal(lab,role,miner,tx,fixture):
    from chain import decode_block
    raw=call(role.public,'tx',id=tx)[1]
    need(sha256(raw).hexdigest()==tx and raw[:5]==b'MSP3\x01','canonical new C packet')
    lab.request(miner,'submit',raw)
    mined=lab.mine(miner,1,pay_to='miner-b' if miner=='c' else 'miner-a')
    block=decode_block(lab.request(miner,'block',id=mined['tip'])[1])
    need(block.packets==(raw,) and block.amount==103,'confirmed exact recipient spend and native fee')
    return mined,capture(lab,miner,fixture)


def add_cost(a,b):
    return {k:a.get(k,0)+b.get(k,0) for k in sorted(set(a)|set(b))}


def benchmark(dep,ports,stores,peer,pin,case):
    results={}
    for name in ('measured-replay','measured-snapshot'):
        store=stores/name
        store.mkdir()
        timer=Measure(store)
        role=None
        try:
            snap=name.endswith('snapshot')
            role=Role(dep,ports,name,store,source=peer.public,pin=pin if snap else None)
            data=checked(role,'bootstrap',target=case['main'][-1]) if snap else checked(
                role,'advance',start=1,target=case['main'][-1])
            to_usable=dict(**timer.finish(),traffic=data['traffic'],status=data['status']['bootstrap'])
            if not snap:
                results['ordinary']=dict(to_usable=to_usable,to_full=to_usable)
                expected=public_view(role)
                continue
            check=Measure(store)
            try:
                # The installation discards work preimages, then re-fetches the prefix for full validation.
                # Already validated live suffix bodies are locally rechecked at promotion.
                replay=checked(role,'verify',target=case['base'])
            finally:
                stage=check.finish()
            need(public_view(role)==expected,'timed nodes disagree')
            total=dict(elapsed_s=to_usable['elapsed_s']+stage['elapsed_s'],
                       observed_peak_logical_B=max(to_usable['observed_peak_logical_B'],stage['observed_peak_logical_B']),
                       observed_peak_allocated_B=max(to_usable['observed_peak_allocated_B'],stage['observed_peak_allocated_B']),
                       end_logical_B=stage['end_logical_B'],end_allocated_B=stage['end_allocated_B'],
                       traffic=add_cost(to_usable['traffic'],replay['traffic']),status=replay['status']['bootstrap'])
            results['snapshot']=dict(to_usable=to_usable,additional_replay=dict(**stage,traffic=replay['traffic']),to_full=total)
        finally:
            if timer.thread.is_alive():
                timer.finish()
            if role:
                role.stop()
    return results


def run(out,dep,ports,stack):
    fixture,source,stores=out/'fixture',out/'source',out/'stores'
    stores.mkdir(mode=0o700)
    case=json.loads((fixture/'case.json').read_bytes())
    base,h,main,usable=case['base'],case['base_height'],case['first_main'],case['usable']
    need(base==main[h-1] and len(main)==h+1,'base and endpoint')
    pin=out/'operator-pin.json'
    # Attestation inputs are distinct original validating stores. The B process receives no A files.
    for mode,dbpath,dest in [('pin',out/'b-base.sqlite',pin),('export',out/'a-base.sqlite',fixture)]:
        if mode=='pin':
            pin.touch(mode=0o600,exist_ok=False)
        # Mount a private copy of the named archive in its own directory for SQLite rollback journals.
        roledata=out/('attestor-'+mode)
        roledata.mkdir(mode=0o700)
        shutil.copyfile(dbpath,roledata/'base.sqlite')
        mounts=[(roledata,'/db',True),(dest,'/out',True)]
        cmd=command(dep,'attest.py',['/deployment','/db/base.sqlite','/out',mode],mounts)
        subprocess.run(cmd,check=True,timeout=120)
    need(json.loads(pin.read_bytes())==json.loads((fixture/'manifest.json').read_bytes()),'independent base digest mismatch')
    shutil.copyfile(pin,fixture/'pin.json')
    peer=Role(dep,ports,'peer',stores/'peer',fixture=fixture)
    stack.callback(peer.stop)
    def node(name,pinned=True):
        role=Role(dep,ports,name,stores/name,source=peer.public,pin=pin if pinned else None)
        stack.callback(role.stop)
        return role
    snap=node('snap')
    ordinary=node('ordinary',False)
    report={'controls':{},'wallet':{},'views':{}}
    def fault(**params):
        peer.rpc('fault',fault=params)
    def compare_original(view,miner):
        original=lab.status(miner)
        for k in ('tip','height','work','anchor','issued','fees','notes','spent','spent_set_sha256'):
            need(view[k]==original[k],'original funded-C node diverged on '+k)
        assets=lab.request(miner,'assets',after='00'*32,limit=32,tip=original['tip'])[0]
        need(assets['next'] is None and assets['entries']==view['registry'],'original funded registry')
    def assert_equal(label):
        view=public_view(snap)
        need(view==public_view(ordinary),'genesis and snapshot disagree at '+label)
        report['views'][label]=view
        return view
    fault(op='state',mode='corrupt')
    err=fails(snap,'bootstrap','snapshot',target=usable)
    need(err['status']['height']==0,'corrupt import published a state')
    fault(op='block',id=base,mode='corrupt')
    err2=fails(snap,'bootstrap','wrong historical block',target=usable)
    need(err2['status']['height']==0,'wrong work changed genesis')
    fault()
    report['controls']['rejected_downloads']=[err['reason'],err2['reason']]
    state=checked(snap,'bootstrap',target=usable)['status']
    need(state['bootstrap']['mode']=='provisional' and state['tip']==usable,'wrong provisional endpoint')
    snap.stop()
    snap=node('snap')
    need(snap.rpc('status')['bootstrap']['mode']=='provisional','restart lost trust boundary')
    checked(ordinary,'advance',start=1,target=usable)
    first=assert_equal('usable')
    funding=case['funding_block']
    # Attach all but one real pre-base wallet record; this is the one carrying the offline payment.
    rest=[i for i in main[:h] if i!=funding]
    attached=checked(snap,'attach',ids=rest)['traffic']
    fault(op='record',id=funding,mode='corrupt')
    bad=fails(snap,'attach','',ids=[funding])
    fault(op='record',id=funding,mode='gap')
    unavailable=fails(snap,'attach','unavailable',ids=[funding])
    oldhome=out/'wallets'/'old'
    def runwallet(home,who,target,action,**kw):
        return wallet(dep,home,who.public,target,action,**kw)
    missing=runwallet(oldhome,snap,usable,'restore',backup=out/'offline.backup')
    need(not missing['complete'] and not missing['submitted'] and 'native' not in missing,'wallet reported balance across gap')
    report['wallet']['missing']=compact_wallet(missing)
    report['controls']['record_corruption']=bad['reason']
    report['controls']['missing_record']=unavailable['reason']
    fault()
    repaired=checked(snap,'attach',ids=[funding])['traffic']
    report['receipt_archive']=dict(admitted=add_cost(attached,repaired),corrupt=bad['traffic'],unavailable=unavailable['traffic'])
    clean=runwallet(oldhome,snap,usable,'restore',backup=out/'offline.backup')
    need(clean['complete'] and clean['native']==17 and clean['notes']==1 and clean['owned'][0]['creator_tx']==case['funding'],
         'expected exact old receipt')
    cm=clean['owned'][0]['commitment']
    report['wallet']['old_complete']=compact_wallet(clean)
    spend=runwallet(oldhome,snap,usable,'spend',origin=case['funding'],address=out/'payee.addr',intent='old-receipt')
    need(spend['source_cm']==cm and spend['real_inputs']==1,'restored source pin')
    report['wallet']['first_spend']=compact_wallet(spend)
    lab=load_lab(source)
    lab.start(manual=True)
    stack.callback(lab.stop)
    initial,case['main']=seal(lab,snap,'a',spend['tx'],fixture)
    target=initial['tip']
    case['spend']=spend['tx']
    save(fixture/'case.json',case)
    for n in (snap,ordinary):
        checked(n,'advance',start=h+2,target=target)
    confirmed=assert_equal('post_base_spend')
    compare_original(confirmed,'a')
    need(confirmed['fees']==first['fees']+3 and confirmed['spent']>first['spent'],'new spend effects')
    def balances(label,tip,source_role,old_name,payee_name,expected):
        rows=[]
        for name,backup,expect in ((old_name,'offline',expected[0]),(payee_name,'payee',expected[1])):
            data=runwallet(out/'wallets'/name,source_role,tip,'restore',backup=out/(backup+'.backup'))
            need(data['complete'] and data['native']==expect,'wallet mismatch at '+label)
            rows.append(compact_wallet(data))
        report['wallet'][label]=rows
    balances('old_branch_balances',target,snap,'old','payee',(3,11))
    # C stayed at the funding block. Its independently mined branch crosses the base.
    longer=lab.mine('c',initial['height']-case['fork_height']+1,pay_to='miner-b')
    tip=longer['tip']
    case['fork']=capture(lab,'c',fixture)
    need(case['fork'][:h-1]==case['main'][:h-1] and case['fork'][h-1]!=base,'fork must diverge before base')
    save(fixture/'case.json',case)
    blocked=fails(snap,'advance','snapshot base',start=h,target=tip)
    need(blocked['status']['tip']==target and blocked['status']['bootstrap']['mode']=='provisional','cross-base import escaped')
    fault(op='block',id=funding,mode='gap')
    for method,endpoint in [('verify',base),('fork',tip)]:
        gap=fails(snap,method,'unavailable',target=endpoint)
        need(gap['status']['bootstrap']['mode']=='provisional' and gap['status']['tip']==target,'missing originals promoted the node')
    report['controls']['original_gap_kept_provisional']=True
    fault()
    full=checked(snap,'verify',target=base)
    need(full['status']['bootstrap']['mode']=='full','full replay gate')
    need(assert_equal('verified_original')==confirmed,'promotion changed selected money')
    merged=checked(snap,'fork',target=tip)
    checked(ordinary,'advance',start=h,target=tip)
    fork_view=assert_equal('heavier_fork')
    compare_original(fork_view,'c')
    need(fork_view['fees']==first['fees'] and fork_view['spent_set_sha256']==first['spent_set_sha256'] and
         fork_view['issued']==longer['height']*100,'fork spent set, fees or subsidies')
    balances('fork_wallets',tip,snap,'old','payee',(17,0))
    balances('reference_fork_wallets',tip,ordinary,'old-reference','payee-reference',(17,0))
    # A new process restores the same seed on the winning branch. The old proof was anchored only on the detached branch.
    next_home=out/'wallets'/'winning-old'
    restored=runwallet(next_home,snap,tip,'restore',backup=out/'offline.backup')
    need(restored['owned'][0]['commitment']==cm and restored['native']==17,'wrong recovered receipt on preferred branch')
    second=runwallet(next_home,snap,tip,'spend',origin=case['funding'],address=out/'payee.addr',intent='winning-old-receipt')
    need(second['tx']!=spend['tx'] and second['source_cm']==cm,'fresh selected-branch spend')
    final,case['fork']=seal(lab,snap,'c',second['tx'],fixture)
    case['winning_spend']=second['tx']
    save(fixture/'case.json',case)
    for n in (snap,ordinary):
        checked(n,'advance',start=final['height'],target=final['tip'])
    end=assert_equal('final')
    compare_original(end,'c')
    need(end['fees']==first['fees']+3 and end['spent']==confirmed['spent'] and end['registry']==first['registry'],
         'winning supply, spentness and fee reconciliation')
    balances('final_wallets',final['tip'],snap,'winning-old','payee',(3,11))
    balances('reference_final_wallets',final['tip'],ordinary,'old-reference','payee-reference',(3,11))
    report['wallet']['winning_spend']=compact_wallet(second)
    report['controls']['same_old_receipt_both_branches']=True
    report['controls']['private_amounts_are_disclosed_test_observations']=True
    report['controls']['below_base_preference']=dict(crossing_error=blocked['reason'],winning_status=merged['status']['bootstrap'])
    for n in 'ac':
        copy_records(source/'nodes'/n/'chain.sqlite',fixture)
    lab.stop()
    snap.stop()
    ordinary.stop()
    save(out/'functional.json',report)
    report['measurements']=benchmark(dep,ports,stores,peer,pin,case)
    save(out/'results.json',report)
    print(json.dumps({'usable_height':h+2,'base_height':h,'final_height':end['height'],
                      'measurements':report['measurements']}),flush=True)


if __name__=='__main__':
    os.umask(0o077)
    root=Path(sys.argv[1]).resolve()
    dep=install(root/'source/deployment',root/'registered')
    with tempfile.TemporaryDirectory(prefix='snb-') as directory, ExitStack() as stack:
        run(root,dep,Path(directory),stack)
