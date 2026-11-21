"""Recover from two surviving peers, then replace a spent branch below the body window."""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import isolation
from roles import Role, call, disk, save, transport
from wallet_compare import OWNERS, compare


def required(condition, message):
    if not condition:
        raise ValueError(message)


def traces(archives):
    return {name:len((role.store/'peer.jsonl').read_text().splitlines()) for name,role in archives.items()}


def snapshot(path, endpoint):
    # Public evidence capture, outside all measured peer phases. No wallet requests here.
    ids = call(endpoint,'selected',start=1,limit=128)[0]
    for bid in ids:
        dest = path/(bid+'.bin')
        if not dest.exists():
            dest.write_bytes(call(endpoint,'block',id=bid)[1])


def wallet(deployment, private, endpoint, tip, action, *, backup=None, address=None, args=()):
    private.mkdir(mode=0o700,parents=True,exist_ok=True)
    mounts = [(private,'/wallet',True),(endpoint,'/endpoint.sock',False)]
    if backup:
        mounts.append((backup,'/backup',False))
    if address:
        mounts.append((address,'/address',False))
    argv = ['/code/wallet.py','/deployment','/wallet','/endpoint.sock',tip,action,*args]
    start = time.monotonic()
    output = subprocess.check_output(isolation.command(deployment,argv,mounts), timeout=300)
    return dict(json.loads(output), process_elapsed_s=time.monotonic()-start)


def campaign(network, stores, out):
    os.umask(0o077)
    dep = network/'deployment'
    seeds = network/'owner-backups'
    address = network/'negotiation/forward.addr'
    public = out/'public'
    public.mkdir(parents=True)
    (public/'blocks').mkdir()
    shutil.copy(network/'public/SCENARIO.json', public)
    scenario = json.loads((public/'SCENARIO.json').read_bytes())
    initial = scenario['tips']['initial']['tip']
    managed = scenario['asset_ids']['managed']
    miner = {n:(network/('nodes/'+n+'/miner.pk')).read_text().strip() for n in 'ab'}
    cfg = json.loads((network/'network.json').read_bytes())
    archives = {}
    live = []
    metrics = dict(archive_initial=json.loads((stores/'replication.json').read_bytes()), traces={},
                   home_phases={}, wallet={}, storage={}, controls={}, isolation={})
    outcome = dict(balances={})

    def launch(directory, ports=()):
        obj = Role(dep,directory,ports)
        live.append(obj)
        return obj

    def recover(phase, target, fail=False):
        before = traces(archives)
        start = time.monotonic()
        try:
            home.rpc('recover')
            required(not fail,'gap was accepted')
        except ValueError as err:
            required(fail and 'incomplete history' in str(err),str(err))
        duration = time.monotonic()-start
        status = home.rpc('status')
        progress = status['recovery']
        required(progress['status'] == ('incomplete' if fail else 'ready'), 'wrong readiness')
        if not fail:
            required(status['tip']==target,'endpoint mismatch')
        metrics['traces'][phase] = {k:[v,traces(archives)[k]] for k,v in before.items()}
        metrics['home_phases'][phase] = dict(progress=progress, selected=status['tip'],
            height=status['height'], storage=status['storage'], elapsed_s=duration)
        save(out/'metrics.json',metrics)
        return status

    def ordinary(tip,action,**kwargs):
        return wallet(dep,out/'offline-wallet',home.store/'wallet.sock',tip,action,**kwargs)

    def controls(label, tip, archive, expected, fresh=False):
        wallets, views = {}, {}
        for kind,role in [('home',home),('full',archive)]:
            wallets[kind] = {}
            st = role.rpc('status')
            registry = role.rpc('assets',after='00'*32,limit=32,tip=tip)
            required(registry['next'] is None,'incomplete registry')
            views[kind] = (st,{entry['id']:entry for entry in registry['entries']})
            for owner in OWNERS:
                path = out/'control-wallets'/kind/owner
                action = 'restore' if fresh else 'balance'
                kwargs = dict(backup=seeds/owner,args=['--seed','/backup']) if fresh else {}
                wallets[kind][owner] = wallet(dep,path,role.store/'wallet.sock',tip,action,**kwargs)
        result = compare(views,wallets,expected)
        if fresh:
            required(len(result['cold_queries'])==2,'missing seven-owner common-range comparison')
        outcome['balances'][label] = result['balances']
        metrics['controls'][label] = result
        save(out/'metrics.json',metrics)

    def pay(label, tip, miner_role, key):
        intent_args = ['--intent','archive-recovery-payment']
        result = ordinary(tip,'spend',address=address,args=['--address','/address','--asset',managed,*intent_args])
        required(result['complete'] and (result['change'],result['token_change'])==(3,3),'payment change')
        packet = call(home.store/'wallet.sock','tx',id=result['tx'])[1]
        required(packet.startswith(b'MSP2') and len(packet)==result['packet_B'],'home admitted wrong suite')
        call(miner_role.store/'wallet.sock','submit',packet)
        # Two confirmations, each found by a real CPU search under the unchanged target.
        st = miner_role.rpc('mine',count=2,pk=key)
        recover('extend' if label=='initial' else 'final_extend',st['tip'])
        confirmed = ordinary(st['tip'],'confirm',args=intent_args)
        required(confirmed['tx']==result['tx'] and confirmed['native']==3 and
                 confirmed['assets']=={managed:3},'selected intent or change differs')
        metrics['wallet'][label+'_payment'] = dict(submission=result,confirmation=confirmed)
        outcome[label+'_spend'] = result['tx']
        return st['tip']

    try:
        for name in ('archive1','archive2'):
            archives[name] = launch(stores/name)
            required(archives[name].rpc('status')['tip']==initial,'archives need the initial selected tip')
        a,b = archives.values()
        # Every original peer goes offline before recovery. No original DB, reference
        # block export, or source control socket is in any recovering role's mounts.
        for name in 'abc':
            try:
                call(transport.control(network,name),'stop')
            except (FileNotFoundError,ConnectionRefusedError):
                pass
        for name in 'abcd':
            for retry in range(80):
                try:
                    call(cfg['ports'][name],'status')
                except (ConnectionError, OSError):
                    break
                time.sleep(.1)
            else:
                raise ValueError('original still reachable')
        probe = 'import os,sys; assert all(not os.path.exists(x) for x in sys.argv[1:]); print("absent")'
        hidden = [str(network), str(network/'nodes'), str(public), str(stores/'archive1')]
        for name,store,net in [('home',out/'home',True),('wallet',out/'offline-wallet',False)]:
            store.mkdir(mode=0o700)
            mounts = [(store,'/store',True)]
            result = subprocess.check_output(isolation.command(dep,['-c',probe,*hidden],mounts,net))
            required(result.strip()==b'absent','unexpected host-side visibility')
        metrics['isolation'] = dict(original_ports_offline=4, reference_and_original_hidden=True,
                                    home_configured_archives=2, wallet_network_unshared=True,
                                    new_home_database=not (out/'home/home.sqlite').exists())
        required(metrics['isolation']['new_home_database'],'fresh home required')
        snapshot(public/'blocks',a.store/'wallet.sock')
        unavailable = a.rpc('selected',start=12,limit=1)[0]
        for role in (a,b):
            role.rpc('withhold',ids=[unavailable])
        ports = [a.port,b.port]
        home = launch(out/'home',ports)
        gap = recover('gap',initial,True)
        required(gap['recovery']['first_missing_height']==12,'wrong missing interval')
        blocked = ordinary(initial,'restore',backup=seeds/'offline',args=['--seed','/backup'])
        required(not blocked['complete'] and not blocked['submitted'] and 'native' not in blocked and 'assets' not in blocked,
                 'wallet reported an unverified balance')
        blocked_spend = ordinary(initial,'spend',address=address,args=['--address','/address','--asset',managed,
                                    '--intent','archive-recovery-payment'])
        required(not blocked_spend['complete'] and not blocked_spend['submitted'],'unverified wallet spend')
        metrics['wallet']['gap'] = dict(restore=blocked,spend=blocked_spend)
        b.rpc('withhold',ids=[])
        recovered = recover('resume',initial)
        required(recovered['storage']['body_rows']==3,'body pruning failed')
        try:
            call(home.store/'wallet.sock','block',id=unavailable)
        except ValueError as exc:
            required('pruned' in str(exc),'unexpected archive error')
        else:
            raise ValueError('home still serves the old funded body')
        received = ordinary(initial,'balance')
        required((received['native'],received['assets'],received['notes'])==(34,{managed:28},2),'two-era recovery failed')
        metrics['wallet']['restored'] = received
        metrics['storage']['cold_wallet'] = disk(out/'offline-wallet')
        controls('initial',initial,a,{'offline':(34,{managed:28})},True)
        old = pay('initial',initial,a,miner['a'])
        outcome['initial_settled'] = old
        snapshot(public/'blocks',a.store/'wallet.sock')
        controls('initial_settled',old,a,{'offline':(3,{managed:3}),'forward':(28,{managed:32})})
        home.stop()
        metrics['storage']['before_restart'] = disk(out/'home','home.sqlite')
        # A public-only miner builds on the signed swap at H14. No funding genesis
        # is regenerated and neither mining key nor private note is used to import state.
        fork = launch(out/'fork-miner')
        metrics['fork_seed'] = fork.rpc('sync',source=b.port,height=14)
        new = fork.rpc('mine',count=14,pk=miner['b'])
        required(new['height']==28 and new['fees']==24,'wrong fork effects')
        metrics['archive2_fork'] = b.rpc('sync',source=fork.port)
        fork.stop()
        home = launch(out/'home',ports)
        required(home.rpc('status')['tip']==old,'restart lost committed selected state')
        reorg = recover('deep',new['tip'])
        required(reorg['recovery']['deep'] and reorg['recovery']['common_height']==14,'fork did not cross retention')
        outcome['reorganized'] = new['tip']
        reverted = ordinary(new['tip'],'reconcile')
        required((reverted['native'],reverted['assets'])==(34,{managed:28}),'restored holdings after branch change')
        metrics['wallet']['reorganized'] = reverted
        controls('reorganized',new['tip'],b,{'offline':(34,{managed:28}),'forward':(0,{})})
        final = pay('final',new['tip'],b,miner['b'])
        outcome['final'] = final
        snapshot(public/'blocks',b.store/'wallet.sock')
        controls('final',final,b,{'offline':(3,{managed:3}),'forward':(28,{managed:25})})
        # Bring the other independent archive to the selected head as an additional
        # end-to-end witness. This transfer is charged outside home/wallet recovery.
        metrics['archive1_final'] = a.rpc('sync',source=b.port)
        required(a.rpc('status')['tip']==final,'second full validator differs')
        save(public/'OUTCOME.json',outcome)
        for role in (home,a,b):
            role.stop()
        for label,directory,db in [('home',out/'home','home.sqlite'),('archive1',a.store,'archive.sqlite'),
                                   ('archive2',b.store,'archive.sqlite'),('wallet',out/'offline-wallet',None)]:
            metrics['storage'][label] = disk(directory,db)
        save(out/'metrics.json',metrics)
    finally:
        for role in reversed(live):
            role.stop()


if __name__ == '__main__':
    if not __debug__:
        sys.exit('run with Python assertions enabled')
    p = argparse.ArgumentParser(description=__doc__)
    for key in ('network','stores','out'):
        p.add_argument(key,type=Path)
    args = p.parse_args()
    campaign(*(v.resolve() for v in vars(args).values()))
