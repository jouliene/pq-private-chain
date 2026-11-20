"""Live user issuance, private multi-asset wallets and branch recovery on the local AST1 PoW network."""
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
HOME = Path(sys.argv[1]).resolve()
sys.path[:0] = [str(HOME/"deployment/devnet"),str(HERE)]
from chain import GENESIS, NETWORK, PROFILE, WINDOW, block_id, decode_block
from cli import Lab, wait
from assets import inventory

LAB = Lab(HOME,HOME/"deployment/runtime")
PUBLIC = HOME/"public"
KEYS = ('network','genesis','tip','height','work','anchor','header','notes','spent','spent_set_sha256','issued','fees')
MINERS = ('miner-a','miner-b','fork-miner','winning-miner')
OWNERS = (*MINERS,'issuer-a','issuer-b','offline','next-a','next-b','sink-a','sink-b')
NATIVE = 'native'


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def cli(*args, refusal=None):
    call = subprocess.run([ROOT/'pqd','assets','--home',HOME,*map(str,args)],
                          capture_output=True,text=True,timeout=330)
    if refusal:
        require(call.returncode != 0 and call.stderr.strip() == refusal,'unexpected wallet refusal: '+call.stderr[-400:])
        return refusal
    if call.returncode:
        raise RuntimeError(str(args[0])+' failed: '+call.stderr[-900:])
    return json.loads(call.stdout)


def status(node):
    st = LAB.status(node)
    return {k:st[k] for k in KEYS}


def converge(nodes):
    return wait(lambda:[status(n) for n in nodes],lambda states:all(s==states[0] for s in states),
                'autonomous convergence on '+nodes)[0]


def retained(node, tip):
    bid = bytes.fromhex(tip)
    while bid != GENESIS:
        file = PUBLIC/'blocks'/(bid.hex()+'.bin')
        if file.exists():
            break
        raw = LAB.request(node,'block',id=bid.hex())[1]
        require(block_id(raw)==bid,'public block identity')
        file.write_bytes(raw)
        b = decode_block(raw)
        for packet in b.packets:
            (PUBLIC/'packets'/(hashlib.sha256(packet).hexdigest()+'.bin')).write_bytes(packet)
        bid = b.parent


def wallet_name(name):
    return 'recovered' if name=='offline' else name


def funds(info):
    return dict(native=info['balance'], assets=info['assets'])


def balance(owner, node='c'):
    return funds(cli('balance',wallet_name(owner),'--node',node))


def public_addr(name):
    return '@'+str(HOME/(name+'.addr'))


class Trial:
    def __init__(self):
        self.run = dict(network=NETWORK.hex(),genesis=GENESIS.hex(),vk=PROFILE.hex(),
                        tips={},registries={},balances={},payments={},miner_keys={},asset_ids={})
        self.blocks = {}

    def block(self,node,bid):
        if bid not in self.blocks:
            raw = LAB.request(node,'block',id=bid)[1]
            require(block_id(raw).hex()==bid,'block fetch identity')
            self.blocks[bid] = decode_block(raw)
        return self.blocks[bid]

    def selected(self,nodes,start,limit,depth=2):
        columns = []
        for n in nodes:
            count = min(limit,status(n)['height']-depth-start+1)
            columns.append(LAB.request(n,'selected',start=start,limit=count)[0] if count>0 else [])
        return [row[0] for row in zip(*columns) if len(set(row))==1]

    def funding_ready(self):
        pks = {LAB.address(n)[1:33] for n in ('miner-a','miner-b')}
        def check():
            seen = set()
            for start in range(1,status('c')['height']+1,128):
                seen.update(self.block('c',b).pk for b in self.selected('abc',start,128))
            return pks<=seen
        wait(check,bool,'common mature reward for each miner')

    def settle(self,result,owner,intent,node):
        nodes = 'abc' if node=='c' else node
        for attempt in range(3):
            start = result['anchor_height']+1
            end = time.monotonic()+110
            while time.monotonic()<end:
                for bid in self.selected(nodes,start,WINDOW):
                    if any(hashlib.sha256(p).hexdigest()==result['tx'] for p in self.block(node,bid).packets):
                        return result
                if status(node)['height']>=start+WINDOW+2:
                    break
                time.sleep(.3)
            if attempt<2:
                result = cli('resume',wallet_name(owner),intent,'--node',node,'--wait',180)
        raise ValueError('payment failed to settle on shared history: '+intent)

    def payment(self,label,payer,payee,native=0,asset=NATIVE,token=0,*,supply=0,resume=None,node='c'):
        owner = wallet_name(payer)
        intent = resume or label
        if resume:
            cmd = ('resume',owner,intent)
        elif supply:
            cmd = ('issue',owner,supply,'--intent',intent)
        else:
            cmd = ('send',owner,public_addr(payee),native,asset,token,'--intent',intent)
        result = cli(*cmd,'--node',node,'--wait',180)
        result = self.settle(result,payer,intent,node)
        require(result['status']=='confirmed','unconfirmed wallet result')
        keys = ('tx','amount','token_amount','asset_id','issue_supply','fee','change','token_change','real_inputs',
                'input_total','token_input_total','anchor_height','packet_B','proving_wall_s','prover_cpu_s',
                'prover_role_peak_rss_KiB')
        row = {k:result[k] for k in keys}
        require(row['fee']==3 and row['amount']==native and row['issue_supply']==supply
                and row['token_amount']==(supply or token),'wallet intent mismatch')
        if token and not supply:
            require(row['asset_id']==asset,'wallet asset mismatch')
        row.update(payer=payer,payee=payee,output_count=2)
        row['wallet_native_meters'] = [m for m in result['wallet_metrics']
                                       if m['operation'] in ('wallet_setup','compact_prove')]
        directory = LAB.walletdir(owner)
        with sqlite3.connect((directory/'ast1-intents.sqlite').as_uri()+'?mode=ro',uri=True) as db:
            pinned = json.loads(db.execute('SELECT pinned FROM intents WHERE id=?',(intent,)).fetchone()[0])
        rows = []
        with sqlite3.connect((directory/'ast1-wallet-state.sqlite').as_uri()+'?mode=ro',uri=True) as db:
            for cm in pinned:
                kind,n,a,t = db.execute('SELECT kind,amount,asset,token FROM owned WHERE cm=?',(bytes.fromhex(cm),)).fetchone()
                rows.append(dict(kind=kind,native=n,asset=a.hex(),token=t))
        row['input_sources'] = rows
        self.run['payments'][label] = row
        return row

    def snapshot(self,label,node,st,owners):
        self.run['tips'][label] = st
        self.run['registries'][label] = inventory(LAB,node,st['tip'])
        self.run['balances'][label] = {name:balance(name,node) for name in owners}
        retained(node,st['tip'])

    def exercise(self):
        for sub in ('blocks','packets'):
            (PUBLIC/sub).mkdir(parents=True)
        initial = LAB.start()
        for name in OWNERS:
            if name not in ('miner-a','miner-b'):
                cli('create',name)
            cli('export-address',name,HOME/(name+'.addr'))
        self.run['miner_keys'] = {n:LAB.address(n)[1:33].hex() for n in MINERS}
        require(LAB.address('issuer-a')!=LAB.address('issuer-b'),'distinct issuer keys')
        seed = HOME/'offline-backup'
        cli('backup','offline',seed)
        require(seed.stat().st_size==32,'seed-only backup size')
        self.funding_ready()
        self.payment('fund-issuer-a','miner-a','issuer-a',50)
        self.payment('fund-issuer-b','miner-b','issuer-b',55)
        a = self.payment('issue-a','issuer-a','issuer-a',supply=180)['asset_id']
        self.payment('deliver-a','issuer-a','offline',asset=a,token=70)
        self.payment('native-23','miner-a','offline',23)
        self.payment('native-17','miner-b','offline',17)
        self.run['continuous'] = {n:{k:v for k,v in LAB.status(n).items() if k in ('remaining','found')} for n in 'ab'}
        require(all(v['remaining']==-1 and v['found']>0 for v in self.run['continuous'].values()),'independent miners')
        LAB.mining('a',0)
        LAB.mining('b',0)
        common = converge('abc')
        self.snapshot('common','c',common,['issuer-a','issuer-b'])
        require(set(self.run['registries']['common'])=={a},'common A registry')
        for n,p in [('a',[]),('b',['c']),('c',['b'])]:
            LAB.links(n,p)
        LAB.mining('a',-1,'fork-miner')
        LAB.mining('b',-1,'winning-miner')
        wait(lambda:status('a')['height'],lambda h:h>common['height'],'fork-only issuance anchor')
        issue = self.payment('branch-issue-b','issuer-b','issuer-b',supply=260,node='a')
        b = issue['asset_id']
        require(a!=b,'distinct new asset identities')
        self.run['asset_ids'] = {'A':a,'B':b}
        self.payment('branch-deliver-b','issuer-b','offline',asset=b,token=60,node='a')
        wait(lambda:status('a')['height'],lambda h:h>=common['height']+9,'detachment beyond undo window')
        LAB.mining('a',0)
        loser = status('a')
        self.snapshot('loser','a',loser,['issuer-a','issuer-b','fork-miner'])
        require(set(self.run['registries']['loser'])=={a,b},'losing issue registry')
        raw = LAB.request('a','tx',id=issue['tx'])[1]
        try:
            LAB.request('a','submit',raw)
        except ValueError as err:
            require(str(err)=='asset already issued','unexpected issuance rejection')
            self.run['duplicate_issuance'] = str(err)
        else:
            raise ValueError('duplicate issuance accepted')
        require(status('a')==loser and LAB.status('a')['mempool']==0,'duplicate issuance mutated state')
        wait(lambda:status('b')['height'],lambda h:h>=max(loser['height']+2,common['height']+WINDOW+4),'heavier competing branch')
        LAB.mining('b',0)
        win = converge('bc')
        require(win['work']>loser['work'] and win['fees']==common['fees'] and loser['fees']==win['fees']+6,'fork work/fees')
        self.snapshot('winner','b',win,['issuer-a','issuer-b','fork-miner'])
        require(self.run['registries']['winner']==self.run['registries']['common'],'surviving A and removed B')
        require(not (HOME/'nodes/d/chain.sqlite').exists(),'cold node store exists')
        fresh = LAB.launch('d')
        require(fresh['height']==0 and fresh['issued']==0 and not inventory(LAB,'d',fresh['tip']),'cold empty genesis')
        LAB.links('d',['a'])
        require(converge('da')==loser and inventory(LAB,'d',loser['tip'])==self.run['registries']['loser'],'cold rejected losing history')
        LAB.links('d',['b'])
        require(converge('db')==win and inventory(LAB,'d',win['tip'])==self.run['registries']['winner'],'cold failed heavier selection')
        for n in 'abcd':
            LAB.links(n,[p for p in 'abcd' if p!=n])
        require(converge('abcd')==win,'nodes failed to converge')
        require(balance('issuer-b','a')=={'native':55,'assets':{}} and balance('fork-miner','a')=={'native':0,'assets':{}},
                'orphan issuance, private change or reward remains')
        self.run['fresh_tips'] = [fresh['tip'],loser['tip'],win['tip']]
        self.run['deep_replays'] = {n:LAB.status(n)['deep_replays'] for n in 'ad'}
        require(min(self.run['deep_replays'].values())>0,'deep selected-state reconstruction')
        for n in 'ab':
            LAB.mining(n,-1,'miner-'+n)
        renewed = self.payment('issue-b','issuer-b','issuer-b',supply=260,resume='branch-issue-b')
        require(renewed['asset_id']==b and renewed['tx']!=issue['tx'],'reauthorized issuance identity')
        self.payment('deliver-b','issuer-b','offline',asset=b,token=60)
        require(not (LAB.walletdir('offline')/'ast1-wallet-state.sqlite').exists() and not LAB.walletdir('recovered').exists(),
                'recipient must be offline before restore')
        restored = funds(cli('restore','recovered',seed,'--node','c'))
        require(restored=={'native':40,'assets':{a:70,b:60}},'cold restored native and both assets')
        self.run['offline_restore'] = restored
        first = self.payment('spend-a','offline','next-a',9,a,45)
        second = self.payment('spend-b','offline','next-b',6,b,34)
        require([(p['real_inputs'],p['change'],p['token_change']) for p in (first,second)]==[(2,11,25),(2,8,26)],
                'partial payment change')
        self.run['wallet_wrong_asset'] = cli('send','next-a',public_addr('sink-b'),0,b,1,'--intent','wrong-lane',
                                            refusal='insufficient compatible funds within two unreserved inputs')
        self.payment('onward-a','next-a','sink-a',4,a,13)
        self.payment('onward-b','next-b','sink-b',1,b,8)
        LAB.mining('a',0)
        LAB.mining('b',0)
        final = converge('abcd')
        self.snapshot('final','d',final,OWNERS)
        reg = self.run['registries']['final']
        require(reg[a]['supply']==180 and reg[a]['tx']==self.run['payments']['issue-a']['tx']
                and reg[b]['supply']==260 and reg[b]['tx']==renewed['tx'] and len(reg)==2,'final fixed issuances')
        require(all(inventory(LAB,n,final['tip'])==reg for n in 'abc'),'registry divergence')
        wallets = self.run['balances']['final']
        for who,native,assets in [('offline',19,{a:25,b:26}),('next-a',2,{a:32}),('next-b',2,{b:26}),
                                  ('sink-a',4,{a:13}),('sink-b',1,{b:8})]:
            require(wallets[who]==dict(native=native,assets=assets),who+' terminal spend/change')
        require(sum(w['native'] for w in wallets.values())==final['issued']==final['height']*100
                and final['fees']==36 and set().union(*(w['assets'] for w in wallets.values()))==set(reg),
                'native issuance and fee reconciliation')
        for asset,row in reg.items():
            require(sum(w['assets'].get(asset,0) for w in wallets.values())==row['supply'],'fixed supply mismatch')
        self.run['fresh_tips'].append(final['tip'])
        self.run['original_peer_processes_retained'] = all(initial[n]['pid']==LAB.status(n)['pid'] for n in 'abc')
        require(self.run['original_peer_processes_retained'],'initial peers restarted during multi-asset operation')
        (PUBLIC/'RUN.json').write_text(json.dumps(self.run,sort_keys=True,indent=2)+'\n')
        return dict(result='passed',public=str(PUBLIC),height=final['height'],native_issued=final['issued'],
                    fees=final['fees'],fixed_supply={i:d['supply'] for i,d in reg.items()})


if __name__=='__main__':
    if (HOME/'nodes').exists() or PUBLIC.exists():
        sys.exit('walkthrough needs a fresh home')
    try:
        print(json.dumps(Trial().exercise(),indent=2))
    finally:
        if (HOME/'network.json').exists():
            LAB.stop()
