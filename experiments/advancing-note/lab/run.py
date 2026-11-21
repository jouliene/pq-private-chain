"""Fund a separate pool, exercise moving-branch wallet payments, and replay public blocks."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
import os
import shutil
import struct
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ZERO, data, digest, funding_policy, genesis_id, need, parse, split_bundle, store, u32s
from roles import Roles, Peak, tree_cpu

A = digest('N7G2/disposable-asset', b'A')[:32]
B = digest('N7G2/disposable-asset', b'B')[:32]
PALETTE = {'alice': [(5,11,A),(7,23,A)], 'bob': [], 'eve': [(8,4,A)], 'frank': [(45,20,A)],
           'carol': [(3,4,A),(4,5,A)], 'dana': [(4,18,B),(6,17,B)], 'sink': []}


class Campaign:
    def __init__(self, roles):
        self.roles = roles
        self.folder = roles.folder
        self.private = roles.private
        self.controls = {}
        self.proofs = {}
        self.addresses = {}
        self.branches = self.folder / 'branch'
        self.branches.mkdir()

    def wallet(self, who, op, cfg, label, **args):
        return self.roles.wallet(who, op, cfg, label=label, **args)

    def genesis(self):
        seeds = self.private / 'seeds'
        seeds.mkdir(mode=0o700)
        self.roles.public.mkdir()
        nonce = os.urandom(32)
        scope = digest('N7G2/key-scope', nonce)
        for name in PALETTE:
            (seeds / name).write_bytes(os.urandom(48))
            (self.private / name).mkdir(mode=0o700)
            self.addresses[name] = self.wallet(name, 'init', dict(net=scope.hex(),scope=scope.hex()), 'address-'+name)
        grants = [dict(owner=self.addresses[o]['owner'],asset=u32s(asset),native=n,token=t)
                  for o,rows in PALETTE.items() for n,t,asset in rows]
        self.net = funding_policy(nonce, grants)
        credits = []
        supply = Counter()
        for who, notes in PALETTE.items():
            if not notes:
                continue
            rows = []
            for n,t,asset in notes:
                i = len(credits)+len(rows)
                rows.append(dict(index=i,slot=i%2,native=n,token=t,asset=asset.hex()))
                supply['native'] += n
                supply[asset.hex()] += t
            credits.extend(self.wallet(who,'fund',dict(net=self.net.hex(),scope=scope.hex(),rows=rows),'grants-'+who))
        genesis = dict(profile='N7P2',network=self.net.hex(),nonce=nonce.hex(),credits=credits,issued=supply)
        store(self.roles.public/'genesis.json',genesis)
        (self.folder/'founding-id').write_text(genesis_id(genesis).hex()+'\n')
        need(all(row['owner'] != self.addresses['bob']['owner'] for row in credits),'recipient has founding credit')
        return self.wallet('bob','balance',{},'initial-zero-recipient')

    def payment(self, who, recipient, n, t, label, *, prefix=None):
        cfg=dict(kind=0,recipient=self.addresses[recipient],native=n,token=t,asset=A.hex())
        return self.offer(who,cfg,label,public=prefix)

    def offer(self, who, cfg, label, **extra):
        self.proofs[label]=self.wallet(who,'prepare',cfg,label,**extra)
        return (self.private/who/'offer.bin').read_bytes()

    def start_swap(self):
        plan=dict(net=self.net.hex(),nonce=os.urandom(48).hex(),expiry=24,payer=1,
                  parties=[dict(address=self.addresses['carol'],native=0,token=7,asset=A.hex()),
                           dict(address=self.addresses['dana'],native=0,token=30,asset=B.hex())])
        exchange=self.private/'exchange'
        exchange.mkdir(mode=0o700)
        core=self.offer('carol',dict(kind=1,agreement=plan),'carol-leg')
        (exchange/'leg-0.bin').write_bytes(core)
        return plan,exchange

    def swap(self,server,start):
        plan,exchange=start
        second=self.offer('dana',dict(kind=2,agreement=plan),'dana-leg')
        (exchange/'leg-1.bin').write_bytes(second)
        frames=[(exchange/'leg-0.bin').read_bytes(),second]
        a,b=[parse(c)['statement'] for c in frames]
        need(a['count']+18==b['count'] and a['root']!=b['root'],'swap must cross nine funded updates')
        sigs=[]
        for j, who in enumerate(('carol','dana')):
            approval=self.wallet(who,'authorize',dict(side=j,agreement=plan),who+'-authorize',exchange=exchange)
            need(approval['verified_both_proofs'] and approval['checked_incoming_and_change'],'approval scope')
            sigs.append((self.private/who/'auth.bin').read_bytes())
        bundle=b'N7S2'+b''.join(struct.pack('<I',len(c)+len(s))+c+s for c,s in zip(frames,sigs,strict=True))
        bad=bytearray(bundle)
        bad[-1]^=1
        self.controls['changed_approval']=server.rejected(bad,'owner authorization')
        self.controls['incomplete_swap']=server.rejected(frames[0],'incomplete swap')
        server.include(bundle)
        return dict(signed_leg_B=[len(c)+len(s) for c,s in zip(frames,sigs,strict=True)],
                    negotiation_core_and_approvals_B=sum(map(len,frames+sigs)),
                    private_agreement_JSON_B=len(json.dumps(plan,sort_keys=True,separators=(',',':')).encode()),
                    submitted_B=len(bundle))

    def generate(self):
        zero=self.genesis()
        need(zero==dict(count=0,native=0,assets={}), 'first recipient initially funded')
        with self.roles.service(self.roles.public, forks=True) as server:
            swap_start=self.start_swap()
            unrelated=self.payment('eve','sink',2,1,'unrelated')
            first=self.payment('alice','bob',7,13,'first-two-real')
            need(self.proofs['first-two-real']['inputs']==2,'funding arity')
            server.include(first)
            prefix_state=server.summary()
            # The previous recipient process is gone. The new role gets one seed and a clean private mount.
            who='restored'
            shutil.copyfile(self.private/'seeds/bob', self.private/'seeds'/who)
            (self.private/who).mkdir(mode=0o700)
            restored=self.wallet(who,'balance',{},'restore-one-note')
            need(restored==dict(count=1,native=7,assets={A.hex():13}), 'recovery inventory')
            prefix=self.private/'public-at-one'
            shutil.copytree(self.roles.public,prefix,ignore=shutil.ignore_patterns('.*'))
            block=server.mined(unrelated)
            marker=self.private/who/'proving.marker'
            with ThreadPoolExecutor(max_workers=1) as pool:
                future=pool.submit(self.payment,who,'alice',2,3,'restored-onward',prefix=prefix)
                deadline=time.monotonic()+600
                while not marker.is_file():
                    if future.done():
                        future.result()
                        raise RuntimeError('native proof did not signal phase')
                    if time.monotonic()>deadline:
                        raise RuntimeError('native prove marker timed out')
                    time.sleep(.005)
                advanced=server.call('accept',block=block.hex())['metric']
                onward=future.result()
            need(self.proofs['restored-onward']['inputs']==1,'recipient required multiple inputs')
            native=self.proofs['restored-onward']['proof']
            t0,t1=native['prove_start_ns'],native['prove_end_ns']
            need(t0<=advanced['start_ns']<advanced['end_ns']<=t1,'append outside cryptographic proving interval')
            self.branches.joinpath('original-2.bin').write_bytes(block)
            self.branches.joinpath('original-3.bin').write_bytes(server.include(onward))
            old_tip=server.summary()
            # Different public statement, same current authorizations. Verify it later on the unspent prefix.
            conflict=self.payment(who,'sink',1,4,'conflicting-authorized',prefix=prefix)
            need(parse(conflict)['statement']['nullifiers']==parse(onward)['statement']['nullifiers']
                 and conflict!=onward,'retry spent identities')
            self.branches.joinpath('conflict.packet').write_bytes(conflict)
            self.controls['current_conflict']=server.rejected(conflict,'spent')
            probe=self.payment('frank','sink',1,1,'orphan-anchored')
            self.branches.joinpath('detached.packet').write_bytes(probe)
            # Demonstrate genuine admissibility on the original tip, then durably rewind three blocks.
            server.include(probe)
            server.call('revert')
            need(server.summary()==old_tip,'remove probe')
            server.call('revert')
            server.call('revert')
            need(server.summary()==prefix_state,'rollback root, fees, or nullifiers')
            # The independent conflicting proof is valid here. Revert before choosing the other spend.
            server.include(conflict)
            server.call('revert')
            need(server.summary()==prefix_state,'rollback conflicting branch')
            server.include(onward)
            server.include(unrelated)
            new_tip=server.summary()
            need(new_tip['root']!=old_tip['root'] and new_tip['count']==old_tip['count']
                 and new_tip['spent_hash']==old_tip['spent_hash'],'alternate ordering')
            self.controls['detached_root']=server.rejected(probe,'root/count')
            self.controls['same_prefix_spent']=server.rejected(conflict,'spent')
        # Restart from the public files. Reverted blocks must be absent on disk.
        with self.roles.service(self.roles.public,forks=True) as server:
            need(server.summary()==new_tip,'durable branch recovery')
            self.controls['detached_after_restart']=server.rejected(probe,'root/count')
            for seq in range(6):
                server.include(self.payment('frank','sink',1,1,f'sequential-{seq+1}'))
            exchange=self.swap(server,swap_start)
            final=server.summary()
        balances={}
        for who in ('alice','restored','eve','frank','carol','dana','sink'):
            balances[who]=self.wallet(who,'balance',{},'final-'+who)
        expected={'alice':(4,24,0),'restored':(2,10,0),'eve':(3,3,0),'frank':(21,14,0),
                  'carol':(7,2,30),'dana':(7,7,5),'sink':(8,7,0)}
        for who,(n,a,b) in expected.items():
            assets={k.hex():v for k,v in ((A,a),(B,b)) if v}
            need(balances[who]['native']==n and balances[who]['assets']==assets,'wallet reconciliation '+who)
        need(final['issued']=={'native':82,A.hex():67,B.hex():35}
             and sum(final['miner_fees'].values())==30 and final['spent']==22,'supply or spent identities')
        return dict(zero=zero,restored=restored,balances=balances,proofs=self.proofs,wallets=self.roles.wallet_cost,
                    controls=self.controls,exchange=exchange,final=final,old_tip=old_tip,prefix=prefix_state,
                    alternate=new_tip,overlap=dict(native_start_ns=t0,accept_start_ns=advanced['start_ns'],
                    accept_end_ns=advanced['end_ns'],native_end_ns=t1,advanced_height=advanced['height']))

def public_checks(roles):
    blocks=sorted(roles.public.glob('block-*.bin'))
    need(len(blocks)==10,'canonical history length')
    raw=[p.read_bytes() for p in blocks]
    # Exactly nine ordinary packets and one two-party swap. Fixtures and expected values stay outside timers.
    need([b[180:184] for b in raw]==[b'N7P2']*9+[b'N7S2'],'mixed series')
    samples=[]
    for epoch in range(3):
        with tempfile.TemporaryDirectory(prefix='n7p2-public-mix-') as tmp:
            ledger=Path(tmp)
            shutil.copyfile(roles.public/'genesis.json',ledger/'genesis.json')
            with roles.service(ledger) as server:
                coded=[r.hex() for r in raw]
                rows=[]
                peak=Peak(server.proc.pid)
                cpu=tree_cpu(server.proc.pid)
                start=time.monotonic()
                try:
                    for block in coded:
                        rows.append(server.call('accept',block=block)['metric'])
                    elapsed=time.monotonic()-start
                    cpu=tree_cpu(server.proc.pid)-cpu
                finally:
                    memory=peak.finish()
                state=server.summary()
                need(state['height']==10 and state['spent']==22 and all(row['durable'] for row in rows),
                     'durable public sequence')
                need(sum(len(row['legs']) for row in rows)==11 and sum(row['signatures'] for row in rows)==2,
                     'incomplete proof or signature verification')
                samples.append(dict(cold=server.cold,registration=server.ready['verifier'],warm=rows,
                                    cpu_s=cpu,wall_s=elapsed,**memory,final=state,
                                    stored_block_B=sum(p.stat().st_size for p in ledger.glob('block-*.bin')),
                                    index_stat=server.call('summary').get('index_stat',{})))
    branch=roles.folder/'branch'
    with tempfile.TemporaryDirectory(prefix='n7p2-public-reorg-') as tmp:
        ledger=Path(tmp)
        shutil.copyfile(roles.public/'genesis.json',ledger/'genesis.json')
        with roles.service(ledger,forks=True) as server:
            server.call('accept',block=raw[0].hex())
            common=server.summary()
            for i in (2,3):
                server.call('accept',block=(branch/f'original-{i}.bin').read_bytes().hex())
            detached=(branch/'detached.packet').read_bytes()
            conflict=(branch/'conflict.packet').read_bytes()
            server.include(detached)
            server.call('revert')
            server.rejected(conflict,'spent')
            server.call('revert')
            server.call('revert')
            need(server.summary()==common,'public rollback')
            server.include(conflict)
            server.call('revert')
            for r in raw[1:3]:
                server.call('accept',block=r.hex())
            server.rejected(detached,'root/count')
            server.rejected(conflict,'spent')
            for r in raw[3:]:
                server.call('accept',block=r.hex())
            need(server.summary()==samples[0]['final'],'public branch replay')
    # Exactly one funded update makes genesis a unique old root. Empty, valid PoW blocks age it.
    with tempfile.TemporaryDirectory(prefix='n7p2-public-window-') as tmp:
        ledger=Path(tmp)
        shutil.copyfile(roles.public/'genesis.json',ledger/'genesis.json')
        with roles.service(ledger,forks=True) as server:
            server.include(raw[2][180:])
            for _ in range(62):
                server.include(b'')
            eligible=server.summary()
            need(eligible['height']==63,'positive anchor boundary height')
            server.include(raw[0][180:])
            server.call('revert')
            need(server.summary()==eligible,'positive boundary rollback')
            server.include(b'')
            expired=server.rejected(raw[0][180:],'root/count')
        with roles.service(ledger) as restarted:
            need(restarted.summary()['height']==64,'window restart height')
            restarted.rejected(raw[0][180:],'root/count')
    return dict(cpu_affinity=roles.cpus,trials=samples,
                window=dict(accepted_at_age=63,rejected_at_age=64,reason=expired,checked_after_restart=True))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=('fresh','check'))
    p.add_argument('binary',type=Path)
    p.add_argument('node',type=Path)
    p.add_argument('folder',type=Path)
    a=p.parse_args()
    with tempfile.TemporaryDirectory(prefix='n7p2-private-') as tmp:
        roles=Roles(a.binary,a.node,a.folder,Path(tmp))
        if a.mode=='fresh':
            roles.folder.mkdir(parents=True,exist_ok=False)
            result=Campaign(roles).generate()
            result['public']=public_checks(roles)
            need(all(trial['final']==result['final'] for trial in result['public']['trials']),'public acceptance')
            store(roles.folder/'RESULT.json',result)
            print(json.dumps(dict(controls=result['controls'],final=result['final'],overlap=result['overlap'])))
        else:
            print(json.dumps(public_checks(roles)))

if __name__=='__main__':
    main()
