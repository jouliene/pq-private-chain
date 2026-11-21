"""Operate isolated one-seed wallets, a fresh genesis, and public-only replay."""
import argparse
from collections import Counter
from hashlib import sha3_384
import json
import os
from pathlib import Path
import resource
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time

HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE.parents[1]/'funded-tcith/wallet')]
from common import *
from subtree import sample

ASSET_A=digest('N7G1/disposable-asset',b'asset A')[:32]
ASSET_B=digest('N7G1/disposable-asset',b'asset B')[:32]


class Lab:
    def __init__(self,binary,node,folder):
        self.binary=binary.resolve(strict=True); self.node=node.resolve(strict=True)
        self.folder=folder.resolve(); self.pub=self.folder/'public'
        self.temp=None
        self.profiles={}

    def run(self,label,script,mode,request=None,owner=None,item=None,exchange=None,binary=False):
        args=['bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv','--cap-drop','ALL',
              '--setenv','PATH','/usr/bin:/bin','--setenv','LANG','C','--setenv','RAYON_NUM_THREADS','4',
              '--dev','/dev','--proc','/proc','--tmpfs','/tmp']
        for src,dst in [(s,s) for s in ('/usr','/lib','/lib64','/bin','/etc/ld.so.cache')]+[
                (self.binary,'/circuit'),(self.node,'/node'),(HERE,'/lab'),(self.pub,'/public')]:
            args+=['--ro-bind',str(src),dst]
        if (self.folder/'founding-id').is_file():
            args+=['--ro-bind',str(self.folder/'founding-id'),'/founding-id']
        if owner:
            args+=['--ro-bind',str(self.temp/'seeds'/owner),'/seed','--bind',str(self.temp/owner),'/own']
        if item:
            args+=['--ro-bind',str(item),'/item']
        if exchange:args+=['--ro-bind',str(exchange),'/exchange']
        args+=['--remount-ro','/','--chdir','/','--','/usr/bin/time','-f','N7M %U %S %M','/usr/bin/python3','-IB','/lab/'+script+'.py',mode]
        start=time.perf_counter()
        proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        peaks=[0,0]; stop=threading.Event()
        def meter():
            while not stop.is_set():
                rss,pss=sample(proc.pid)
                peaks[0]=max(peaks[0],rss); peaks[1]=max(peaks[1],pss or 0)
                stop.wait(.05)
        worker=threading.Thread(target=meter,daemon=True);worker.start()
        try:
            out,err=proc.communicate(json.dumps(request or {}).encode())
        finally:
            stop.set();worker.join()
        if proc.returncode:
            # Role exceptions are fixed public labels. Native witness diagnostics never cross the wallet boundary.
            raise RuntimeError(label+' failed: '+err.decode()[-1800:])
        tag,user,system,peak=err.decode().splitlines()[-1].split()
        need(tag=='N7M','missing role meter')
        if label in self.profiles:
            serial=2
            while f'{label}-{serial}' in self.profiles: serial+=1
            label=f'{label}-{serial}'
        self.profiles[label]=dict(wall_s=time.perf_counter()-start,user_s=float(user),system_s=float(system),
                                  individual_peak_KiB=int(peak),sampled_tree_RSS_KiB=peaks[0],sampled_tree_PSS_KiB=peaks[1])
        if binary:return out
        return json.loads(out) if script!='state' or mode=='verify' else out.decode().strip()

    def wallet(self,owner,mode,request,**kwargs):
        return self.run(owner+'-'+mode,'wallet',mode,request,owner=owner,**kwargs)

    def block(self,packet,index):
        f=self.temp/'candidate.bin';f.write_bytes(packet)
        raw=self.run('include-'+str(index),'state','mine',item=f,binary=True)
        with (self.pub/f'block-{index:04}.bin').open('xb') as out:out.write(raw)
        return len(raw)

    def reject(self,payload,label,expected):
        f=self.temp/'invalid-candidate.bin'; f.write_bytes(payload)
        reason=self.run('reject-'+label,'state','controls',item=f)
        need(expected in reason,label+' unexpected verdict '+reason)
        return reason

    def generate(self):
        self.pub.mkdir(parents=True,exist_ok=False)
        nonce=os.urandom(32);scope=digest('N7G1/key-scope',nonce)
        seeds=self.temp/'seeds';seeds.mkdir(mode=0o700)
        def create(name):
            (seeds/name).write_bytes(os.urandom(48));(self.temp/name).mkdir(mode=0o700)
            return self.wallet(name,'init',dict(net=scope.hex(),scope=scope.hex()))
        owners=('alice','bob','carol','dana')
        addresses={n:create(n) for n in owners}
        palette={'alice':[(5,11,ASSET_A),(7,23,ASSET_A)],'bob':[(8,0,ZERO)],
                 'carol':[(3,5,ASSET_A),(4,9,ASSET_A)],'dana':[(4,20,ASSET_B),(6,15,ASSET_B)]}
        grants=[dict(owner=addresses[o]['owner'],asset=u32s(asset),native=n,token=t)
                for o in owners for n,t,asset in palette[o]]
        net=funding_policy(nonce,grants)
        credits=[];issued=Counter()
        for owner in owners:
            rows=[]
            for n,t,asset in palette[owner]:
                i=len(credits)+len(rows)
                rows.append(dict(index=i,slot=i%2,native=n,token=t,asset=asset.hex()))
                issued['native']+=n
                if t:issued[asset.hex()]+=t
            credits.extend(self.wallet(owner,'fund',dict(net=net.hex(),scope=scope.hex(),rows=rows)))
        store(self.pub/'genesis.json',dict(profile='N7P1',network=net.hex(),nonce=nonce.hex(),credits=credits,issued=issued))
        (self.folder/'founding-id').write_text(genesis_id(data(self.pub/'genesis.json')).hex()+'\n')
        result=dict(wallet={},balances={},controls={})
        first_cfg=dict(kind=0,recipient=addresses['bob'],native=4,token=13,asset=ASSET_A.hex())
        result['wallet']['payment']=self.wallet('alice','prepare',first_cfg)
        first=(self.temp/'alice/offer.bin').read_bytes()
        # All negative cases below run against the still-unspent public genesis.
        edit=bytearray(first);edit[349]^=1  # ordered ciphertext byte
        result['controls']['changed_receipt']=self.reject(edit,'receipt','verify rejected')
        edit=bytearray(first); edit[109:117]=struct.pack('<Q',len(credits)-1)
        result['controls']['changed_count']=self.reject(edit,'count','root/count')
        edit=bytearray(first);edit[53]^=1
        result['controls']['changed_root']=self.reject(edit,'root','root/count')
        edit=bytearray(first);edit[-1]^=1
        result['controls']['corrupt_proof']=self.reject(edit,'proof','verify rejected')
        edit=bytearray(first);edit[5]^=1
        result['controls']['foreign_network']=self.reject(edit,'net','foreign network')
        result['controls']['legacy_profile']=self.reject(b'MSP1'+bytes(4000),'legacy','profile')
        sys.path[:0]=[str(HERE.parents[1]/'managed-assets'),str(HERE.parents[1]/'atomic-swap')]
        from managed_ops import parse as parse_managed
        from swap_wire import leg_shape as parse_swap_leg
        for name,decoder in (('managed',parse_managed),('leg',parse_swap_leg)):
            try: decoder(first)
            except ValueError as exc: result['controls']['old_'+name+'_excludes_new']=str(exc)
            else: raise ValueError('old registration accepted new packet')
        result['block_payment_B']=self.block(first,1)
        result['controls']['duplicate']=self.reject(first,'duplicate','spent')
        # A separate new process and empty private wallet directory see only Bob's original backup and public history.
        alias='bob-restored'
        shutil.copyfile(seeds/'bob',seeds/alias);(self.temp/alias).mkdir(mode=0o700)
        bob=self.wallet(alias,'balance',{})
        need(bob==dict(count=2,native=12,assets={ASSET_A.hex():13}),'wrong restored balance')
        result['balances']['restored']=bob
        result['wallet']['onward']=self.wallet(alias,'prepare',dict(kind=0,recipient=addresses['alice'],
                                                native=5,token=3,asset=ASSET_A.hex()))
        result['block_onward_B']=self.block((self.temp/alias/'offer.bin').read_bytes(),2)
        # Both participants know this salted private agreement and each sees only its own seed.
        agr=dict(net=net.hex(),nonce=os.urandom(48).hex(),expiry=8,payer=1,
                 parties=[dict(address=addresses['carol'],native=0,token=7,asset=ASSET_A.hex()),
                          dict(address=addresses['dana'],native=0,token=30,asset=ASSET_B.hex())])
        exchange=self.temp/'exchange';exchange.mkdir(mode=0o700)
        raws=[];sigs=[]
        for j,owner in enumerate(('carol','dana')):
            result['wallet'][owner]=self.wallet(owner,'prepare',dict(kind=j+1,agreement=agr))
            raw=(self.temp/owner/'offer.bin').read_bytes(); raws.append(raw)
            (exchange/f'leg-{j}.bin').write_bytes(raw)
        result['controls']['half_swap']=self.reject(raws[0],'incomplete','incomplete swap')
        for j,owner in enumerate(('carol','dana')):
            result['wallet'][owner+'_approval']=self.wallet(owner,'authorize',dict(side=j,agreement=agr),exchange=exchange)
            sigs.append((self.temp/owner/'auth.bin').read_bytes())
        bundle=b'N7S1'+b''.join(struct.pack('<I',len(r)+len(s))+r+s for r,s in zip(raws,sigs,strict=True))
        edit=bytearray(bundle);edit[-1]^=1
        result['controls']['changed_signature']=self.reject(edit,'approval','owner authorization')
        result['exchange_bytes']=dict(private_terms_JSON=len(json.dumps(agr,sort_keys=True,separators=(',',':')).encode()),
                                      core_each=list(map(len,raws)),approval_each=list(map(len,sigs)),
                                      public_bundle=len(bundle))
        result['block_swap_B']=self.block(bundle,3)
        result['final']=self.run('public-replay','state','verify')
        for who in ('alice',alias,'carol','dana'):
            result['balances'][who]=self.wallet(who,'balance',{})
        sums=Counter()
        for who in ('alice',alias,'carol','dana'):
            b=result['balances'][who];sums['native']+=b['native'];sums.update(b['assets'])
        sums['native']+=sum(result['final']['state']['miner_fees'].values())
        need(dict(sums)==dict(issued) and result['final']['state']['spent']==8,'supply reconciliation')
        expected={'alice':(2,10,24,0),alias:(1,4,10,0),'carol':(2,7,7,30),'dana':(2,7,7,5)}
        for who,(count,native,asset_a,asset_b) in expected.items():
            assets={k.hex():v for k,v in ((ASSET_A,asset_a),(ASSET_B,asset_b)) if v}
            need(result['balances'][who]==dict(count=count,native=native,assets=assets),'wrong wallet change or receipt')
        result['isolated_roles']=self.profiles
        return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=('fresh','verify'));p.add_argument('binary',type=Path)
    p.add_argument('node',type=Path);p.add_argument('folder',type=Path)
    a=p.parse_args();lab=Lab(a.binary,a.node,a.folder)
    if a.mode=='fresh':
        with tempfile.TemporaryDirectory(prefix='n7-private-') as tmp:
            lab.temp=Path(tmp);result=lab.generate()
        store(lab.folder/'RESULT.json',result)
        print(json.dumps(result['final'],indent=2))
    else:
        print(json.dumps(lab.run('public-replay','state','verify'),indent=2))
