"""Public-only research ledger, ordered fixed-depth tree and exact atomic fee accounting."""
from collections import Counter
from copy import copy
from hashlib import sha3_384
import json
from pathlib import Path
import struct
import time
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import *


class Tree:
    def __init__(self, arithmetic):
        self.arithmetic=arithmetic
        self.empty=[arithmetic.call('empty')]
        self.layers=[{} for _ in range(DEPTH+1)]
        for level in range(DEPTH):
            z=self.empty[-1]
            self.empty.append(self.parent(level,z,z))
        self.count=0

    def parent(self, level, a, b):
        return self.arithmetic.call('parent',level=level,left=a,right=b)

    def get(self, level, i):
        return self.layers[level].get(i,self.empty[level])

    def append(self, cm):
        need(self.count<MAX_COUNT,'tree full')
        i=self.count
        self.count+=1
        self.layers[0][i]=cm
        for level in range(DEPTH):
            parent=i//2
            self.layers[level+1][parent]=self.parent(level,self.get(level,2*parent),self.get(level,2*parent+1))
            i=parent

    @property
    def root(self):
        return self.get(DEPTH,0)

    def path(self,index):
        need(0<=index<self.count,'invalid occurrence')
        return [self.get(j,(index>>j)^1) for j in range(DEPTH)]


def unframe(raw):
    need(raw[:4]==b'N7B1' and len(raw)>180,'block framing')
    header=raw[:176]
    size,=struct.unpack_from('<I',raw,176)
    packet=raw[180:]
    need(len(packet)==size and size<=2*MAX_PACKET+12,'block payload')
    need(header[104:152]==digest('N7B1/body',raw[176:]),'block body binding')
    need(int.from_bytes(digest('N7B1/work',header)[:2],'big')<64,'block work')
    return header,packet


class Ledger:
    def __init__(self,arith,genesis):
        self.arith=arith
        self.tree=Tree(arith)
        self.net=bytes.fromhex(genesis['network'])
        self.tip=self.genesis=genesis_id(genesis)
        need(self.genesis.hex()==Path('/founding-id').read_text().strip(),'unapproved founding genesis')
        self.scope=digest('N7G1/key-scope',bytes.fromhex(genesis['nonce']))
        need(genesis['profile']=='N7P1' and self.net==funding_policy(bytes.fromhex(genesis['nonce']),genesis['credits']),'new genesis domain')
        self.height=0
        self.spent=set()
        self.cms=set()
        self.history=[]
        self.fees=Counter()
        self.supply=Counter()
        for i,row in enumerate(genesis['credits']):
            n={k:row[k] for k in ('owner','asset','native','token')}
            n['salt']=credit_salt(self.net,i)
            need(0<=n['native']<2**62 and 0<=n['token']<2**62 and bool(n['token'])==any(n['asset']),'genesis note')
            self.supply['native']+=n['native']
            if n['token']: self.supply[struct.pack('<8I',*n['asset']).hex()]+=n['token']
            cm=self.arith.call('note',note=n)
            ct=bytes.fromhex(row['receipt'])
            need(row['cm']==cm and len(ct)==CT and pack(cm) not in self.cms,'genesis credit')
            self.add(cm,ct,i%2)
        need(dict(self.supply)==genesis['issued'],'founding quantities')
        self.metrics=[]

    def add(self,cm,ct,slot):
        self.tree.append(cm); self.cms.add(pack(cm));self.history.append((cm,ct,slot))

    def validate(self,packet):
        if packet[:4]==b'N7S1':
            frames=split_bundle(packet,self.genesis)
            (_,a,_),(_,b,_)=frames
            need((a['expiry'],a['terms'],a['payer'])==(b['expiry'],b['terms'],b['payer']) and
                 a['auth']!=b['auth'] and self.height+1<=a['expiry'],'swap agreement or expiry')
            decision=swap_digest(frames[0][0],frames[1][0])
            for _,leg,sig in frames:
                need(crypto('verify',leg['auth']+decision+sig)==bytes([1]),'owner authorization')
            legs=[a,b]
        else:
            leg=parse(packet,self.genesis); need(leg['kind']==0,'incomplete swap')
            legs=[leg]
        nfs=[]; cms=[]; fees=0
        for leg in legs:
            s=leg['statement']
            need(leg['net']==self.net,'foreign network')
            nfs.extend(map(pack,s['nullifiers'])); cms.extend(map(pack,s['outputs']));fees+=s['fee']
        need(len(set(nfs))==len(nfs) and not self.spent.intersection(nfs),'spent or repeated nullifier')
        need(len(set(cms))==len(cms) and not self.cms.intersection(cms),'previous or duplicate output')
        need(self.tree.count+len(cms)<=MAX_COUNT and fees==3,'capacity or fee')
        meters=[]
        for leg in legs:
            s=leg['statement']
            need(s['count']==self.tree.count and s['root']==self.tree.root,'wrong selected root/count')
            _,m=role('verify',s,leg['proof']);meters.append(m)
        return legs,nfs,fees,meters

    def mine(self,packet,miner):
        # The test driver has no authority to set a root or declare a proof valid.
        body=struct.pack('<I',len(packet))+packet
        core=(b'N7B1'+self.net+struct.pack('<I',self.height+1)+self.tip+digest('N7B1/body',body)+miner+struct.pack('<I',3))
        need(len(core)==172,'header layout')
        for n in range(2**32):
            header=core+struct.pack('<I',n)
            if int.from_bytes(digest('N7B1/work',header)[:2],'big')<64:
                return header+body
        raise ValueError('nonce exhausted')

    def accept(self,raw):
        header,packet=unframe(raw)
        need(header[4:52]==self.net and int.from_bytes(header[52:56],'little')==self.height+1 and header[56:104]==self.tip,'block ancestry')
        start=time.perf_counter(); cpu=time.process_time()
        legs,nfs,fees,meters=self.validate(packet)
        need(int.from_bytes(header[168:172],'little')==fees,'fee credit')
        # Every peer-controlled condition and all cryptographic checks precede publication.
        tree=copy(self.tree)
        tree.layers=[layer.copy() for layer in self.tree.layers]
        appended=[]
        for leg in legs:
            for i,(cm,ct) in enumerate(zip(leg['statement']['outputs'],leg['cts'],strict=True)):
                tree.append(cm); appended.append((cm,ct,i))
        credits=self.fees.copy()
        credits[header[152:168].hex()]+=fees
        state=(tree,self.history+appended,self.cms.union(pack(cm) for cm,_,_ in appended),self.spent.union(nfs),credits)
        self.tree,self.history,self.cms,self.spent,self.fees=state
        self.height+=1;self.tip=digest('N7B1/work',header)
        self.metrics.append(dict(height=self.height,legs=meters,packet_B=len(packet),block_B=len(raw),
                         elapsed_s=time.perf_counter()-start,parent_cpu_s=time.process_time()-cpu))

    def summary(self):
        return dict(height=self.height,tip=self.tip.hex(),root=pack(self.tree.root).hex(),count=self.tree.count,
                    spent=len(self.spent),spent_hash=digest('N7B1/spent',*sorted(self.spent)).hex(),miner_fees=dict(self.fees),issued=dict(self.supply))


def replay(arith,folder,limit=None):
    db=Ledger(arith,data(folder/'genesis.json'))
    for p in sorted(folder.glob('block-*.bin')):
        if limit is not None and db.height>=limit: break
        db.accept(p.read_bytes())
    return db


def main(mode):
    folder=Path('/public')
    with Arithmetic() as arith:
        db=replay(arith,folder)
        if mode=='verify':
            print(json.dumps(dict(state=db.summary(),verification=db.metrics)))
        elif mode=='mine':
            block=db.mine(Path('/item').read_bytes(),b'N7 devnet miner!')
            db.accept(block)
            sys.stdout.buffer.write(block)
        elif mode=='controls':
            before=db.summary()
            # Put each candidate through the same validator used for block acceptance.
            test=Path('/item').read_bytes()
            try: db.accept(db.mine(test,b'N7 devnet miner!'))
            except ValueError as err:
                need(before==db.summary(),'failed candidate changed state')
                print(str(err))
            else: raise ValueError('invalid transaction admitted')
        else: raise ValueError('unknown node operation')


if __name__=='__main__':
    main(sys.argv[1])
