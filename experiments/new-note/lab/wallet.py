"""Single-backup N7P1 wallet. The prover receives the private assignment on a pipe."""
from itertools import combinations
from pathlib import Path
import json
import os
import resource
import struct
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import *
from state import replay


def keys(a,net):
    seed=Path('/seed').read_bytes()
    need(len(seed)==48,'expected new-format backup')
    sk=scalars(b'N7P1/spend',net,seed)
    return seed,sk,a.call('owner',sk=sk)


def accept_address(x,scope):
    need(x.get('format')=='N7A1' and x.get('scope')==scope.hex(),'foreign receiving address')
    need(len(bytes.fromhex(x['kem']))==1568 and len(pack(x['owner']))==56,'recipient address')
    return x


def output(a,net,scope,address,asset,n,t,slot,credit_index=None):
    address=accept_address(address,scope)
    nt=private_note(address['owner'],asset,n,t)
    if credit_index is not None:
        nt['salt']=credit_salt(net,credit_index)
    cm=a.call('note',note=nt)
    ct=crypto('seal',net+bytes([slot])+pack(cm)+bytes.fromhex(address['kem'])+note_bytes(nt))
    need(len(ct)==CT,'receipt width')
    return nt,cm,ct


def open_note(a,db,seed,owner,cm,ct,slot):
    raw=crypto('open',db.net+bytes([slot])+pack(cm)+db.scope+seed+ct)
    if not raw: return None
    try:
        n=decode_note(raw)
    except ValueError:
        return None
    if (n['owner']!=owner or n['native']>=2**62 or n['token']>=2**62 or bool(n['token'])!=any(n['asset'])):
        return None
    return n if a.call('note',note=n)==cm else None


def scan(a,db,seed,sk,owner):
    found=[]
    for i,(cm,ct,slot) in enumerate(db.history):
        n=open_note(a,db,seed,owner,cm,ct,slot)
        if n is not None and (n['native'] or n['token']):
            nf=a.call('nf',sk=sk,index=i,commitment=cm)
            if pack(nf) not in db.spent: found.append((i,n,nf))
    return found


def negotiation(plan):
    # Private, independently agreed slots and bounded quantities. Only the salted hash enters the leg.
    return digest('N7S1/private-agreement',json.dumps(plan,sort_keys=True,separators=(',',':')).encode())


def prepare(a,db,cfg):
    seed,sk,owner=keys(a,db.scope)
    inventory=scan(a,db,seed,sk,owner)
    k=cfg['kind']
    if k:
        agr=cfg['agreement'];side=k-1
        need(bytes.fromhex(agr['net'])==db.net and agr['expiry']>=db.height+1,'private agreement context')
        own=agr['parties'][side]
        need(own['address']['owner']==owner and own['address']['kem']==crypto('address',db.scope+seed).hex(),'agreement signer')
        other=agr['parties'][1-side]['address'];fee=3*int(agr['payer']==side)
        amount=own['native'];tokens=own['token'];asset=bytes.fromhex(own['asset'])
        key=crypto('auth-key',b'');need(len(key)==116,'owner approval key')
        (Path('/own')/'signing.der').write_bytes(key[32:])
        extras=dict(expiry=agr['expiry'],payer=agr['payer'],terms=negotiation(agr),auth=key[:32])
    else:
        amount,tokens,asset=cfg['native'],cfg['token'],bytes.fromhex(cfg['asset'])
        other=cfg['recipient'];fee=3;extras={}
    eligible=[v for v in inventory if not v[1]['token'] or struct.pack('<8I',*v[1]['asset'])==asset]
    need(type(amount) is int and type(tokens) is int and 0<=amount<2**62 and 0<=tokens<2**62
         and (amount or tokens) and len(asset)==32 and (not tokens or any(asset)), 'invalid payment request')
    eligible=next((pair for pair in combinations(eligible,2)
                   if 0<=sum(v['native'] for _,v,_ in pair)-amount-fee<2**62
                   and 0<=sum(v['token'] for _,v,_ in pair)-tokens<2**62),None)
    need(eligible is not None,'no two eligible notes cover this payment')
    ixs=[i for i,_,_ in eligible]
    native=sum(v['native'] for _,v,_ in eligible); total=sum(v['token'] for _,v,_ in eligible)
    need(native>=amount+fee and total>=tokens and (amount or tokens),'insufficient funds')
    change=(native-amount-fee,total-tokens)
    me=dict(format='N7A1',scope=db.scope.hex(),owner=owner,kem=crypto('address',db.scope+seed).hex())

    slot=0 if k else os.urandom(1)[0]%2
    outs=[None,None]
    outs[slot]=output(a,db.net,db.scope,other,asset,amount,tokens,slot)
    outs[1-slot]=output(a,db.net,db.scope,me,asset,*change,1-slot)
    nfs=[nf for _,_,nf in eligible]; cms=[v[1] for v in outs];cts=[v[2] for v in outs]
    header=context_header(db.net,k,db.tree.root,db.tree.count,fee,nfs,cms,cts,**extras)
    statement=dict(root=db.tree.root,count=db.tree.count,fee=fee,
                   nullifiers=nfs,outputs=cms,context=u32s(digest('N7P1/proof-context',db.genesis,header)))
    witness=dict(inputs=[dict(index=i,note=n,sk=sk,path=db.tree.path(i)) for i,n,_ in eligible],outputs=[v[0] for v in outs])
    proof,metric=role('prove',statement,witness=witness)
    payload=header+struct.pack('<I',len(proof))+proof
    need(parse(payload,db.genesis)['statement']==statement,'wallet statement drift')
    (Path('/own')/'offer.bin').write_bytes(payload)
    if k:
        store(Path('/own/expect.json'),dict(change=change,asset=asset.hex(),terms=negotiation(agr).hex()))
    return dict(proof=metric,proof_B=len(proof),core_B=len(payload),inputs=len(ixs),outputs=2,
                scanned_outputs=db.tree.count,restored_from_seed=True)


def authorize(a,db,agr,side):
    seed,_,owner=keys(a,db.scope)
    raws=[Path('/exchange',f'leg-{j}.bin').read_bytes() for j in (0,1)]
    stored=Path('/own/offer.bin').read_bytes()
    need(raws[side]==stored and bytes.fromhex(agr['net'])==db.net and db.height+1<=agr['expiry'],'changed own offer or expiry')
    legs=[parse(raw,db.genesis) for raw in raws]
    known=data('/own/expect.json')
    need(known['terms']==negotiation(agr).hex(),'changed private agreement')
    all_nf=[];all_cm=[]
    for j,l in enumerate(legs):
        s=l['statement']
        need(l['net']==db.net and l['kind']==j+1 and l['terms']==negotiation(agr) and
             l['payer']==agr['payer'] and l['expiry']==agr['expiry'] and s['root']==db.tree.root
             and s['count']==db.tree.count,'unmatched terms or branch')
        role('verify',s,l['proof'])
        all_nf+=list(map(pack,s['nullifiers']));all_cm+=list(map(pack,s['outputs']))
    need(legs[0]['auth']!=legs[1]['auth'] and len(set(all_nf))==len(set(all_cm))==4 and not
         db.spent.intersection(all_nf) and not db.cms.intersection(all_cm),'conflict')
    def expected(which,slot,q,value,asset):
        leg=legs[which]
        note=open_note(a,db,seed,owner,leg['statement']['outputs'][slot],leg['cts'][slot],slot)
        need(note is not None and (note['native'],note['token'])==(q,value) and
             struct.pack('<8I',*note['asset'])==(bytes.fromhex(asset) if value else ZERO),'unspendable promised output')
    give=agr['parties'][1-side];expected(1-side,0,give['native'],give['token'],give['asset'])
    expected(side,1,*known['change'],known['asset'])
    signature=crypto('sign',Path('/own/signing.der').read_bytes()+swap_digest(*raws))
    need(crypto('verify',legs[side]['auth']+swap_digest(*raws)+signature)==bytes([1]),'wrong owner key')
    Path('/own/auth.bin').write_bytes(signature)
    return dict(verified_both_proofs=True,checked_incoming_and_change=True)


def main(mode):
    cfg=json.load(sys.stdin)
    with Arithmetic() as a:
        if mode in ('init','fund'):
            net=bytes.fromhex(cfg['net']);scope=bytes.fromhex(cfg['scope']);seed,_,owner=keys(a,scope)
            address=dict(format='N7A1',scope=scope.hex(),owner=owner,kem=crypto('address',scope+seed).hex())
            if mode=='init': return address
            credits=[]
            for row in cfg['rows']:
                n,cm,ct=output(a,net,scope,address,bytes.fromhex(row['asset']),row['native'],row['token'],row['slot'],row['index'])
                credits.append(dict(owner=owner,native=n['native'],token=n['token'],asset=n['asset'],cm=cm,receipt=ct.hex()))
            return credits
        db=replay(a,Path('/public'))
        if mode=='prepare': return prepare(a,db,cfg)
        if mode=='authorize': return authorize(a,db,cfg['agreement'],cfg['side'])
        if mode=='balance':
            seed,sk,owner=keys(a,db.scope);notes=scan(a,db,seed,sk,owner)
            balances={}
            for _,n,_ in notes:
                if n['token']:
                    ai=struct.pack('<8I',*n['asset']).hex(); balances[ai]=balances.get(ai,0)+n['token']
            return dict(native=sum(n['native'] for _,n,_ in notes),assets=balances,count=len(notes))
        raise ValueError('wallet mode')


if __name__=='__main__':
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    print(json.dumps(main(sys.argv[1])))
