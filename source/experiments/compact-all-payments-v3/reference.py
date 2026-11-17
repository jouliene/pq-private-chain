#!/usr/bin/env python3
"""Independent PUBLIC linked payment generator and frame03 byte decoder.

Imports the frozen independent Python arity/hash arithmetic, never Rust. Hashing
three depth40 trees is a CPU job; main requires root's allocation. No private API.
"""
import argparse, hashlib, importlib.util, json
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
spec=importlib.util.spec_from_file_location('arity03_independent',HERE.parent/'compact-arities-v3/reference.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
P=r.P
FEES=(2116775,2112174,2112248)
QUALIFICATION='PUBLIC synthetic prefix history; source authorization, receipt encryption and canonical admission unverified'
TAG=b'PQPC/CP-FRI/03/FRAME'
CONTEXT=hashlib.sha3_512(b'PQPC/CP-P2-03/RESEARCH-PAYMENT').digest()

def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode()
def linked():
    # Fixed reservation tariff, not actual-proof-size fees. All synthetic secrets
    # below are deliberately PUBLIC controls; source entitlement is not asserted.
    credit=r.payment('linked-0x2',[],[50000000,47883225],FEES[0],credit=100000000,source=bytes(range(48)),nonce_tag=1)
    _,orig0=r.core_origins(credit['s'])
    one=r.payment('linked-1x2',[(credit['w']['outputs'][0],credit['output_keys'][0],orig0[0])],[30000000,17887826],FEES[1],nonce_tag=2)
    # Retain the entire two-leaf funded credit prefix in the synthetic anchor,
    # including the sibling note not consumed by this transfer.
    chain=bytes(credit['s']['chain'])
    leaves0=[r.h(chain,4,orig0[j]+credit['s']['commitments'][j]) for j in range(2)]
    root,paths=r.tree(chain,leaves0,[0,1]);one['s']['root']=root;one['s']['count']=2;one['w']['inputs'][0]['siblings']=paths[0]
    _,orig1=r.core_origins(one['s'])
    two=r.payment('linked-2x2',[(credit['w']['outputs'][1],credit['output_keys'][1],orig0[1]),(one['w']['outputs'][0],one['output_keys'][0],orig1[0])],[40000000,35770977],FEES[2],nonce_tag=3,indices=[1,2])
    leaves1=leaves0+[r.h(chain,4,orig1[j]+one['s']['commitments'][j]) for j in range(2)]
    root,paths=r.tree(chain,leaves1,[0,1,2,3]);two['s']['root']=root;two['s']['count']=4
    two['w']['inputs'][0]['siblings']=paths[1];two['w']['inputs'][1]['siblings']=paths[2]
    payments=[credit,one,two];fixtures=[];checks=[]
    for n,p in enumerate(payments):
        s,w=p['s'],p['w'];encoded=r.encode(s)
        assert r.parse(encoded)==s and not r.relation(s,w)
        assert s['fee']==FEES[n] and len(encoded)==(448,464,528)[n]
        assert len(r.projection(s))==(33,41,49)[n]
        fixtures.append(dict(arity=n,name=f'linked-{n}x2',statement_hex=encoded.hex(),witness=w))
        core,orig=r.core_origins(s)
        checks.append(dict(arity=n,statement_sha256=hashlib.sha256(encoded).hexdigest(),public_values=r.projection(s),core=core,output_origins=orig,fee=s['fee'],credit=s['credit'],input_indices=[i['index'] for i in w['inputs']],count=s['count']))
    return dict(format='CP-ALL-PUBLIC-LINKED-03',qualification=QUALIFICATION,fixtures=fixtures),checks

def frame(ids,statement):
    s=r.parse(statement);values=r.projection(s)
    assert len(values)==33+8*len(s['nullifiers']) and all(0<=x<P for x in values)
    return (len(TAG).to_bytes(2,'little')+TAG+b'\3\0'+b''.join(bytes.fromhex(ids[k]) for k in ('profile','program'))+CONTEXT+
        b''.join(bytes.fromhex(ids[k]) for k in ('preprocessing','preprocessing_commitment'))+
        len(statement).to_bytes(4,'little')+statement+len(values).to_bytes(4,'little')+b''.join(x.to_bytes(8,'little') for x in values))

def decode_frame(data):
    at=0
    def take(n):
        nonlocal at
        if n<0 or at+n>len(data):raise ValueError('truncated frame')
        out=data[at:at+n];at+=n;return out
    if take(int.from_bytes(take(2),'little'))!=TAG or take(2)!=b'\3\0':raise ValueError('frame tag/version')
    ids={k:take(64).hex() for k in ('profile','program','context','preprocessing','preprocessing_commitment')}
    if ids.pop('context')!=CONTEXT.hex():raise ValueError('context')
    statement=take(int.from_bytes(take(4),'little'))
    s=r.parse(statement);count=int.from_bytes(take(4),'little')
    if count!=33+8*len(s['nullifiers']):raise ValueError('projection count')
    values=[int.from_bytes(take(8),'little') for _ in range(count)]
    if at!=len(data) or values!=r.projection(s) or any(x>=P for x in values):raise ValueError('projection/trailing')
    if frame(ids,statement)!=data:raise ValueError('noncanonical frame')
    return dict(ids=ids,arity=len(s['nullifiers']),statement_sha256=hashlib.sha256(statement).hexdigest(),frame_sha3_512=hashlib.sha3_512(data).hexdigest(),public_count=count)

def decode_envelope(data,ids,statement):
    # Structural reference only. Authentication and actual inner decode are Rust
    # production operations. This is never a verifier or acceptance substitute.
    if not 206<=len(data)<=2097152 or data[:10]!=b'CPFRI003\3\0':raise ValueError('envelope limit/version')
    f=frame(ids,statement)
    if data[10:74]!=bytes.fromhex(ids['profile']) or data[74:138]!=bytes.fromhex(ids['program']) or data[138:202]!=hashlib.sha3_512(f).digest():raise ValueError('identity')
    size=int.from_bytes(data[202:206],'little')
    if size>8388608 or size+206!=len(data):raise ValueError('payload length')
    return dict(envelope_bytes=len(data),payload_bytes=size,frame=decode_frame(f),inner_payload_sha256=hashlib.sha256(data[206:]).hexdigest(),cryptographic_verification=False)

def bounded(path,limit):
    if path.is_symlink() or not path.is_file() or path.stat().st_size>limit:raise ValueError('bounded regular public file')
    with path.open('rb') as f:data=f.read(limit+1)
    if len(data)>limit:raise ValueError('file cap')
    return data

def main():
    ap=argparse.ArgumentParser();group=ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--out',type=Path);group.add_argument('--decode-public',type=Path);args=ap.parse_args()
    if args.decode_public is not None:
        d=args.decode_public;manifest=json.loads(bounded(d/'manifest.json',1000000));ids=manifest['prepared']
        print(json.dumps(decode_envelope(bounded(d/'proof.bin',2097152),ids,bounded(d/'statement.bin',528)),sort_keys=True));return
    bundle,checks=linked();data=canonical(bundle)
    args.out.mkdir(parents=True,exist_ok=False)
    (args.out/'fixtures.json').write_bytes(data)
    (args.out/'checks.json').write_bytes(canonical(dict(qualification=QUALIFICATION,checks=checks)))
    pin=dict(format=bundle['format'],sha256=hashlib.sha256(data).hexdigest())
    (args.out/'fixture-pins.json').write_bytes(canonical(pin))
    print(json.dumps(dict(fixture_sha256=pin['sha256'],payments=3,fees=FEES,statement_lengths=[448,464,528],public_counts=[33,41,49],qualification=QUALIFICATION),sort_keys=True))
if __name__=='__main__':main()
