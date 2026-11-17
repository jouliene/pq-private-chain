#!/usr/bin/env python3
"""Independent PUBLIC CP-P2 reference. Stdlib only; no Rust/source trace imported.

Commands are not an authorized private-witness interface. Fixed synthetic values
are public test data. Execution requires root's CPU allocation in this project.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
P = 2**64 - 2**32 + 1
MAX = 1_840_960_000_000_000
V = 0x43505032
M4 = ((2,3,1,1),(1,2,3,1),(1,1,2,3),(3,1,1,2))
DIAG = (-2,1,2,pow(2,-1,P),3,4,-pow(2,-1,P),-3,-4,
        pow(8,-1,P),pow(16,-1,P),pow(32,-1,P),
        -pow(8,-1,P),-pow(16,-1,P),-pow(32,-1,P),pow(2**32,-1,P))
# Parameter data only: this reference independently implements every operation.
RC = json.loads((HERE/'data/round-constants.json').read_text())['constants']
assert len(RC) == 152 and all(0 <= x < P for x in RC)

def external(x):
    t = [sum(M4[i][j]*x[b+j] for j in range(4)) % P
         for b in range(0,16,4) for i in range(4)]
    sums = [sum(t[j::4]) % P for j in range(4)]
    return [(t[i]+sums[i%4]) % P for i in range(16)]

def permute(x):
    x = external(list(x))
    for r in range(4):
        x = external([pow((a+c)%P,7,P) for a,c in zip(x,RC[16*r:16*r+16])])
    for r in range(24):
        x[0] = pow((x[0]+RC[64+r])%P,7,P)
        s = sum(x)
        x = [(s+DIAG[i]*x[i]) % P for i in range(16)]
    for r in range(4):
        x = external([pow((a+c)%P,7,P) for a,c in zip(x,RC[88+16*r:104+16*r])])
    return x

def chunks(b):
    assert len(b) == 32
    return [int.from_bytes(b[i:i+7],'little') for i in range(0,32,7)]

def h(chain,role,payload):
    assert all(type(x) is int and 0 <= x < P for x in payload)
    words = [V,role,*chunks(chain),len(payload),*payload,1]
    words += [0]*(-len(words)%8)
    s = [0]*16
    for at in range(0,len(words),8):
        s[:8] = [(s[j]+words[at+j])%P for j in range(8)]
        s = permute(s)
    return s[:8]

def canonical_words(b):
    if len(b)%8: raise ValueError('field-vector length')
    a = [int.from_bytes(b[i:i+8],'little') for i in range(0,len(b),8)]
    if any(x >= P for x in a): raise ValueError('noncanonical field')
    return a

def pack_words(a):
    if any(type(x) is not int or not 0 <= x < P for x in a): raise ValueError('noncanonical field')
    return b''.join(x.to_bytes(8,'little') for x in a)

def parse(b):
    if len(b)!=528 or b[:16] != b'CP-P2-01'+bytes((1,0,2,2,1,0,0,0)): raise ValueError('statement grammar')
    s = dict(chain=list(b[16:48]),nonce=list(b[48:80]),
             nullifiers=[canonical_words(b[80:144]),canonical_words(b[144:208])],
             commitments=[canonical_words(b[208:272]),canonical_words(b[272:336])],
             fee=int.from_bytes(b[336:344],'little'),root=canonical_words(b[344:408]),
             count=int.from_bytes(b[408:416],'little'),credit=int.from_bytes(b[416:424],'little'),
             debit=int.from_bytes(b[424:432],'little'),receipts=[list(b[432:480]),list(b[480:528])])
    if s['fee']>MAX or not 1<=s['count']<=2**40 or s['credit'] or s['debit']: raise ValueError('statement integer bounds')
    if s['nullifiers'][0]==s['nullifiers'][1]: raise ValueError('duplicate nullifier')
    return s

def encode(s):
    return (b'CP-P2-01'+bytes((1,0,2,2,1,0,0,0))+bytes(s['chain'])+bytes(s['nonce'])+
            b''.join(pack_words(x) for x in s['nullifiers']+s['commitments'])+
            s['fee'].to_bytes(8,'little')+pack_words(s['root'])+
            b''.join(s[k].to_bytes(8,'little') for k in ('count','credit','debit'))+
            b''.join(bytes(x) for x in s['receipts']))

def projection(s):
    return chunks(bytes(s['chain']))+sum(s['nullifiers']+s['commitments'],[])+[s['fee']]+s['root']+[s['count'],s['credit'],s['debit']]

def core_origins(s):
    payload=[1,2,2]+sum(s['nullifiers']+s['commitments'],[])+[s['fee']]+chunks(bytes(s['nonce']))+[1]
    assert len(payload)==42
    core=h(bytes(s['chain']),6,payload)
    return core,[h(bytes(s['chain']),7,core+[j]) for j in range(2)]

def hashes(s,w):
    chain=bytes(s['chain']); result=[]
    for item in w['inputs']:
        note,key,origin=item['note'],item['key'],item['origin']
        owner=h(chain,1,key); cm=h(chain,2,note); nf=h(chain,3,key+origin+cm); cur=h(chain,4,origin+cm)
        result += [owner,cm,nf,cur]
        for d,sibling in enumerate(item['siblings']):
            left,right=(sibling,cur) if (item['index']>>d)&1 else (cur,sibling)
            cur=h(chain,5,[d]+left+right); result.append(cur)
    result += [h(chain,2,n) for n in w['outputs']]
    assert len(result)==90
    return result

def relation(s,w):
    # Recompute all intermediate values. Failures describe semantic equations,
    # never substitute for compiled AIR tests.
    failures=[]; hs=hashes(s,w)
    for i,item in enumerate(w['inputs']):
        at=44*i
        if item['note'][2:10]!=hs[at]: failures.append(f'authority{i}')
        if s['nullifiers'][i]!=hs[at+2]: failures.append(f'nullifier{i}')
        if s['root']!=hs[at+43]: failures.append(f'membership{i}')
        if not 0<=item['index']<s['count']<=2**40: failures.append(f'index{i}')
    for j in range(2):
        if s['commitments'][j]!=hs[88+j]: failures.append(f'output{j}')
    notes=[x['note'] for x in w['inputs']]+w['outputs']
    if any(n[0]!=0 for n in notes): failures.append('asset')
    if any(not 0<=n[1]<=MAX for n in notes) or not 0<=s['fee']<=MAX: failures.append('range')
    if notes[0][1]+notes[1][1]!=notes[2][1]+notes[3][1]+s['fee']: failures.append('balance')
    if s['credit'] or s['debit']: failures.append('issuance')
    return failures

def fixture(name,amounts,fee,same_note=False,indices=(0,1)):
    chain=bytes(range(32)); nonce=bytes(range(32,64)); keys=[[101+i*10+j for j in range(5)] for i in range(2)]
    owners=[h(chain,1,k) for k in keys]
    notes=[[0,amounts[i],*owners[i],*[301+i*10+j for j in range(5)],*[401+i*10+j for j in range(5)]] for i in range(2)]
    if same_note: notes[1]=notes[0].copy();keys[1]=keys[0].copy()
    outputs=[[0,amounts[2+j],*h(chain,1,[801+j*10+k for k in range(5)]),*[901+j*10+k for k in range(5)],*[1001+j*10+k for k in range(5)]] for j in range(2)]
    origins=[[501+i*10+j for j in range(8)] for i in range(2)]
    cms=[h(chain,2,n) for n in notes]; leaves=[h(chain,4,origins[i]+cms[i]) for i in range(2)]
    # Full depth40 sparse tree; each absent leaf is zero, not a hashed zero note.
    empty=[[0]*8]; levels=[dict(zip(indices,leaves))]
    for d in range(40):
        empty.append(h(chain,5,[d]+empty[-1]+empty[-1]))
        old=levels[-1]; parents={}
        for idx in sorted({x//2 for x in old}):
            parents[idx]=h(chain,5,[d]+old.get(2*idx,empty[d])+old.get(2*idx+1,empty[d]))
        levels.append(parents)
    inputs=[dict(note=notes[i],key=keys[i],origin=origins[i],index=indices[i],
                 siblings=[list(levels[d].get((indices[i]>>d)^1,empty[d])) for d in range(40)]) for i in range(2)]
    w=dict(inputs=inputs,outputs=outputs)
    s=dict(chain=list(chain),nonce=list(nonce),nullifiers=[h(chain,3,keys[i]+origins[i]+cms[i]) for i in range(2)],
           commitments=[h(chain,2,n) for n in outputs],fee=fee,root=levels[40][0],count=max(indices)+1,credit=0,debit=0,
           receipts=[list(bytes([41])*48),list(bytes([42])*48)])
    b=encode(s); assert parse(b)==s; assert not relation(s,w)
    core,origins_out=core_origins(s)
    return dict(name=name,statement_hex=b.hex(),witness=w,expected=dict(projection=projection(s),
                hash_outputs=hashes(s,w),core=core,output_origins=origins_out,
                statement_sha256=hashlib.sha256(b).hexdigest()))

def program_digest(height):
    # Independently expand contract01 rather than importing the Rust program.
    ops=[]
    for i in range(2):
        for role in range(1,5):
            ops += [(role,i,0,b) for b in range(2 if role==1 else 4)]
        for depth in range(40): ops += [(5,i,depth,b) for b in range(4)]
    for item in (2,3): ops += [(2,item,0,b) for b in range(4)]
    assert len(ops)==356
    rows=[]
    for row in range(height):
        p=[0]*114
        if row<len(ops):
            role,item,depth,block=ops[row]
            p[80+item]=1
            if item<2: p[84+item]=1
            p[86+4*(role-1)+block]=1
            if role==5: p[item*40+depth]=1; p[113]=depth
        for i,at in enumerate((0,2,348,352,6)):
            if row==at: p[106+i]=1
        for i,at in enumerate((10,184)):
            if row==at: p[111+i]=1
        rows.extend(p)
    return hashlib.sha256(pack_words(rows)).hexdigest()

def negative_expectations(base):
    s=parse(bytes.fromhex(base['statement_hex'])); w=base['witness']; cases=[]
    def add(name,ss,ww):
        failures=relation(ss,ww)
        assert failures, name
        canonical=json.dumps(ww,sort_keys=True,separators=(',',':')).encode()
        cases.append(dict(name=name,failures=failures,
                          input_sha256=hashlib.sha256(encode(ss)+canonical).hexdigest()))
    def refresh(ss,ww):
        chain=bytes(ss['chain'])
        ss['nullifiers']=[h(chain,3,i['key']+i['origin']+h(chain,2,i['note'])) for i in ww['inputs']]
        ss['commitments']=[h(chain,2,n) for n in ww['outputs']]
    ss,ww=copy.deepcopy(s),copy.deepcopy(w);ww['inputs'][0]['key'][0]+=1;refresh(ss,ww)
    add('wrong-authority-recomputed-NF',ss,ww)
    ss,ww=copy.deepcopy(s),copy.deepcopy(w);ww['inputs'][0]['note'][10]+=1;refresh(ss,ww)
    add('unauthorized-note-recomputed-CM-NF',ss,ww)
    ss=copy.deepcopy(s);ss['nullifiers'][0][0]=(ss['nullifiers'][0][0]+1)%P
    add('wrong-public-NF-fresh-trace',ss,w)
    ss,ww=copy.deepcopy(s),copy.deepcopy(w);ww['inputs'][0]['origin'][0]+=1;refresh(ss,ww)
    add('wrong-origin-recomputed-leaf-NF',ss,ww)
    ww=copy.deepcopy(w);ww['inputs'][0]['siblings'][17][0]=(ww['inputs'][0]['siblings'][17][0]+1)%P
    add('wrong-depth17-sibling-rehashed',s,ww)
    ww=copy.deepcopy(w);ww['inputs'][0]['index']^=1
    add('wrong-index-rehashed-path',s,ww)
    ss=copy.deepcopy(s);ss['count']=1
    add('count-prefix-excludes-input1',ss,w)
    ww=copy.deepcopy(w);ww['inputs'][0]['index']=2**40
    add('index-over-40bits',s,ww)
    ss=copy.deepcopy(s);ss['root'][0]=(ss['root'][0]+1)%P
    add('wrong-public-root',ss,w)
    ww=copy.deepcopy(w);ww['outputs'][0][2]=(ww['outputs'][0][2]+1)%P
    add('wrong-output-owner-old-CM-fresh-trace',s,ww)
    ss,ww=copy.deepcopy(s),copy.deepcopy(w);ww['outputs'][0][1]+=1;refresh(ss,ww)
    add('balance-recomputed-output-CM',ss,ww)
    ss=copy.deepcopy(s);ss['commitments'][0][0]=(ss['commitments'][0][0]+1)%P
    add('wrong-public-output-CM',ss,w)
    ss=copy.deepcopy(s);ss['fee']+=1
    add('fee-conservation',ss,w)
    for name,key in [('credit-direct-AIR','credit'),('debit-direct-AIR','debit')]:
        ss=copy.deepcopy(s);ss[key]=1;add(name,ss,w)
    return cases

def main():
    p=argparse.ArgumentParser();p.add_argument('output',type=Path);a=p.parse_args()
    if a.output.exists(): raise SystemExit('immutable output already exists')
    fixtures=[fixture('ordinary',[7,11,9,7],2),fixture('zero',[0,0,0,0],0),
              fixture('max',[MAX,MAX,MAX,MAX],0),fixture('additive-equal-commitment',[5,5,4,4],2,True),
              fixture('high-index-AIR-only-not-funding-history',[7,11,9,7],2,indices=(0,2**40-1))]
    output=dict(format='CP-P2-PUBLIC-FIXTURES-01',fixtures=fixtures,
                host_negative_expectations=negative_expectations(fixtures[0]),
                program_sha256={str(n):program_digest(n) for n in (512,1024)},
                permutation_vectors=[dict(input=x,output=permute(x)) for x in ([0]*16,list(range(16)),[P-1-i for i in range(16)])])
    a.output.write_text(json.dumps(output,sort_keys=True,indent=2)+'\n')
    print(json.dumps(dict(public_only=True,fixtures=len(fixtures),output_sha256=hashlib.sha256(a.output.read_bytes()).hexdigest())))
if __name__=='__main__':main()
