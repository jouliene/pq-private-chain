#!/usr/bin/env python3
"""Independent PUBLIC arity reference. No Rust trace/generator or proof imported.

Reuses the already independent frozen Python permutation/hash arithmetic and
parameter data, not Rust. New statement/schedule/value/credit logic is below.
Execution is CPU-bound and requires root allocation; import is not a private API.
"""
import argparse,copy,hashlib,importlib.util,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
p=HERE.parent/'compact-payment-v1/reference.py'
spec=importlib.util.spec_from_file_location('independent_p2_hash_reference',p)
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
P,MAX,h,pack=base.P,base.MAX,base.h,base.pack_words

def encode(s):
    n=len(s['nullifiers']);kind=3 if n==0 else 1
    return (b'CP-P2-03'+bytes((3,0,n,2,kind,0,0,0))+bytes(s['chain'])+bytes(s['nonce'])+
        b''.join(pack(d) for d in s['nullifiers']+s['commitments'])+s['fee'].to_bytes(8,'little')+pack(s['root'])+
        b''.join(s[k].to_bytes(8,'little') for k in ('count','credit','debit'))+
        b''.join(bytes(x) for x in s['receipts'])+(bytes(s['source_id']) if n==0 else b''))

def parse(b):
    if len(b)<16 or b[:8]!=b'CP-P2-03' or b[8:10]!=b'\3\0' or b[11]!=2 or b[13:16]!=bytes(3):raise ValueError('header')
    n=b[10]
    if n not in (0,1,2) or len(b)!=(448,464,528)[n] or b[12]!=(3 if n==0 else 1):raise ValueError('kind/arity/length')
    at=80;nf=[]
    for _ in range(n):nf.append(base.canonical_words(b[at:at+64]));at+=64
    cm=[base.canonical_words(b[at:at+64]),base.canonical_words(b[at+64:at+128])];at+=128
    fee=int.from_bytes(b[at:at+8],'little');at+=8;root=base.canonical_words(b[at:at+64]);at+=64
    count,credit,debit=[int.from_bytes(b[at+8*i:at+8*i+8],'little') for i in range(3)];at+=24
    receipts=[list(b[at:at+48]),list(b[at+48:at+96])];at+=96
    if fee>MAX or debit or count>2**40:raise ValueError('fee/debit/count')
    if n==0 and not 1<=credit<=MAX:raise ValueError('credit bound')
    if n and (credit or count==0):raise ValueError('transfer issuance/count')
    if n==2 and nf[0]==nf[1]:raise ValueError('duplicate NF')
    return dict(chain=list(b[16:48]),nonce=list(b[48:80]),nullifiers=nf,commitments=cm,fee=fee,root=root,
        count=count,credit=credit,debit=debit,receipts=receipts,source_id=list(b[at:at+48]) if n==0 else None)

def projection(s):return base.chunks(bytes(s['chain']))+sum(s['nullifiers']+s['commitments'],[])+[s['fee']]+s['root']+[s[k] for k in ('count','credit','debit')]
def core_origins(s):
    n=len(s['nullifiers']);payload=[3 if n==0 else 1,n,2]+sum(s['nullifiers']+s['commitments'],[])+[s['fee']]+base.chunks(bytes(s['nonce']))+[1]
    if n==0:payload += [int.from_bytes(bytes(s['source_id'])[i:i+7],'little') for i in range(0,48,7)]+[s['credit']]
    assert len(payload)==(34,34,42)[n]
    core=h(bytes(s['chain']),6,payload);return core,[h(bytes(s['chain']),7,core+[j]) for j in range(2)]

def hashes(s,w):
    chain=bytes(s['chain']);result=[]
    for i in w['inputs']:
        owner=h(chain,1,i['key']);cm=h(chain,2,i['note']);nf=h(chain,3,i['key']+i['origin']+cm);cur=h(chain,4,i['origin']+cm)
        result += [owner,cm,nf,cur]
        for d,sib in enumerate(i['siblings']):
            left,right=(sib,cur) if (i['index']>>d)&1 else (cur,sib)
            cur=h(chain,5,[d]+left+right);result.append(cur)
    result += [h(chain,2,n) for n in w['outputs']]
    assert len(result)==44*len(w['inputs'])+2;return result

def relation(s,w):
    n=len(s['nullifiers']);fail=[]
    if len(w['inputs'])!=n:return ['witness arity']
    hs=hashes(s,w)
    for i,item in enumerate(w['inputs']):
        if item['note'][2:10]!=hs[44*i]:fail.append('authority'+str(i))
        if s['nullifiers'][i]!=hs[44*i+2]:fail.append('NF'+str(i))
        if s['root']!=hs[44*i+43]:fail.append('membership'+str(i))
        if not 0<=item['index']<s['count']<=2**40:fail.append('index/count'+str(i))
    for j in range(2):
        if s['commitments'][j]!=hs[44*n+j]:fail.append('output CM'+str(j))
    notes=[i['note'] for i in w['inputs']]+w['outputs']
    if any(x[0] for x in notes):fail.append('asset')
    if any(not 0<=x[1]<=MAX for x in notes) or not 0<=s['fee']<=MAX:fail.append('range')
    if s['debit'] or (n and s['credit']) or (not n and not 1<=s['credit']<=MAX):fail.append('credit/debit')
    if sum(i['note'][1] for i in w['inputs'])+s['credit']!=sum(o[1] for o in w['outputs'])+s['fee']:fail.append('integer balance')
    return fail

def note(chain,amount,key,tag):return [0,amount,*h(chain,1,key),*[tag+j for j in range(5)],*[tag+100+j for j in range(5)]]
def tree(chain,leaves,indices):
    assert len(leaves)==len(indices) and len(set(indices))==len(indices)
    empty=[[0]*8];levels=[dict(zip(indices,leaves))]
    for d in range(40):
        empty.append(h(chain,5,[d]+empty[-1]+empty[-1]));prev=levels[-1]
        levels.append({x:h(chain,5,[d]+prev.get(2*x,empty[d])+prev.get(2*x+1,empty[d])) for x in sorted({i//2 for i in prev})})
    return levels[40].get(0,empty[40]),[[list(levels[d].get((idx>>d)^1,empty[d])) for d in range(40)] for idx in indices]
def refresh(s,w):
    chain=bytes(s['chain']);s['nullifiers']=[h(chain,3,i['key']+i['origin']+h(chain,2,i['note'])) for i in w['inputs']]
    s['commitments']=[h(chain,2,o) for o in w['outputs']]
def reanchor(s,w):
    chain=bytes(s['chain']);leaves=[h(chain,4,i['origin']+h(chain,2,i['note'])) for i in w['inputs']]
    s['root'],paths=tree(chain,leaves,[i['index'] for i in w['inputs']])
    for i,path in zip(w['inputs'],paths):i['siblings']=path

def payment(name,inputs,out_amounts,fee,credit=0,source=None,nonce_tag=0,indices=None):
    chain=bytes(range(32));n=len(inputs);keys=[[801+nonce_tag*100+j*10+k for k in range(5)] for j in range(2)]
    outputs=[note(chain,out_amounts[j],keys[j],901+nonce_tag*100+j*10) for j in range(2)]
    ii=[]
    for j,(nn,key,origin) in enumerate(inputs):ii.append(dict(note=list(nn),key=list(key),origin=list(origin),index=(indices or list(range(n)))[j],siblings=[]))
    w=dict(inputs=ii,outputs=outputs)
    s=dict(chain=list(chain),nonce=[(32+k+nonce_tag)%256 for k in range(32)],nullifiers=[],commitments=[],fee=fee,root=[0]*8,
        count=max((x['index'] for x in ii),default=-1)+1,credit=credit,debit=0,
        receipts=[[41+nonce_tag]*48,[42+nonce_tag]*48],source_id=list(source) if n==0 else None)
    refresh(s,w);reanchor(s,w);assert parse(encode(s))==s;assert not relation(s,w)
    return dict(name=name,s=s,w=w,output_keys=keys)
def expected(s,w):
    core,origins=core_origins(s);return dict(projection=projection(s),hash_outputs=hashes(s,w),core=core,output_origins=origins,statement_sha256=hashlib.sha256(encode(s)).hexdigest())
def case(name,s,w,accept,base_s=None,patch=None):
    failures=relation(s,w)
    assert bool(failures)!=accept,(name,failures)
    return dict(name=name,statement_hex=encode(s).hex(),base_statement_hex=encode({**s,**{k:base_s[k] for k in (patch or {})}} if base_s is not None else s).hex(),public_patch=patch or {},witness=w,expected_accept=accept,failures=failures,expected=expected(s,w))

def schedule(n):
    ops=[]
    for item in range(n):
        for role in range(1,5):ops += [(role,item,0,b) for b in range(2 if role==1 else 4)]
        for d in range(40):ops += [(5,item,d,b) for b in range(4)]
    for item in (2,3):ops += [(2,item,0,b) for b in range(4)]
    assert len(ops)==174*n+8;return ops
def program(n):
    ops=schedule(n);rows=[];real=len(ops)
    for row in range(512):
        p=[0]*114
        if row<real:
            role,item,d,b=ops[row];p[80+item]=1
            if item<2:p[84+item]=1
            p[86+4*(role-1)+b]=1
            if role==5:p[d]=1;p[113]=d
        ie=row in [174*i+173 for i in range(n)];oe=row in (174*n+3,174*n+7)
        if not ie and not oe:p[40]=1
        if row in [174*i for i in range(n)]:p[41]=p[42]=1
        if row in (174*n,174*n+4):p[42]=p[43]=1
        if row==real:p[44]=1
        if ie:p[45]=1
        if oe:p[45]=P-1
        if row==real-1:p[46]=1
        for i in range(n):
            if row==174*i:p[106+i]=1
            if row==174*i+10:p[111+i]=1
        for j in range(2):
            if row==174*n+4*j:p[108+j]=1
        if row==(8 if n==0 else 6):p[110]=1
        if n==0 and row==9:p[47]=1
        if n==0 and row==10:p[48]=1
        assert sum(p[106:113])+p[47]+p[48]<=1
        rows.extend(p)
    raw=pack(rows);identity=b'PQPC/CP-P2-03/TRUSTED-PROGRAM\0'+bytes([n])+(512).to_bytes(8,'little')+raw
    return dict(preprocessing_sha256=hashlib.sha256(raw).hexdigest(),program_sha256=hashlib.sha256(identity).hexdigest(),real_rows=real)

def make_cases(payments):
    cases=[]
    for payment_ in payments:
        s,w=payment_['s'],payment_['w'];n=len(w['inputs']);prefix=str(n)+'x2/'
        cases.append(case(prefix+payment_['name'],s,w,True))
    # Rebuilt malicious contexts use all derived hashes, not stale trace cells.
    for payment_ in payments[:3]:
        s,w=payment_['s'],payment_['w'];n=len(w['inputs']);prefix=str(n)+'x2/'
        def altered(name,mutate,anchor=False,refresh_hash=True,accept=False):
            ss,ww=copy.deepcopy(s),copy.deepcopy(w);mutate(ss,ww)
            if refresh_hash:refresh(ss,ww)
            if anchor:reanchor(ss,ww)
            cases.append(case(prefix+name,ss,ww,accept))
        altered('output-amount-rehashed-conservation',lambda ss,ww:ww['outputs'][0].__setitem__(1,ww['outputs'][0][1]+1))
        altered('output-asset-rehashed',lambda ss,ww:ww['outputs'][0].__setitem__(0,1))
        altered('arbitrary-output-owner-rehashed-allowed',lambda ss,ww:ww['outputs'][0].__setitem__(2,(ww['outputs'][0][2]+1)%P),accept=True)
        altered('wrong-public-output-CM',lambda ss,ww:ss['commitments'][0].__setitem__(0,(ss['commitments'][0][0]+1)%P),refresh_hash=False)
        ss=copy.deepcopy(s);ss['fee']+=1;cases.append(case(prefix+'fee-conservation',ss,w,False))
        for field,value in [('debit',1),('fee',MAX+1),('credit',0 if n==0 else 1)]:
            ss=copy.deepcopy(s);ss[field]=value;cases.append(case(prefix+'direct-AIR-'+field,ss,w,False,base_s=s,patch={field:value}))
        if n==0:
            ss=copy.deepcopy(s);ww=copy.deepcopy(w);ss['credit']=0;ww['outputs'][0][1]=ww['outputs'][1][1]=ss['fee']=0;refresh(ss,ww)
            cases.append(case(prefix+'zero-credit-exact-balance-still-reject',ss,ww,False,base_s=s,patch={'credit':0,'fee':0}))
            ss=copy.deepcopy(s);ss['source_id'][0]^=1
            # Source is public host/core context. AIR MUST NOT be credited as its authorization check.
            cases.append(case(prefix+'source-change-AIR-accept-host-core-diff',ss,w,True))
            ss=copy.deepcopy(s);ww=copy.deepcopy(w);ss['credit']=MAX+1;ss['fee']=0
            ww['outputs'][0][1]=MAX;ww['outputs'][1][1]=1;refresh(ss,ww)
            cases.append(case(prefix+'credit-MAX-plus1-exact-balance',ss,ww,False,base_s=s,patch={'credit':MAX+1}))
        else:
            ss,ww=copy.deepcopy(s),copy.deepcopy(w);ss['credit']=1;ww['outputs'][0][1]+=1;refresh(ss,ww)
            cases.append(case(prefix+'forged-credit-coherent-balance',ss,ww,False,base_s=s,patch={'credit':1}))
            altered('wrong-authority-recomputed-NF',lambda ss,ww:ww['inputs'][0]['key'].__setitem__(0,ww['inputs'][0]['key'][0]+1),anchor=True)
            altered('wrong-note-rebuilt-membership',lambda ss,ww:ww['inputs'][0]['note'].__setitem__(10,ww['inputs'][0]['note'][10]+1),anchor=False)
            altered('wrong-NF',lambda ss,ww:ss['nullifiers'][0].__setitem__(0,(ss['nullifiers'][0][0]+1)%P),refresh_hash=False)
            altered('wrong-depth17-path-rehashed',lambda ss,ww:ww['inputs'][0]['siblings'][17].__setitem__(0,(ww['inputs'][0]['siblings'][17][0]+1)%P),refresh_hash=False)
            altered('wrong-index-rehashed',lambda ss,ww:ww['inputs'][0].__setitem__('index',ww['inputs'][0]['index']^1),refresh_hash=False)
            altered('index-outside-count-reanchored',lambda ss,ww:ww['inputs'][0].__setitem__('index',ss['count']),anchor=True)
            altered('index-over40-reanchored',lambda ss,ww:ww['inputs'][0].__setitem__('index',2**40),anchor=True)
            altered('input-asset-rebuilt-path',lambda ss,ww:ww['inputs'][0]['note'].__setitem__(0,1),anchor=True)
            if n==2:
                altered('input1-asset-rebuilt-path',lambda ss,ww:ww['inputs'][1]['note'].__setitem__(0,1),anchor=True)
                ss,ww=copy.deepcopy(s),copy.deepcopy(w);ww['inputs'][0]['note'][1]=0;ww['inputs'][1]['note'][1]=MAX+1
                ww['outputs'][0][1]=MAX;ww['outputs'][1][1]=1;ss['fee']=0;refresh(ss,ww);reanchor(ss,ww)
                cases.append(case(prefix+'input1-MAX-plus1-exact-balance',ss,ww,False))
                ss=copy.deepcopy(s);ss['count']=1;cases.append(case(prefix+'count-prefix-excludes-input1',ss,w,False))
                ss,ww=copy.deepcopy(s),copy.deepcopy(w)
                ww['inputs'][0]['note'][1]=MAX;ww['inputs'][1]['note'][1]=MAX
                ww['outputs'][0][1]=MAX-1;ww['outputs'][1][1]=0;ss['fee']=MAX+1
                refresh(ss,ww);reanchor(ss,ww)
                cases.append(case(prefix+'fee-MAX-plus1-exact-balance',ss,ww,False,base_s=s,patch={'fee':MAX+1}))
            # Exact integer mismatch, yet ZERO field balance: never just a stale trace.
            ss,ww=copy.deepcopy(s),copy.deepcopy(w);ss['fee']=0
            if n==2:
                ww['inputs'][0]['note'][1]=P-1;ww['inputs'][1]['note'][1]=1
                ww['outputs'][0][1]=ww['outputs'][1][1]=0
            else:
                ww['inputs'][0]['note'][1]=0
                ww['outputs'][0][1]=P-1;ww['outputs'][1][1]=1
            assert (sum(i['note'][1] for i in ww['inputs'])-sum(o[1] for o in ww['outputs']))%P==0
            refresh(ss,ww);reanchor(ss,ww)
            cases.append(case(prefix+'modular-only-balance-range-reject',ss,ww,False))
    return cases

def parser_cases(statements):
    out=[]
    for s in statements:
        n=len(s['nullifiers']);b=encode(s)
        def add(name,data):
            try:parse(data)
            except ValueError:out.append(dict(name=str(n)+'x2/'+name,bytes_hex=data.hex()));return
            raise AssertionError('parser must reject '+name)
        add('suffix',b+b'\0');add('truncated',b[:-1])
        for at in (0,8,10,11,12,13):
            d=bytearray(b);d[at]^=1;add('header-'+str(at),d)
        d=bytearray(b);cm=80+64*n;d[cm:cm+8]=P.to_bytes(8,'little');add('noncanonical-CM',d)
        offsets={'fee':80+64*n+128,'count':80+64*n+128+8+64,'credit':80+64*n+128+8+64+8,'debit':80+64*n+128+8+64+16}
        for field,value in [('fee',MAX+1),('count',2**40+1),('debit',1),('credit',0 if n==0 else 1)]:
            d=bytearray(b);at=offsets[field];d[at:at+8]=value.to_bytes(8,'little');add('invalid-'+field,d)
        if n:
            d=bytearray(b);at=offsets['count'];d[at:at+8]=bytes(8);add('zero-count',d)
        if n==0:add('missing-source',b[:-48])
        else:add('extra-source',b+bytes(48))
        if n==2:
            d=bytearray(b);d[144:208]=d[80:144];add('duplicate-NF',d)
    return out

def main():
    p=argparse.ArgumentParser();p.add_argument('output',type=Path);a=p.parse_args()
    if a.output.exists():raise SystemExit('immutable fixture label')
    credit=payment('credit-distribution-registry-unverified',[],[12,6],2,20,bytes(range(48)),1)
    c_core,c_origins=core_origins(credit['s'])
    one=payment('spend-actual-credit-output',[(credit['w']['outputs'][0],credit['output_keys'][0],c_origins[0])],[7,3],2,nonce_tag=2)
    _,o_origins=core_origins(one['s'])
    two=payment('spend-credit-and-transfer-output',[(credit['w']['outputs'][1],credit['output_keys'][1],c_origins[1]),(one['w']['outputs'][0],one['output_keys'][0],o_origins[0])],[8,3],2,nonce_tag=3)
    zero_credit=payment('positive-credit-two-zero-outputs',[],[0,0],1,1,bytes([99])*48,4)
    max_credit=payment('MAX-credit',[],[MAX,0],0,MAX,bytes([98])*48,5)
    _,zc_origins=core_origins(zero_credit['s'])
    zero_one=payment('zero-valued-real-input',[(zero_credit['w']['outputs'][0],zero_credit['output_keys'][0],zc_origins[0])],[0,0],0,nonce_tag=6)
    high=payment('high-index-AIR-only-not-history',[(credit['w']['outputs'][0],credit['output_keys'][0],c_origins[0])],[7,3],2,nonce_tag=7,indices=[2**40-1])
    # The retained old independent 2x2 fixture supplies the exact differential predicate case.
    legacy=base.fixture('legacy-two-differential',[7,11,9,7],2)
    legacy_s=base.parse(bytes.fromhex(legacy['statement_hex']));legacy_s['source_id']=None
    diff=dict(name='legacy-two-differential',s=legacy_s,w=legacy['witness'],output_keys=[])
    assert core_origins(legacy_s)==base.core_origins({k:v for k,v in legacy_s.items() if k!='source_id'})
    _,mc_origins=core_origins(max_credit['s'])
    max_one=payment('MAX-input-from-credit',[(max_credit['w']['outputs'][0],max_credit['output_keys'][0],mc_origins[0])],[MAX,0],0,nonce_tag=8)
    oldmax=base.fixture('MAX-two',[MAX,MAX,MAX,MAX],0);oldmax_s=base.parse(bytes.fromhex(oldmax['statement_hex']));oldmax_s['source_id']=None
    maxtwo=dict(name='MAX-two',s=oldmax_s,w=oldmax['witness'],output_keys=[])
    payments=[credit,one,two,zero_credit,max_credit,zero_one,high,diff,max_one,maxtwo]
    output=dict(format='CP-P2-03-PUBLIC-ARITY-FIXTURES',programs={str(n):program(n) for n in (0,1,2)},cases=make_cases(payments),
        legacy_differential_statement_hex=legacy['statement_hex'],legacy_differential_witness=legacy['witness'],
        linkage=dict(credit_core=c_core,credit_output_origins=c_origins,transfer_output_origins=o_origins),
        parser_cases=parser_cases([credit['s'],one['s'],two['s']]),primitive_security_claim=False,source_signature_verified=False)
    a.output.write_text(json.dumps(output,sort_keys=True,indent=2)+'\n')
    print(json.dumps(dict(public_only=True,cases=len(output['cases']),sha256=hashlib.sha256(a.output.read_bytes()).hexdigest())))
if __name__=='__main__':main()
