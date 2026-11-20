"""Small public Protocol 8 round-trip. The witness is a synthetic algebra example."""
from hashlib import sha3_512, shake_256
from itertools import count
from struct import pack, unpack
from model import P, ceildiv, field_counts

N, S, L, DEG, RHO, ETA = 64, 3, 2, 7, 2, 2
D = S + L - 1
OMEGA = tuple(range(N, N+S))
PUBLIC_MATRIX = (2, 5, 11, 17, 19, 29)
CONTEXT = b"research/TCitH-MT/mini/v1\0" + bytes((N,S,L,DEG,RHO,ETA))


def words(vals):
    return b"".join(pack("<Q",x) for x in vals)


def h(tag, *fields):
    return sha3_512(CONTEXT+tag+b"".join(fields)).digest()


def draws(tag, *fields):
    seed = h(tag, *fields)
    for i in count():
        v = int.from_bytes(shake_256(seed+pack("<Q",i)).digest(8),"little")
        if v < P:
            yield v


def take(stream, n):
    return [next(stream) for _ in range(n)]


def choose(transcript):
    stream=draws(b"open", transcript)
    selected=set()
    while len(selected)<L:
        r=next(stream)
        if r < P-P%N:
            selected.add(r%N)
    return sorted(selected)


def ev(coeff,x):
    val=0
    for c in reversed(coeff):
        val=(val*x+c)%P
    return val


def interpolate(grid,vals,x):
    if x in grid:
        return vals[grid.index(x)]
    z=0
    for i,u in enumerate(grid):
        num=den=1
        for v in grid:
            if v!=u:
                num=num*(x-v)%P
                den=den*(u-v)%P
        z+=vals[i]*num*pow(den,-1,P)
    return z%P


def sample_polynomial(stream,slots):
    mask=take(stream,L)
    def eval_at(x):
        return (interpolate(OMEGA,slots,x)+vanish(x)*ev(mask,x))%P
    return eval_at


def vanish(x):
    v=1
    for z in OMEGA:
        v=v*(x-z)%P
    return v


def offsets(t):
    return [min(j*S,t-D) for j in range(ceildiv(t+1-L,S))]


OFFSET0 = offsets(DEG*D-S)
OFFSETSUM = offsets(2*S+L-2)
HINTS = len(OFFSET0)+len(OFFSETSUM)


def combine(vals,shifts,x):
    return sum(v*pow(x,o,P) for v,o in zip(vals,shifts,strict=True))%P


def party(row,x,fac):
    xx,yy=row[:2]
    out=[]
    for j,(poly,linear) in enumerate(fac):
        hint=row[2+j*HINTS:2+(j+1)*HINTS]
        b=len(OFFSET0)
        v=vanish(x)*combine(hint[:b],OFFSET0,x)
        a=(v+poly*(pow(xx,7,P)-yy))%P
        lin=interpolate(OMEGA,PUBLIC_MATRIX[:S],x)*xx+interpolate(OMEGA,PUBLIC_MATRIX[S:],x)*yy
        ap=(linear*lin+combine(hint[b:],OFFSETSUM,x))%P
        out.extend((a,ap))
    return out


def degree_check(row,gamma):
    q=row[:-ETA]
    return [(u+sum(a*b for a,b in zip(q,g,strict=True)))%P
            for u,g in zip(row[-ETA:],gamma,strict=True)]


def transcript(tag,rows):
    return h(tag,words(x for row in rows for x in row))


def siblings(indices):
    nodes={N+x for x in indices}
    while nodes!={1}:
        for k in sorted(nodes):
            if k^1 not in nodes:
                yield k^1
        nodes={k//2 for k in nodes}


def leaf(i,salt,row):
    return h(b"leaf",pack("<Q",i),salt,words(row))


def parent(i,left,right):
    return h(b"node",pack("<Q",i),left,right)


def owner(slots):
    ys=[pow(x,7,P) for x in slots]
    statement=sum(a*b for a,b in zip((*slots,*ys),PUBLIC_MATRIX,strict=True))%P
    rng=draws(b"public-synthetic-fixture",words(slots))
    fns=[sample_polynomial(rng,z) for z in (slots,ys)]
    for _ in range(RHO):
        chunks=[take(rng,D+1) for _ in range(HINTS)]
        lin=chunks[len(OFFSET0):]
        total=sum(combine([ev(c,u) for c in lin],OFFSETSUM,u) for u in OMEGA)
        lin[0][0]=(lin[0][0]-total*pow(S,-1,P))%P
        fns.extend(lambda x,c=c: ev(c,x) for c in chunks)
    for _ in range(ETA):
        c=take(rng,D+1)
        fns.append(lambda x,c=c:ev(c,x))
    rows=[[f(i) for f in fns] for i in range(N)]
    salts=[h(b"test-salt",words(slots),pack("<Q",i))[:32] for i in range(N)]
    tree={N+i:leaf(i,salts[i],row) for i,row in enumerate(rows)}
    for i in range(N-1,0,-1):
        tree[i]=parent(i,tree[2*i],tree[2*i+1])
    h1=h(b"roots",tree[1])
    prefix=words([statement])+h1
    stream=draws(b"degree",prefix)
    gamma=[take(stream,len(fns)-ETA) for _ in range(ETA)]
    xis=[degree_check(row,gamma) for row in rows]
    h2=transcript(b"xi",xis[:D+1])
    stream=draws(b"batch",prefix,h2)
    fac=[take(stream,2) for _ in range(RHO)]
    alphas=[party(row,i,fac) for i,row in enumerate(rows)]
    canonical=[[alphas[x][j] for x in range(degree(j)+1)] for j in range(2*RHO)]
    h3=transcript(b"broadcasts",canonical)
    I=choose(prefix+h2+h3)
    others=[i for i in range(N) if i not in I]
    body=b"".join(salts[i]+words(rows[i]) for i in I)
    body+=b"".join(tree[i] for i in siblings(I))
    body+=words(v for x in OMEGA for v in degree_check([f(x) for f in fns],gamma))
    for j in range(2*RHO):
        secret=OMEGA[:-1] if j%2 else ()
        for x in (*secret,*others[:degree(j)+1-S-L]):
            body+=words([party([f(x) for f in fns],x,fac)[j]])
    return statement,h1+h2+h3+body


def degree(j):
    return 2*S+L-2 if j%2 else DEG*D


def verify(statement,raw):
    """Only the statement and proof enter this function."""
    pos=0
    def read(n):
        nonlocal pos
        b=raw[pos:pos+n]
        if len(b)!=n:
            raise ValueError("truncated")
        pos+=n
        return b
    def read_words(n):
        out=unpack("<"+"Q"*n,read(8*n))
        if any(v>=P for v in out):
            raise ValueError("noncanonical field encoding")
        return list(out)
    h1,h2,h3=read(64),read(64),read(64)
    prefix=words([statement])+h1
    I=choose(prefix+h2+h3)
    others=[i for i in range(N) if i not in I]
    rows={}
    tree={}
    rowlen=2+RHO*HINTS+ETA
    for i in I:
        salt=read(32)
        rows[i]=read_words(rowlen)
        tree[N+i]=leaf(i,salt,rows[i])
    for i in siblings(I):
        tree[i]=read(64)
    for i in range(N-1,0,-1):
        if 2*i in tree and 2*i+1 in tree:
            tree[i]=parent(i,tree[2*i],tree[2*i+1])
    if h(b"roots",tree[1])!=h1:
        return False
    stream=draws(b"degree",prefix)
    gamma=[take(stream,rowlen-ETA) for _ in range(ETA)]
    axis=I+list(OMEGA)
    cols=list(zip(*([degree_check(rows[i],gamma) for i in I]+[read_words(ETA) for _ in OMEGA]),strict=True))
    xis=[[interpolate(axis,c,x) for c in cols] for x in range(D+1)]
    if transcript(b"xi",xis)!=h2:
        return False
    stream=draws(b"batch",prefix,h2)
    fac=[take(stream,2) for _ in range(RHO)]
    alphas=[party(rows[i],i,fac) for i in I]
    canon=[]
    for j in range(2*RHO):
        secret=[0]*S
        if j%2:
            secret=read_words(S-1)
            secret.append((fac[j//2][1]*statement-sum(secret))%P)
        extra=degree(j)+1-S-L
        vals=[a[j] for a in alphas]+secret+read_words(extra)
        grid=axis+others[:extra]
        canon.append([interpolate(grid,vals,x) for x in range(degree(j)+1)])
    return pos==len(raw) and transcript(b"broadcasts",canon)==h3


if __name__=="__main__":
    st,proof=owner([7,14,23])
    assert verify(st,proof)
    assert not verify(st+1,proof)
    assert not verify(st,proof+b"\0")
    assert not verify(st,proof[:-1]+bytes([proof[-1]^1]))
    try:
        verify(st,proof[:224]+words([P])+proof[232:])
    except ValueError:
        pass
    else:
        raise AssertionError("noncanonical opened field accepted")
    _,fc=field_counts(S,L,DEG,2,RHO,ETA)
    I=choose(words([st])+proof[:192])
    assert len(proof)==192+8*sum(fc.values())+32*L+64*len(list(siblings(I)))
    print("synthetic Goldilocks transcript verified; four malformed/changed inputs rejected;",len(proof),"bytes")
