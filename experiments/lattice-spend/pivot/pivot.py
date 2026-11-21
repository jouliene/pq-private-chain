"""Recompile complete funded relations with a fixed-arity, separated parent."""
import inspect
import io
from hashlib import sha256
from pathlib import Path
import struct
import sys
from types import FunctionType

HERE=Path(__file__).resolve().parent
EX=HERE.parents[1]
sys.path.insert(0,str(EX/"packed-tcith/encoding"))
import encoding as e

f=e.f
TAG=int.from_bytes(b"PQ4N/v1","little")
PUBLIC={suite:n+4 for suite,n in f.PUBLIC.items()}


class FixedParent:
    in_path=False

    def path(self,cm,note,active):
        self.in_path=True
        try:
            return super().path(cm,note,active)
        finally:
            self.in_path=False

    def sponge(self,*parts):
        if not self.in_path:
            return super().sponge(*parts)
        if len(parts)!=4 or any(len(child)!=4 for child in parts):
            raise ValueError("invalid fixed-parent arity")
        state=[f.ZERO]*12
        state[8]=f.literal(TAG)
        for a,b in (parts[:2],parts[2:]):
            state[:8]=[f.add((x,1),(y,1)) for x,y in zip(state[:8],[*a,*b],strict=True)]
            state=f.permute(self,state,self.parameters)
            self.permutations+=1
        return state[:4]


class Compact(FixedParent,e.Compact):
    pass


class Quadratic(FixedParent,e.Circuit):
    pass


def builder(cls):
    original=inspect.getsource(f.compile_relation)
    old="zip(root, header[13:17])"
    if original.count(old)!=1:
        raise RuntimeError("upstream terminal membership check changed")
    # Local checkout code only. Preserve header/anchor validation independently
    # from the appended branch-derived public root. Never load a supplied program.
    namespace=dict(f.compile_relation.__globals__,Circuit=cls,PUBLIC=PUBLIC)
    exec(compile(original.replace(old,"zip(root, pub[-4:])"),__file__,"exec"),namespace)
    return namespace["compile_relation"]


def compile_full(suite,params,private,cls=Compact,register=False):
    e.canonical(dict(private,public=private["public"][:-4]))
    out=io.BytesIO() if register else None
    c=builder(cls)(suite,params,private,out)
    if not register:
        return c
    prefix=e.COMPACT if cls.inline else e.MAGIC
    program=prefix+e.SHAPE.pack(PUBLIC[suite],len(c.z),c.rows)+out.getvalue()
    return c,program


def census(suite,c,program):
    private=len(c.z)-1-PUBLIC[suite]
    groups=[private]+[c.degrees[2]]*3+([c.degrees[7]]*2 if c.inline else [])
    return dict(serialized_shape_sha256=sha256(program).hexdigest(),public_words=PUBLIC[suite],
                rows=c.rows,private_columns=private,permutations=c.permutations,
                path_permutations=c.path_perms,seventh_powers=c.sboxes,
                rows_by_degree={str(i):c.degrees[i] for i in (1,2,7)},
                packing_groups=groups,linear_wiring_equations=c.degrees[1]+c.ports[2]+c.ports[7],
                global_matrix_private_nnz=c.private_nnz,known_rhs_affine_nnz=c.rhs_terms,
                rows_with_structural_public_or_constant_rhs=c.rhs_rows)


def bound_function(fn,overrides):
    return FunctionType(fn.__code__,dict(fn.__globals__,**overrides),fn.__name__,fn.__defaults__)


def parent(params,children):
    """Independent plain integer permutation for chain replay and wallets."""
    if len(children)!=4 or any(len(c)!=32 for c in children):
        raise ValueError("four encoded children required")
    inp=struct.unpack("<16Q",b"".join(children))
    p=f.P
    if any(x>=p for x in inp):
        raise ValueError("noncanonical child")
    init,inside,diagonal,final=params

    def external(s):
        m=((2,3,1,1),(1,2,3,1),(1,1,2,3),(3,1,1,2))
        t=[sum(a*b for a,b in zip(s[k:k+4],row)) for k in (0,4,8) for row in m]
        cols=[sum(t[j::4]) for j in range(4)]
        return [(x+cols[i%4])%p for i,x in enumerate(t)]

    def full(s,constants):
        for off in range(0,48,12):
            s=external([pow(x+a,7,p) for x,a in zip(s,constants[off:off+12])])
        return s

    state=[0]*12
    state[8]=TAG
    for off in (0,8):
        state[:8]=[(x+y)%p for x,y in zip(state[:8],inp[off:off+8])]
        state=full(external(state),init)
        for a in inside:
            state[0]=pow(state[0]+a,7,p)
            t=sum(state)
            state=[(x*d+t)%p for x,d in zip(state,diagonal)]
        state=full(state,final)
    return struct.pack("<4Q",*state[:4])


def tree(params,leaves,selected):
    if not 0<=selected<len(leaves)<=4**f.DEPTH:
        raise ValueError("funded occurrence outside capacity")
    nodes=leaves[:]
    path=[]
    positions=[]
    while True:
        up=[]
        for start in range(0,len(nodes),4):
            children=sorted((nodes[start:start+4]+[bytes(32)]*3)[:4])
            if start<=selected<start+4:
                j=children.index(nodes[selected])
                positions.append(j)
                path.append([list(struct.unpack("<4Q",v)) for i,v in enumerate(children) if i!=j])
            up.append(parent(params,children))
        if len(up)==1:
            return up[0],path,positions
        nodes=up
        selected//=4
