"""Mixed-field Compiler 1: DECS base-field columns and extension-field sum-check/LCS."""
import os
import numpy as np
import sw_wide
from commitment import Profile, derive_leaf, merkle, node
from field import WIDE, mul, xor
from transcript import hash_bytes
from wide import interpolation_batch
from subfield import (BETA, EMBED, F, fbasis, fencode, feval, finv, fmul, fpowers, frandom,
                      freduce, join, split)

if not WIDE:
    raise ValueError("mixed backend requires the wide challenge field")

PROFILE = Profile(pack=112,opens=88,leaves=2048,decs_rows=75,salt_bytes=32,hash_bytes=64)
PROFILE_ID = b"FS01-C1-MIX16x256-S112-T88-N2048-ETA75-v1"


def ff_message(tr,label,n,values=None):
    return np.frombuffer(tr.message(label,2*n,fencode(values) if values is not None else None),F)


def ff_challenge(tr,label,n):
    # Draw the matrix natively over F. Take the first n 16-bit coordinates of a uniform byte string.
    # Every emitted block and its length are transcript-bound; unused final bytes are discarded.
    wide = tr.challenge(label,(n+15)//16)
    return np.frombuffer(b"".join(x.to_bytes(32,"little") for x in wide),F,count=n)


def packed_length(width,tlen):
    return width+16*tlen


def pack_secret(w,masks):
    return np.concatenate((np.asarray(w,F),np.asarray([split(x) for x in masks],F).ravel()))


def pack_coeff(coef,width):
    # Trace coordinates t_j=sum beta_i*t_ji lie in K; w coordinates already lie in F.
    t = mul(coef[width:,None],np.asarray(BETA,dtype=object))
    return np.concatenate((coef[:width],t.ravel()))


class MixedCommitment:
    def __init__(self,tr,length,wt=None,*,profile=PROFILE, early_degree=False):
        self.early_degree = early_degree
        p = self.profile = profile
        self.n = n = (length+p.pack-1)//p.pack
        d = len(p.points)
        if tr.producing:
            table = frandom((n,d))
            table[:,:p.pack] = np.pad(wt,(0,n*p.pack-length)).reshape(n,p.pack)
            # Sample the 16 components of an extension mask jointly under sum_Omega M=0.
            coeff = frandom((16,len(p.qpoints)))
            functional = freduce(np.array([fpowers(len(p.qpoints),x) for x in p.omega]),axis=0)
            pivot = np.flatnonzero(functional)[0]
            coeff[:,pivot] ^= fmul(freduce(fmul(coeff,functional),axis=1),finv(functional[pivot]))
            lo,hi = coeff[:,:d].copy(),coeff[:,p.pack:].copy()
            overlap = frandom((16,d-p.pack))
            lo[:,p.pack:] = overlap
            hi[:,:d-p.pack] ^= overlap
            mask_chunks = np.vstack((lo,hi))
            mask_evals = np.array([freduce(fmul(mask_chunks,fpowers(d,x)),axis=1) for x in p.points]).T
            self.samples = np.vstack((table,mask_evals,frandom((p.decs_rows,d))))
            self.columns = [feval(self.samples,p.points,p.evaluation(i)) for i in range(p.leaves)]
            self.salts = [os.urandom(p.salt_bytes) for _ in range(p.leaves)]
            self.tree = merkle([derive_leaf(i,fencode(col),s,p.hash_bytes)
                                for i,(col,s) in enumerate(zip(self.columns,self.salts))])
        self.root = tr.message(b"mixed DECS root",p.hash_bytes,self.tree[-1][0] if tr.producing else None)
        self.gamma = ff_challenge(tr,b"mixed degree matrix",p.decs_rows*(n+32)).reshape(p.decs_rows,n+32)
        if tr.producing:
            self.rsamples = np.array([row ^ freduce(fmul(self.samples[:n+32],g[:,None]),axis=0)
                                      for row,g in zip(self.samples[n+32:],self.gamma)])
        if early_degree:
            data = self.rsamples.ravel() if tr.producing else None
            self.rsamples = ff_message(tr, b"explicit degree table v1",
                                       p.decs_rows*d, data).reshape(p.decs_rows, d)
        else:
            digest = hash_bytes(b"mixed R",fencode(self.rsamples)).digest(p.hash_bytes) if tr.producing else None
            self.digest = tr.message(b"mixed degree digest",p.hash_bytes,digest)

    def open(self,tr,coef,target,*,invalid_calibration=False):
        p,n = self.profile,self.n
        weights = np.pad(coef,(0,n*p.pack-len(coef))).reshape(n,p.pack)
        def weights_at(xs):
            # A has coefficients in K; interpolate at embedded points in F, using F Lagrange weights.
            return interpolation_batch(weights, np.asarray([EMBED[fbasis(p.omega,x)] for x in xs]))
        def qvalue(x,col,alpha):
            m = join(col[n:n+16]) ^ sw_wide.mul(EMBED[fpowers(p.pack+1,x)[-1]],join(col[n+16:n+32]))
            return m ^ xor(mul(alpha,EMBED[col[:n]]))
        if tr.producing:
            av = weights_at(p.qpoints)
            q = [qvalue(x,feval(self.samples,p.points,x),av[x]) for x in p.qpoints]
        q = tr.fields(b"mixed Q",len(p.qpoints),q if tr.producing else None)
        if xor(q[:p.pack])!=target and not (tr.producing and invalid_calibration):
            raise ValueError("mixed linear constraints rejected")
        indices = []
        while len(indices)<p.opens:
            for value in ff_challenge(tr,b"mixed opening indices",p.opens):
                idx = int(value)%p.leaves
                if idx not in indices:
                    indices.append(idx)
                    if len(indices)==p.opens:
                        break
        indices.sort()
        xs = [p.evaluation(i) for i in indices]
        av = weights_at(xs)
        r_open = []
        for j,(i,x) in enumerate(zip(indices,xs)):
            col = ff_message(tr,b"mixed open column",n+32+p.decs_rows,
                             self.columns[i] if tr.producing else None)
            salt = tr.message(b"mixed salt",p.salt_bytes,self.salts[i] if tr.producing else None)
            leaf = derive_leaf(i,fencode(col),salt,p.hash_bytes)
            idx = i
            for depth in range(p.leaves.bit_length()-1):
                sib = tr.message(b"mixed Merkle sibling",p.hash_bytes,
                                 self.tree[depth][idx^1] if tr.producing else None)
                leaf = node(sib,leaf) if idx&1 else node(leaf,sib)
                idx >>= 1
            if leaf != self.root:
                raise ValueError("mixed Merkle opening rejected")
            if xor(mul(q,EMBED[fbasis(p.qpoints,x)])) != qvalue(x,col,av[j]):
                raise ValueError("mixed Q opening rejected")
            r_open.append(col[n+32:] ^ freduce(fmul(self.gamma,col[:n+32]),axis=1))
        if self.early_degree:
            for x, column in zip(xs, r_open, strict=True):
                if not np.array_equal(feval(self.rsamples,p.points,x), column):
                    raise ValueError("explicit degree opening rejected")
            return
        extra = [j for j in range(p.leaves) if j not in indices][:len(p.points)-p.opens]
        for i in extra:
            v = feval(self.rsamples,p.points,p.evaluation(i)) if tr.producing else None
            r_open.append(ff_message(tr,b"mixed R completion",p.decs_rows,v))
        domain = tuple(p.evaluation(i) for i in indices+extra)
        recovered = np.array([feval(np.asarray(r_open).T,domain,x) for x in p.points]).T
        if hash_bytes(b"mixed R",fencode(recovered)).digest(p.hash_bytes) != self.digest:
            raise ValueError("mixed degree check rejected")
