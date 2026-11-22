"""Masked sum-check with affine verifier state and joint trace-product linearization."""
import numpy as np
from runtime import U, basis, fold, inv, mul, product, xor


class Context:
    def __init__(self,tr,nbits,ntrace,bits=None,masks=None):
        self.tr,self.nbits,self.ntrace = tr,nbits,ntrace
        self.bits,self.masks = bits,masks
        self.cursor = 0
        self.bindings,self.lines,self.products = [],[],[]

    def form(self,constant=0):
        a = np.zeros(self.ntrace+1,U)
        a[0] = constant
        return a

    def value(self,a):
        return a[0]^xor(mul(self.masks,a[1:]))

    def masked(self,label,n,values=None):
        start = self.cursor
        self.cursor += n
        if self.cursor > self.ntrace:
            raise ValueError("trace mask overflow")
        data = np.asarray(values,U)^self.masks[start:self.cursor] if self.tr.producing else None
        sent = self.tr.fields(label,n,data)
        v = [self.form(x) for x in sent]
        for i,f in enumerate(v):
            f[start+i+1] = 1
        return v

    def bind(self,projection,affine):
        self.bindings.append((projection,affine))

    def linear(self,affine):
        self.lines.append(affine)

    def product(self,a,b,c):
        self.products.append((a,b,c))

    def finalize(self):
        m = len(self.products)
        if m < 1 or self.cursor+m+1 != self.ntrace:
            raise ValueError("inconsistent linearization geometry")
        nodes = tuple(range(1,m+1))
        qnodes = tuple(range(m+2,2*m+2))
        blind = self.form()
        blind[-1] = 1
        f1,f2,f3 = [np.array(t,U) for t in zip(*self.products)]
        f1 = np.vstack([f1,blind])
        def interp(data,nodes,x):
            return xor(mul(basis(nodes,x)[:,None],data),axis=0)
        if self.tr.producing:
            # Values on these public nodes determine a degree m-1 quotient.
            a,b,c = [np.array([self.value(f) for f in group],U) for group in (f1,f2,f3)]
            q = []
            for u in qnodes:
                def ev(p,ns):
                    return xor(mul(p,basis(ns,u)))
                numerator = mul(ev(a,nodes+(m+1,)),ev(b,nodes))^ev(c,nodes)
                q.append(mul(numerator,inv(product(np.array([u^j for j in nodes],U)))))
        else:
            q = None
        qforms = np.asarray(self.masked(b"trace quotient",m,q),U)
        self.cursor += 1
        r = 1
        while r in nodes:
            r = self.tr.challenge(b"trace quotient point",1)[0]
        a,b,c = interp(f1,nodes+(m+1,),r),interp(f2,nodes,r),interp(f3,nodes,r)
        v = self.tr.fields(b"blinded trace evaluation",1,[self.value(a)] if self.tr.producing else None)[0]
        self.linear(a^self.form(v))
        z = product(np.array([r^j for j in nodes],U))
        self.linear(mul(b,v)^c^mul(z,interp(qforms,qnodes,r)))
        scales = self.tr.challenge(b"joint bit and trace equations",len(self.bindings)+len(self.lines))
        coeff = np.zeros(self.nbits,U)
        f = self.form()
        for (apply,g),k in zip(self.bindings,scales):
            apply(coeff,k)
            f ^= mul(g,k)
        for g,k in zip(self.lines,scales[len(self.bindings):]):
            f ^= mul(g,k)
        return coeff,f[1:],f[0]


def sumcheck(ctx,claim,ell,degree,arrays,evaluate,label):
    """Reduce a hypercube sum, retaining its final scalar as an affine form in trace masks."""
    coords = []
    points = tuple(range(degree+1))
    for _ in range(ell):
        msg = None
        if ctx.tr.producing:
            msg = [xor(evaluate(*(fold(t,j) for t in arrays))) for j in points[1:]]
        terms = ctx.masked(label,degree,msg)
        r = ctx.tr.challenge(label+b" fold",1)[0]
        coords.append(r)
        claim = xor(mul(basis(points,r)[:,None],np.array([claim^terms[0],*terms],U)),axis=0)
        if ctx.tr.producing:
            arrays = tuple(fold(t,r) for t in arrays)
    return claim,coords,([t[0] for t in arrays] if ctx.tr.producing else None)
