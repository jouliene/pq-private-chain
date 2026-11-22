"""Degree-three equality-weighted selection sum-check over packed F16 elements."""
import numpy as np
from cbip import sumcheck
from runtime import EMBED, U, eq_table, mul, product, xor

PACK_BASIS = EMBED[[1<<i for i in range(16)]]


def run_products(ctx,ell,prover_arrays,bind_forms,label):
    """Check A*B=C over 2^ell rows. bind_forms(point,forms,ctx) binds all three endpoint MLEs."""
    gamma = ctx.tr.challenge(label+b" row",ell)
    arrays = (eq_table(gamma),*prover_arrays) if ctx.tr.producing else None
    def equation(eq,a,b,c):
        return mul(eq,mul(a,b)^c)
    end,r,terminal = sumcheck(ctx,ctx.form(),ell,3,arrays,equation,label)
    eq = product(np.array([1^a^b for a,b in zip(gamma,r)],U))
    forms = ctx.masked(label+b" endpoints",3,terminal[1:] if ctx.tr.producing else None)
    a,b,c = forms
    ctx.product(mul(eq,a),b,end^mul(eq,c))
    bind_forms(r,forms,ctx)


def run_selection(child_ids,sibling_ids,dir_ids,left_ids,ctx):
    child,sib,dirs,left = (np.asarray(x) for x in (child_ids,sibling_ids,dir_ids,left_ids))
    count = len(dirs)
    if any(x.shape != (count,512) for x in (child,sib,left)) or not count:
        raise ValueError("invalid selector shape")
    ell = 5+(count-1).bit_length()
    arrays = None
    if ctx.tr.producing:
        def packed(ids):
            bits = np.asarray(ctx.bits[ids],np.uint8).reshape(-1,16)
            byte = np.packbits(bits,bitorder="little",axis=1)
            return EMBED[byte[:,0].astype(np.uint16)|(byte[:,1].astype(np.uint16)<<8)]
        a,b,c = np.repeat(ctx.bits[dirs],32),packed(child)^packed(sib),packed(child)^packed(left)
        arrays = tuple(np.pad(np.array(t,U),(0,(1<<ell)-32*count)) for t in (a,b,c))
    def bind(r,forms,ctx):
        weight = eq_table(r)[:32*count].reshape(count,32)
        def applydir(out,scale):
            np.bitwise_xor.at(out,dirs,mul(xor(weight,axis=1),scale))
        ctx.bind(applydir,forms[0])
        for ids,f in zip((sib,left),forms[1:]):
            def apply(out,scale,ids=ids):
                w = mul(mul(weight[:,:,None],PACK_BASIS),scale).reshape(count,512)
                np.bitwise_xor.at(out,child.ravel(),w.ravel())
                np.bitwise_xor.at(out,ids.ravel(),w.ravel())
            ctx.bind(apply,f)
    run_products(ctx,ell,arrays,bind,b"packed private ordering")
