"""Figures 5, 6 and 13 plus section 3.2 single-product trace linearization."""
import numpy as np

from field import U, basis, eq_table, fold, inv, mul, product, xor


def run(c, tr, masks):
    gamma = tr.challenge(b"row equality", c.ell)
    size = 1 << c.ell
    if tr.producing:
        a,b,d = (np.pad(m.apply(c.w), (0,size-c.height)) for m in c.matrices)
        eq = eq_table(gamma)
    # Affine forms [public offset, one coefficient per precommitted trace mask].
    trace_len = 3*c.ell + 3 + 2
    def affine(v=0):
        expr = np.zeros(trace_len+1, U)
        expr[0] = v
        return expr
    mask_index = 0
    def masked(label, n, values=None):
        nonlocal mask_index
        start = mask_index
        mask_index += n
        sent = tr.fields(label, n, (values ^ masks[start:mask_index]) if tr.producing else None)
        forms = [affine(v) for v in sent]
        for i, form in enumerate(forms):
            form[1+start+i] = 1
        return forms

    claim = affine()
    rs = []
    points = (0,1,2,3)
    for _ in range(c.ell):
        msg = None
        if tr.producing:
            vals = []
            for j in points[1:]:
                aa,bb,dd,ee = (fold(t,j) for t in (a,b,d,eq))
                vals.append(xor(mul(ee, mul(aa,bb)^dd)))
            msg = np.array(vals, U)
        v = masked(b"cubic sumcheck", 3, msg)
        r = int(tr.challenge(b"fold", 1)[0])
        rs.append(r)
        claim = xor(mul(basis(points,r)[:,None], np.array([claim ^ v[0], *v])), axis=0)
        if tr.producing:
            a,b,d,eq = (fold(t,r) for t in (a,b,d,eq))
    abc = np.array([a[0],b[0],d[0]], U) if tr.producing else None
    ta,tb,tc = masked(b"linear ends", 3, abc)
    eq_end = product(np.array([1 ^ int(x) ^ r for x,r in zip(gamma,rs)], U))
    # eq(x,y)=(1+x)(1+y)+xy=1+x+y in characteristic two.
    f1,f2,f3 = mul(ta,eq_end), tb, mul(tc,eq_end)^claim
    if tr.producing:
        p1 = mul(abc[0],eq_end)
        slope = mul(p1 ^ masks[-1], inv(1 ^ 2))
        q = mul(slope, abc[1])
        # q = leading coefficient(p1(X))*p2 for the m=1 division by X-1.
        qmsg = np.array([q ^ masks[-2]], U)
    else:
        qmsg = None
    qhat = tr.fields(b"masked quotient",1,qmsg)[0]
    # Exclude interpolation node 1 exactly, without modular bias.
    r = 1
    while r == 1:
        r = int(tr.challenge(b"linearize", 1)[0])
    l1,l2 = basis((1,2), r)
    p1r = mul(f1,l1)
    p1r[-1] ^= l2
    v = tr.fields(b"blinded p1",1,
                  [mul(p1,l1)^mul(masks[-1],l2)] if tr.producing else None)[0]
    lin1 = p1r ^ affine(v)
    qform = affine(qhat)
    qform[-2] = 1
    lin2 = mul(f2,v) ^ f3 ^ mul(qform,r^1)
    # LCS constraints for w[0]=0, w[1]=1, three MLE endpoints, two linearized checks.
    mix = tr.challenge(b"LCS linear aggregation",7)
    wcoef = np.zeros(c.width, U)
    wcoef[0:2] = mix[:2]
    aggregate = affine(mix[1])
    row_values = eq_table(rs)[:c.height]
    for m, form, scale in zip(c.matrices,(ta,tb,tc),mix[2:5]):
        aggregate ^= mul(form,scale)
        wcoef ^= m.transpose(mul(row_values,scale), c.width)
    aggregate ^= mul(lin1,mix[5]) ^ mul(lin2,mix[6])
    return np.concatenate([wcoef, aggregate[1:]]), int(aggregate[0])
