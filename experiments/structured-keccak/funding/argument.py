"""Authenticate the note and path wiring against the same packed GKR witness."""
import numpy as np
from plan import Wiring
from runtime import U, eq_table, mul, xor
from rounds import run_rounds
from selection import run_products, run_selection
from proof import execute
from ring_switch import wire_bytes, wire_size

FLATTEN = 4


def dimensions(wiring, batch):
    rows = sum(len(a) for a, unused_b, unused_c in wiring.products)
    ell = (rows-1).bit_length()
    sel = 5+(len(wiring.selectors)-1).bit_length()
    # One terminal product per GKR layer and one for each of the two side sum-checks.
    trace = batch.mask_count + (3*sel+3) + (3*ell+3) + batch.depth+3
    return trace,ell


def linear_bindings(w,ctx):
    n = sum(len(target) for _,target in w.linear)
    gamma = ctx.tr.challenge(b"funded FS01 public and absorb wiring",n)
    value = offset = 0
    for _,target in w.linear:
        value ^= xor(gamma[offset:offset+len(target)][target.astype(bool)])
        offset += len(target)

    def apply(out,scale):
        offset = 0
        for columns,target in w.linear:
            size = len(target)
            weights = mul(gamma[offset:offset+size],scale)
            for indices in columns:
                np.bitwise_xor.at(out, indices, weights)
            offset += size
    ctx.bind(apply, ctx.form(value))


def check_bits(w,ell,ctx):
    columns = [np.concatenate(group) for group in zip(*w.products)]
    n = len(columns[0])
    arrays = None
    if ctx.tr.producing:
        arrays = [np.pad(ctx.bits[ids].astype(U),(0,(1<<ell)-n)) for ids in columns]

    def endpoints(point,forms,ctx):
        weights = eq_table(point)[:n]
        for ids,f in zip(columns,forms):
            def apply(out,scale,ids=ids):
                np.bitwise_xor.at(out, ids, mul(weights,scale))
            ctx.bind(apply,f)
    run_products(ctx,ell,arrays,endpoints,b"FS01 scalar predicates")


def shape(w):
    b = w.batch()
    t,ell = dimensions(w,b)
    return dict(permutations=b.p, parents=len(w.selectors), flatten=b.k,
                bit_coordinates=w.width, trace_words=t, scalar_rows=sum(len(a) for a,_,_ in w.products),
                linear_rows=sum(len(v) for _,v in w.linear), scalar_ell=ell,
                ring=wire_size(w.width,t), proof_B=wire_bytes(w.width,t)+32*t)


def run(w,domain,packet=None):
    batch = w.batch()
    t,ell = dimensions(w,batch)
    size = wire_bytes(w.width,t)+32*t
    if packet is not None and len(packet)!=size:
        raise ValueError("funded packet length rejected")

    def constraints(ctx):
        run_rounds(batch,ctx)
        child,sib,d,left = zip(*w.selectors)
        run_selection(child,sib,d,left,ctx)
        check_bits(w,ell,ctx)
        linear_bindings(w,ctx)
    bits = np.frombuffer(w.values, np.uint8) if w.private else None
    result = execute(domain+bytes([w.flatten]),w.width,t,constraints,bits=bits,packet=packet)
    if packet is None and len(result)!=size:
        raise ValueError("funded serialization mismatch")
    return result
