"""Integer certificates for the signed-proof budget and the selected cost minimum."""
import json
from fractions import Fraction
from math import comb
from model import CAP, GROUPS, ceildiv, cost, frontier, P, min_power


def all_N(groups, d, T, r):
    # T=256 or 768; here b=T/64 is exact and p<2**64.
    b = T//64
    K = b+1
    rho=K
    W=sum(groups)
    # Fixed-K lower envelope after substituting s=K**(2/3)*u.
    # 1/s >= 2/r - s/r**2 for s>0.
    linear = b+rho*(d+1)-Fraction(K*W,r*r)
    optim = 2*Fraction(K*W,r) - rho*(d+1) - linear**2*Fraction(K,4*b)
    wire = min(8*W,64*T+8*optim)
    return ceildiv(wire.numerator,wire.denominator)


def prove_small_trees(suite,encoding,max_height,threshold):
    """Exhaust all integer widths that could fit threshold. No floating decisions."""
    g=GROUPS[suite,encoding]
    d=2 if encoding=="r1cs" else 7
    target=256
    rho=min_power(P,1<<target)
    exact=0
    fits=[]
    smax=1 + threshold//(8*rho*(d+1))
    for b in range(1,max_height+1):
        N=1<<b
        for s in range(1,min(smax,(N-1)//d)+1):
            n=sum(ceildiv(c,s) for c in g)
            for ell in range(1,min(threshold//(8*n),(N-1)//d-s+1)+1):
                D=s+ell-1
                k=D+2
                # C(N,ell)/C(dD,ell) <= (N/(dD-ell+1))**ell.
                optimistic_bits=ell*(b-(d*D-ell+1).bit_length()+1)
                if optimistic_bits<=0:
                    continue
                tau=ceildiv(target,optimistic_bits)
                # C(N,k) >= (N/k)**k, rounded toward cheaper communication.
                eta=ceildiv(target+k*(b-(k-1).bit_length()),64)
                h=ceildiv((d-1)*D,s)+ceildiv(2*s-1,s)
                words=ell*(n+rho*h)+(s+ell)*eta+rho*((d-1)*D+2*s-2)
                lower=192+tau*(8*words+32*ell+64*frontier(b,ell))
                if lower<=threshold:
                    exact+=1
                    # Use an exact second pruning step before constructing large eta powers.
                    if (comb(d*D,ell)**tau << target)>comb(N,ell)**tau:
                        tau+=1
                    if 192+tau*(8*words+32*ell+64*frontier(b,ell))>threshold:
                        continue
                    row=cost(suite,encoding,b,s,ell)
                    if row["proof_B"]<=threshold:
                        fits.append([b,s,ell,row["proof_B"]])
    return dict(max_height=max_height,threshold_B=threshold,
                cheap_bound_survivors=exact,fit_count=len(fits),fits=fits)


if __name__=="__main__":
    out={"all_N_floor":{}}
    for suite in ["MNG1","SLG1"]:
        out["all_N_floor"][suite]=dict(
            quadratic_stage256_B=all_N(GROUPS[suite,"r1cs"],2,256,101 if suite=="MNG1" else 102),
            direct7_stage768_B=all_N(GROUPS[suite,"degree7"],7,768,60 if suite=="MNG1" else 61))
    out["signed_minimum_power_height"]=prove_small_trees("SLG1","degree7",19,CAP)
    out["best_signed_through_2^20"]=prove_small_trees("SLG1","degree7",20,238904)
    out["smaller_than_live_through_2^40"]=prove_small_trees("SLG1","degree7",40,139386)
    out["smaller_than_live_at_2^41"]=cost("SLG1","degree7",41,65,8)
    print(json.dumps(out,indent=2))
