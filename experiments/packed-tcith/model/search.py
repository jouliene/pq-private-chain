"""Grid screen, then exact integer repricing; distinct from the all-domain certificate."""
import argparse
import json
import numpy as np
from scipy.special import gammaln
from model import GROUPS, cost, min_power, P

LN2 = np.log(2.0)


def search(suite, encoding, maxs=800, maxell=128, digest=64, target=256):
    d = 2 if encoding=="r1cs" else 7
    s = np.arange(1, maxs+1, dtype=np.int64)[:,None]
    ell = np.arange(1, maxell+1, dtype=np.int64)[None,:]
    D = s+ell-1
    n = sum((v+s-1)//s for v in GROUPS[suite,encoding])
    hints = ((d-1)*D+s-1)//s + (3*s-2)//s
    rho = min_power(P,1 << target)
    k = D+2
    loggood = (gammaln(d*D+1)-gammaln(ell+1)-gammaln(d*D-ell+1))/LN2
    answers = []
    for b in range(6,64):
        N = 1 << b
        if b < 26:
            logbin = (gammaln(N+1.)-gammaln(k+1.)-gammaln(N-k+1.))/LN2
        else:
            # Upper bound on log(C(N,k)); at large N the second-order
            # correction is negligible for the profiled width. Exact repricing below.
            logbin = k*b-gammaln(k+1)/LN2-k*(k-1)/(2*N*LN2)
        # No catastrophic cancellation at very large N.
        logposs = np.cumsum(np.log2(N-np.arange(maxell,dtype=float),where=N>np.arange(maxell),
                                       out=np.full(maxell,-np.inf))-np.log2(ell[0]))
        with np.errstate(invalid="ignore",divide="ignore"):
            tau = np.ceil(target/(logposs-loggood))
        eta = np.ceil((target+logbin)/(64+np.log2(1-2**-32+2**-64)))
        path = 2-ell+sum(np.minimum(1<<j,ell) for j in range(1,b))
        field = ell*(n+rho*hints)+(s+ell)*eta+rho*((d-1)*D+2*s-2)
        with np.errstate(invalid="ignore"):
            est = 3*digest+tau*(8*field+32*ell+digest*path)
        est = np.where((d*D<N)&(tau>0)&np.isfinite(est),est,np.inf)
        if np.all(np.isinf(est)):
            continue
        # Reprice the best eight integer geometries with exact binomials.
        flat=np.argpartition(est.ravel(),min(7,est.size-1))[:8]
        rows=[]
        for i in flat:
            a,j=np.unravel_index(i,est.shape)
            if np.isfinite(est[a,j]):
                rows.append(cost(suite,encoding,b,int(a+1),int(j+1),digest,target))
        answers.append(min(rows,key=lambda r:r["proof_B"]))
    return answers


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--suite",choices=["MNG1","SLG1"],default="SLG1")
    p.add_argument("--encoding",choices=["degree7","r1cs"],default="degree7")
    p.add_argument("--digest",type=int,choices=[48,64],default=64)
    p.add_argument("--max-s",type=int,default=800)
    p.add_argument("--max-ell",type=int,default=128)
    p.add_argument("--target",type=int,default=256)
    a=p.parse_args()
    print(json.dumps(search(a.suite,a.encoding,a.max_s,a.max_ell,a.digest,a.target),indent=2))
