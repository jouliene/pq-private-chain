"""Recalculate Feneuil--Rivain (May 2025), Eq. 18 and Table 7. No funded data."""
from math import ceil, comb, log2
from fractions import Fraction
import json
from model import field_counts, ceildiv

# Field entropy, lattice dimension n, binary planes k, l, s, eta, rho, reported bytes.
EXAMPLES=[
    ("Toy1",32,2048,2,43,32,17,4,38081),
    ("Toy2",61,4096,1,47,41,10,3,57409),
    ("Kyber512",log2(3329),1024,3,37,19,38,11,21185),
    ("Kyber768",log2(3329),1536,3,39,23,40,11,24938),
    ("Kyber1024",log2(3329),2048,3,41,27,42,11,28241),
    ("Dilithium2",log2(8380417),2048,3,43,32,23,6,40100),
    ("Dilithium3",log2(8380417),2816,4,45,37,24,6,57526),
    ("Dilithium5",log2(8380417),3840,3,45,37,24,6,58088),
]


def expected_frontier(b,ell):
    N=1<<b
    return 2-ell+sum((1<<j)*(1-Fraction(comb(N-(N>>j),ell),comb(N,ell))) for j in range(1,b))


def table():
    out={}
    for label,entropy,lattice_n,k,ell,s,eta,rho,reported in EXAMPLES:
        n=k*ceildiv(lattice_n,s)
        _,counts=field_counts(s,ell,2,n,rho,eta)
        base=96+sum(counts.values())*entropy/8
        formula=base+32*ell*log2(1024/ell)
        mean=base+32*float(expected_frontier(10,ell))
        out[label]=dict(packed_witness_columns=n,field_word_count=sum(counts.values()),
                        reference_B=reported,Eq18_literal_B=round(formula,3),
                        exact_mean_frontier_pricing_B=round(mean,3),
                        mean_minus_reference_B=round(mean-reported,3))
    return out


if __name__=="__main__":
    print(json.dumps(table(),indent=2))
