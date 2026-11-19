"""Fixed-agreement RS list/query terms, extracted from both actual registered verification keys."""
from fractions import Fraction
from hashlib import sha256
import json
import math
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
REFERENCE=HERE.parents[1]/'token-profile'
sys.path.insert(0,str(REFERENCE))
from parameters import Wire, read_fri

P=(1<<64)-(1<<32)+1


def term(k,n,queries,alpha):
    t=int(n*alpha)
    degree=k-1
    # For a list of m codewords, truncate each matching set to exactly t points.
    # m^2*t^2/n <= sum of column multiplicities squared <= m*t+m*(m-1)*degree.
    cap=Fraction(n*(t-degree),t*t-n*degree) if t*t>n*degree else None
    q,r=divmod(P,n)
    mass=Fraction(q*t+min(r,t),P)
    bits=-queries*math.log2(mass)
    return {'agreement_fraction':str(alpha),'set_size':t,
            'largest_single_draw_probability':str(mass),
            'single_fixed_set_exponent_bits':bits,
            'RS_list_size_max':math.floor(cap) if cap else None,
            'finite_list_bound_before_floor':str(cap) if cap else None,
            'union_exponent_for_fixed_prelisted_sets_of_at_most_this_size':bits-math.log2(math.floor(cap)) if cap else None}


def model(key,expected):
    raw=key.read_bytes()
    rd=Wire(raw)
    cap=rd.integer()
    if cap!=4:
        raise ValueError('unexpected cap height')
    # TKQ1 encodes 16 Merkle cap nodes and one digest as raw BytesHash<32>.
    # Only read the geometry needed for this bound. TKN1 uses canonical field words.
    if expected==64:
        rd.take(32*((1<<cap)+1))
    else:
        rd.words(4*((1<<cap)+1))
    config=[rd.integer() for _ in range(6)]
    if config != [135,60,2,128,2,8] or rd.take(2)!=b'\x01\x01':
        raise ValueError('unexpected circuit config or row blinding')
    fri=read_fri(rd); bits=rd.integer()
    if read_fri(rd)!=fri or fri['queries']!=expected or fri['rate_bits']!=5:
        raise ValueError('mismatching FRI config')
    folds=[rd.integer() for _ in range(rd.integer())]
    if rd.integer()!=bits or rd.integer(1)!=1 or rd.integer()!=bits or folds!=[2]*(bits//2-1):
        raise ValueError('degree, folds or leaf hiding mismatch')
    k=1<<bits;n=k<<fri['rate_bits']
    return {'key_sha256':sha256(raw).hexdigest(),'trace_rows':k,'domain':n,
            'queries':expected,'p_mod_n':P%n,'assumed_agreements':[term(k,n,expected,a) for a in [Fraction(1,32),Fraction(1,4),Fraction(1,2)]]}


if __name__=='__main__':
    print(json.dumps({'TKN1':model(REFERENCE/'candidate/registry/token.vk',26),
                      'TKQ1':model(HERE/'evidence/tkq1.vk',64)},indent=2,sort_keys=True))
