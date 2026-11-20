"""Reprice two typed-matrix CFW schedules under the explicit Johnson and guard assumptions."""
from decimal import Decimal as D, ROUND_CEILING, localcontext
import json

P=2**64-2**32+1
K=P**5
MAIN=(16384,1024,64,64)
N=(2**19,2**17,2**16,2**17)


def ceil(x):
    return int(x.to_integral_value(rounding=ROUND_CEILING))


def bits(x):
    return round(float(-x.ln()/D(2).ln()),6)


def schedule(queries,guard,max_source=2**18,slack_denominator=4096):
    # At most 19 outer rounds; bound each weighted polynomial by its advertised degree.
    # All private source positions (with valid padding only) belong to the guard.
    rows=19
    # One spare 16-entry block is retained for masking geometry.
    aux=8
    stages=[];miss=D(0);field=D(0)
    for i,(width,main,n,q) in enumerate(zip((16,16,16,1),MAIN,N,queries,strict=True)):
        k=4 if width==16 else 0
        degree=main+aux+(2 if k else 0)+q
        rate=D(degree)/n
        agreement=(D(degree+2)/n).sqrt()+D(1)/slack_denominator
        li=ceil((1-rate)/(agreement**2-rate))
        m=D(max(3,ceil(rate.sqrt()/(agreement-rate.sqrt()))))+D('.5')
        mca=(2*m**5+3*m*(1-agreement)*rate)*n/(3*rate**D('1.5'))+m/rate.sqrt()
        error=agreement**q;miss+=error
        stages.append(dict(q=q,aux=aux,encoded_coefficients=degree+1,list_bound=li,
                           agreement=float(agreement),miss_bits=bits(error),MCA=mca))
        if k:
            next_width=1 if i==2 else 16
            needed=aux+2+q+1
            aux=(needed+1+next_width-1)//next_width
            stages[-1]['fresh_pad']=next_width*aux-needed
    guard_error=stages[0]['list_bound']*(D(max_source)/P)**guard
    field+=stages[0]['list_bound']*((D(rows+1+5*rows+3+guard)/K)+D(5)/(K-2))
    for i,s in enumerate(stages):
        size=s['list_bound'];mca=s.pop('MCA')
        if i==3:
            field+=(mca+size)/K
        else:
            t=stages[i+1]['list_bound']
            field+=(size+15*mca+8*size+D(t*t)/2*max(D(s['encoded_coefficients']-1),D(K)/(K-1))+t*(1+s['q']))/K
    total=guard_error+field+miss
    # Geometry without a ledger envelope; four iterative roots and one independent terminal mask root.
    # Initial lookup pays one salted multiproof for each preterminal tree, two for the terminal trees.
    direct=(6*rows+4)*40+guard*8
    expected=D(direct);maximum=direct
    for i,s in enumerate(stages):
        n=N[i];q=s['q'];w=16 if i<3 else 1;t=1 if i<3 else 2
        direct_fields=14 if i<3 else 1+s['encoded_coefficients']
        def empty(m):
            return (1-D(1)/m)**q
        revealed=n*(1-empty(n))
        frontier=D(0);m=n
        while m>1:
            frontier+=m*(empty(m)-empty(m//2))
            m//=2
        high=2-q+sum(min(2**v,q) for v in range(1,n.bit_length()-1))
        expected+=40*direct_fields+t*(64+revealed*(w*40+64)+64*frontier)
        maximum+=40*direct_fields+t*(64+q*(w*40+64)+64*high)
    return dict(expected_proof_payload_B=round(float(expected),3),maximum_proof_payload_B=maximum,
                johnson_additive_slack_denominator=slack_denominator,q=queries,guard_coins=guard,max_guard_degree=max_source,stages=stages,
                guard_bits=bits(guard_error),aggregate_miss_bits=bits(miss),aggregate_field_bits=bits(field),
                conditional_interactive_bits=bits(total),conditional_quadratic_order_one_log2_t=round(bits(total)/2,4),
                merkle_term_order_one_log2_t=round(512/3,4))


if __name__=='__main__':
    with localcontext() as ctx:
        ctx.prec=85
        print(json.dumps({'research':schedule([53,38,30,31],4),
                          'larger_queries_only_at_historical_slack':schedule([108,78,63,65],7),
                          'same_domain_stronger_screen':schedule([112,86,70,73],7,slack_denominator=128)},sort_keys=True,indent=2))
