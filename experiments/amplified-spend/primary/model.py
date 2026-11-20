"""Executable accounting for a finite-field incidence amplifier followed by guarded CFW switches."""
from dataclasses import dataclass
from fractions import Fraction as Q
from hashlib import sha3_512, sha256, shake_256
from math import ceil, isqrt, log2
import struct
from itertools import product
import json

BASE = 2**64 - 2**32 + 1
EXT = BASE**5
CAP = 241084
DEGREE = 8
POLY = 0b1011
PRIMARY_WIDTH = (2, 16, 16, 16, 1)
PRIMARY_LOG_N = (21, 19, 17, 16, 17)
OUTER_K = 19
SOURCE_WORDS = 2**18
GUARDS = 7


def mul(x, y, bits=3, modulus=POLY):
    z = 0
    for _ in range(bits):
        if y & 1:
            z ^= x
        y >>= 1
        x <<= 1
        if x >> bits:
            x ^= modulus
    return z


def neighbors(right, dimension=7, bits=3, modulus=POLY):
    d = 1 << bits
    if not 0 <= right < d**dimension:
        raise ValueError("right vertex outside graph")
    slope = right % d
    for x in range(d):
        vertex, power = x, x
        for i in range(1, dimension):
            b = (right >> (bits*i)) % d
            vertex |= (b ^ mul(slope, power, bits, modulus)) << (bits*i)
            power = mul(power, x, bits, modulus)
        yield vertex


def max_frontier(n, queries):
    q = min(n, queries)
    return 2 - q + sum(min(2**level, q) for level in range(1, n.bit_length()-1))


def far_apart(n, queries):
    """Bit reversal attains min(2^level,q) nonempty prefixes at every tree level simultaneously."""
    bits = n.bit_length()-1
    return [int(format(i, '0%db' % bits)[::-1], 2) for i in range(min(n, queries))]


def actual_frontier(n, indices):
    nodes, count = set(indices), 0
    for _ in range(n.bit_length()-1):
        count += sum((v ^ 1) not in nodes for v in nodes)
        nodes = {v >> 1 for v in nodes}
    return count


def ceil_sqrt(x):
    scale = 2**40
    a = isqrt(x.numerator * scale**2 // x.denominator)
    if Q(a*a, scale**2) < x:
        a += 1
    return Q(a, scale)


def miss_queries(agreement, target):
    # Floating point supplies a starting point only. Verify the threshold exactly.
    q = max(1, ceil(target/-log2(float(agreement))))
    limit = Q(1, 1 << target)
    while agreement**q > limit:
        q += 1
    while q > 1 and agreement**(q-1) <= limit:
        q -= 1
    return q


@dataclass
class Stage:
    i: int
    n: int
    width: int
    d: int
    main: int
    aux: int
    mask: int
    q: int
    degree: int
    gamma: Q
    agreement: Q
    list_bound: int
    mca: int | None
    radius_mode: str
    fresh_pad: int = 0

    @property
    def seed(self):
        return self.q * self.d + 1


def stage(i, log_n, width, d, main, aux, radius, target, slack):
    n = 2**log_n
    k = width.bit_length()-1
    mask = 2 if k else 0
    if d != 1:
        h = d.bit_length()-1
        if d != 1 << h or log_n % h or not 1 <= log_n//h-1 < d:
            raise ValueError("inadmissible incidence graph dimension")
        spectral_sq = Q(log_n//h-1, d)
    q = 1
    for _ in range(250):
        # seed + spare coordinates + main + folded auxiliary, minus one for polynomial degree.
        degree = main + aux + mask + q*d
        if degree+2 >= n:
            raise ValueError("unusable base RS rate")
        rate = Q(degree, n)
        gamma = rate if d == 1 else spectral_sq * rate/(1-rate+spectral_sq*rate)
        if radius == "one-third":
            # Strictly 3D < (1-gamma)n in Appendix A.1; delta=D/n.
            D = ceil((1-gamma)*n/3)-1
            a = 1-Q(D, n)
            size, mca = 1, D+1
        else:
            # Johnson list bound is alphabet independent. The RS MCA coefficient below
            # applies only on actual RS stages. No MCA number is invented for tuple codes.
            corrected = Q(degree+2, n) if d == 1 else gamma
            a = ceil_sqrt(corrected) + slack
            if a >= 1:
                raise ValueError("unusable Johnson radius")
            size = ceil((1-gamma)/(a*a-gamma))
            mca = None
            if d == 1:
                hi = ceil_sqrt(rate)
                lo = hi - Q(1,2**40)
                m = Q(max(3, ceil(hi/(a-hi)))) + Q(1,2)
                mca = ceil((2*m**5+3*m*(1-a)*rate)*n/(3*rate*lo)+m/lo)
        required = miss_queries(a, target)
        if q >= required:
            return Stage(i,n,width,d,main,aux,mask,q,degree,gamma,a,size,mca,radius)
        q = required
    raise ValueError("query/masking fixed point did not converge")


def record(s):
    k = s.width.bit_length()-1
    copies = 1 if k else 2
    indices = far_apart(s.n,s.q)
    frontier = actual_frontier(s.n,indices)
    assert frontier == max_frontier(s.n,s.q)
    direct_elements = 2+3*k if k else 1+s.degree+1
    wire = dict(roots=64*copies, direct=40*direct_elements, values=copies*len(indices)*s.width*s.d*40,
                salts=copies*len(indices)*64, siblings=copies*frontier*64)
    return dict(stage=s.i, width=s.width, log_n=s.n.bit_length()-1, d=s.d, main=s.main, aux=s.aux,
                spare=s.mask, seed=s.seed, fold_fresh_sigma=2*(k+1) if k else 0, ood_pad=s.fresh_pad,
                degree=s.degree, root_agreement_exact=f"{s.degree}/{s.n}", amplified_code_agreement=float(s.gamma),
                decoding_agreement=float(s.agreement), radius_mode=s.radius_mode, queries=s.q, base_reads=s.d*s.q,
                per_row_private_query_capacity=s.seed-1, list_bound=s.list_bound,
                mca_numerator=s.mca, miss_bits=-s.q*log2(float(s.agreement)), hash_proof_nodes_per_tree=frontier,
                bytes=wire, maximum_B=sum(wire.values()))


def schedule(widths=PRIMARY_WIDTH, logs=PRIMARY_LOG_N, ds=None, amp_radius="one-third", target=272, slack=Q(1,128)):
    ds = ds or (8,)+(1,)*(len(widths)-1)
    assert len(ds)==len(widths)==len(logs) and widths[-1]==1
    main_total, aux_total = SOURCE_WORDS,128
    rows=[]
    for i,(width, log_n,d) in enumerate(zip(widths,logs,ds)):
        assert main_total%width==0 and aux_total%width==0
        mode = amp_radius if d!=1 else "RS-Johnson"
        s=stage(i,log_n,width,d,main_total//width,aux_total//width,mode,target,slack)
        rows.append(s)
        if i+1<len(widths):
            used=s.aux+s.mask+s.seed
            aux_total=ceil(Q(used+1,widths[i+1]))*widths[i+1]
            s.fresh_pad=aux_total-used
        main_total=s.main
    stages=[record(s) for s in rows]
    base_outer=(6*OUTER_K+4)*40+GUARDS*8
    maximum=base_outer+sum(r["maximum_B"] for r in stages)
    guard=rows[0].list_bound*Q(SOURCE_WORDS,BASE)**GUARDS
    field=rows[0].list_bound*(Q(OUTER_K+1+5*OUTER_K+3+GUARDS,EXT)+Q(5,EXT-2))
    miss=sum(s.agreement**s.q for s in rows)
    known = all(s.mca is not None for s in rows)
    if known:
        for i,s in enumerate(rows):
            k=s.width.bit_length()-1
            if not k:
                field+=Q(s.mca+s.list_bound,EXT)
            else:
                following=rows[i+1].list_bound
                # Union of interleaved MCA factors 2^(k-j), degree-two mask polynomials,
                # initial affine check, one OOD collision, and 1+1+d*q scalar batches.
                field+=((s.width-1)*s.mca+(1+2*k)*s.list_bound+
                        Q(following**2,2)*max(s.degree,2)+following*(1+s.d*s.q))/EXT
    total=guard+field+miss if known else None
    return dict(target_miss_bits_per_stage=target, outer_direct_B=base_outer, stages=stages,
                commitments=len(rows)+1, maximum_proof_B=maximum, cap_B=CAP, excess_B=maximum-CAP,
                interactive_bits=-log2(total) if known else None, aggregate_field_bits=-log2(field) if known else None,
                guard_bits=-log2(guard), aggregate_miss_bits=-log2(miss),
                ideal_quadratic_crossover_log2_queries=-log2(total)/2 if known else None,
                salted_tree_hash_cubic_crossover_log2_queries=512/3,
                total_query_draws=sum(s.q for s in rows),
                authenticated_leaf_reads=sum(s.q*(2 if s.width==1 else 1) for s in rows),
                total_scalar_values=sum((2 if s.width==1 else 1)*s.width*s.d*s.q for s in rows),
                merkle_sibling_hashes_total=sum(r['bytes']['siblings']//64 for r in stages),
                single_tree_oracle_values_B=sum(s.n*s.d*s.width*40 for s in rows),
                total_leaves_committed=sum((2 if s.width==1 else 1)*s.n for s in rows),
                merkle_commit_hash_calls=sum((2 if s.width==1 else 1)*(2*s.n-1) for s in rows),
                merkle_verify_hash_calls_max=sum((2 if s.width==1 else 1)*(r['hash_proof_nodes_per_tree']+2*s.q-1)
                                                 for s,r in zip(rows,stages)),
                ideal_union_100M_per_instance_queries_crossover_log2=min((-log2(total)-log2(10**8))/2,
                       (512-log2(10**8))/3) if known else None,
                all_committed_scalar_payload_B=sum((2 if s.width==1 else 1)*s.n*s.d*s.width*40 for s in rows))


def run():
    primary=schedule()
    variants={}
    for tag, width, logs, ds, radius, target in [
        ("all_plain_same_widths", PRIMARY_WIDTH, PRIMARY_LOG_N, [1]*5, "one-third",272),
        ("optimistic_tuple_Johnson", PRIMARY_WIDTH, PRIMARY_LOG_N, [8,1,1,1,1],"tuple-Johnson-unmapped",272),
        ("first_width_four", (4,8,16,16,1), PRIMARY_LOG_N, [8,1,1,1,1],"one-third",272),
        ("domain_8_to_6", PRIMARY_WIDTH, (18,*PRIMARY_LOG_N[1:]), [8,1,1,1,1],"one-third",272),
        ("last_switch_only", (16,16,2,1), (19,17,18,17), [1,1,8,1],"one-third",272),
        ("single_instance_128_statistical", PRIMARY_WIDTH, PRIMARY_LOG_N, [8,1,1,1,1],"one-third",132),
    ]:
        res=schedule(width,logs,ds,radius,target)
        variants[tag]=dict(maximum_B=res['maximum_proof_B'],queries=[s['queries'] for s in res['stages']],
                           seeds=[s['seed'] for s in res['stages']],interactive_bits=res['interactive_bits'],
                           max_final_coefficient_count=res['stages'][-1]['degree']+1)
    # Small search over retained dyadic tail domains; the graph, fold geometry,
    # reductions, miss target and seven guards stay frozen. This is a bounded search.
    grid=list(product((17,19,21),(15,17,19),(14,16,18),(15,17,19)))
    eligible=[]
    for tail in grid:
        choice=schedule(logs=(21,*tail))
        if choice["interactive_bits"]>=260:
            eligible.append((choice["maximum_proof_B"],tail,choice))
    best,tail,selected=min(eligible,key=lambda v:v[:2])
    optimized=dict(grid_profiles=len(grid),eligible_at_260_bits=len(eligible),
                   max_domain_log2=21,tail_log_n=list(tail),maximum_B=best,
                   guard_coins=GUARDS,queries=[s["queries"] for s in selected["stages"]],
                   terminal_coefficient_count=selected["stages"][-1]["degree"]+1,
                   interactive_bits=selected["interactive_bits"])
    first=primary["stages"][0]
    n,q=1<<first["log_n"],first["queries"]
    dispersed=far_apart(n,q)
    expanded=list(x for right in dispersed for x in neighbors(right))
    assert len(set(expanded))==q*DEGREE
    coinseed=sha3_512(b"funded-amplifier/coin-family-demonstration/v1").digest()
    stream=shake_256(coinseed).digest(8*q)
    sampled=[u[0] & (n-1) for u in struct.iter_unpack("<Q",stream)]
    distinct=len(set(sampled))
    charge=distinct*2*DEGREE*40
    assert charge>CAP
    sample=dict(public_xof_seed_sha3_512=coinseed.hex(), actual_query_list_packed_u32_sha256=
                sha256(b"".join(struct.pack("<I",i) for i in sampled)).hexdigest(),
                actual_distinct=distinct,actual_leaf_value_bytes=charge,
                honest_draws_all_distinct_probability_lower_bound=float(1-Q(q*(q-1),2*n)),
                bit_reversal_distinct_base_neighbors=len(set(expanded)),
                bit_reversal_distinct_right_tuples=q)
    return dict(format="AMPLIFIED-FUNDED-PRIMARY-01",primary=primary,sensitivity=variants,mixed_tail_grid_minimum=optimized,concrete_queries=sample,
                universal_for_selected_profile=dict(best_possible_one_third_miss_queries=miss_queries(Q(2,3),256),
                     attainable_first_tree_leaf_values_B=miss_queries(Q(2,3),256)*2*8*40,
                     scope="one Appendix A.1 stage, interleave at least two, degree at least eight, explicit tuple leaves, n>=q"))


if __name__=="__main__":
    print(json.dumps(run(),sort_keys=True,indent=2))
