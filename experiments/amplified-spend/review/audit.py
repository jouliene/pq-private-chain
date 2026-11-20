"""Independent integer checks for the registered incidence and Boolean proof layouts."""
from fractions import Fraction
from math import comb
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
CAP = 241_084
N = 8**7


def degree_polynomial_spectrum():
    # Sum over all polynomials degree <=6 of C(number of roots,k). Specifying
    # k<=7 roots leaves 7-k free coefficients. For k=8 only zero remains.
    counts = {}
    for k in reversed(range(9)):
        moments = comb(8, k) * 8**(7-k) if k < 8 else 1
        counts[k] = moments - sum(comb(j, k)*n for j, n in counts.items())
    assert sum(counts.values()) == N and counts[6] > 0 and counts[7] == 0 and counts[8] == 1
    return {8*k: count for k, count in sorted(counts.items()) if count}


def exposed(log_n, q):
    # Split the occupied prefixes breadth-first, breaking ties from left to right.
    leaves = set()
    for i in range(q):
        pos = 0
        for bit in range(log_n):
            pos = (pos << 1) | ((i >> bit) & 1)
        leaves.add(pos)
    frontier = set()
    active = leaves
    for depth in range(log_n, 0, -1):
        frontier.update((depth, i ^ 1) for i in active if i ^ 1 not in active)
        active = {i // 2 for i in active}
    assert active == {0}
    threshold = (q-1).bit_length()
    assert len(frontier) == 2**threshold-q+q*(log_n-threshold)
    return leaves, len(frontier)


def miss_count(a, bits):
    q = 1
    while (a.numerator**q << bits) > a.denominator**q:
        q += 1
    return q


def first_stage():
    # Direct search over the query count gives its first admissible integer,
    # including its own effect on the disclosed masking coordinates and rate.
    for q in range(1, 1000):
        deg = 2**17 + 64 + 2 + 8*q
        agreement = Fraction(3*deg, 4*N-deg)
        distance_lb = (1-agreement)*N
        radius = (distance_lb.numerator-1) // (3*distance_lb.denominator)
        chance = 1 - Fraction(radius, N)
        if (chance.numerator**q << 272) <= chance.denominator**q:
            break
    else:
        raise ValueError('no admissible first stage')
    leaves, hashes = exposed(21, q)
    assert all(j % 8 == 0 for j in leaves)
    # At slope zero each line has left endpoints (x,b) as x varies over GF(8).
    endpoints = {(x, j // 8) for j in leaves for x in range(8)}
    assert len(endpoints) == 8*q
    return dict(queries=q, degree=deg, radius=radius, distinct_endpoints=len(endpoints),
                distinct_evaluations_per_row=len(endpoints), seed_elements_per_row=len(endpoints)+1,
                siblings=hashes, tuple_values_B=len(endpoints)*2*40,
                with_roots_salts_and_direct_B=64+q*64+hashes*64+len(endpoints)*2*40+5*40)


def suffix_floor():
    rows=[]
    for log_n, main, width in ((19,8192,16),(17,512,16),(16,32,16),(17,32,1)):
        # Even the ideal Johnson agreement is >=sqrt(main/N) for these stages.
        q = miss_count(Fraction(main, 1 << log_n), 2*272)
        _, frontier = exposed(log_n, q)
        copies = 1 + (width == 1)
        wire = copies * (64*(1 + q + frontier) + q*width*40)
        rows.append(dict(q=q, siblings=frontier, leaf_trees_B=wire))
    return dict(stages=rows, total_B=sum(row['leaf_trees_B'] for row in rows))


def registered_wire():
    model = json.loads((HERE.parent/'primary/MODEL.json').read_text())['primary']
    total = (6*19+4)*40+7*8
    field_count = 0
    for row in model['stages']:
        q, width, d = row['queries'], row['width'], row['d']
        leaves, hashes = exposed(row['log_n'], q)
        copies = 1 + (width == 1)
        fields = len(leaves)*width*d*copies
        direct = 2+3*(width.bit_length()-1) if width>1 else 2+row['degree']
        amount = fields*40 + 64*copies*(1+len(leaves)+hashes) + 40*direct
        assert row['maximum_B'] == amount and row['hash_proof_nodes_per_tree'] == hashes
        total += amount
        field_count += fields
    assert total == model['maximum_proof_B'] and field_count == model['total_scalar_values']
    return dict(proof_B=total, ordinary_B=total+9+31*8+2*1792,
                signed_leg_B=total+21_060, stages=len(model['stages']), scalar_values=field_count)


def fallback():
    # Wire lower bound uses ONLY x4*x2 and x6*x (unreduced partial products).
    # The schoolbook network includes 64 full rows for each of the two products.
    per_sbox = 2*64*64
    # A nonzero third finite difference on the low three Boolean input bits
    # excludes any XOR/NOT network with at most one AND for a full-domain box.
    derivative = 0
    for x in range(8):
        derivative ^= pow(x, 7, 2**64-2**32+1)
    assert derivative == 0x9ac50
    results = {}
    for suite, permutations in [('MNG1',160),('SLG1',164)]:
        raw = per_sbox*(8*12+22)*permutations
        boxes = (8*12+22)*permutations
        results[suite] = dict(partial_product_ANDs=raw, broadcast_B_floor=68*((raw+7)//8),
                              separately_evaluated_full_domain_boxes_B_floor=68*((2*boxes+7)//8))
    return dict(online_openings=68, four_seventh_power_broadcast_B=68*(4*per_sbox//8),
                full_domain_box_third_derivative=hex(derivative),
                max_ANDs_at_cap_with_68_broadcasts=(CAP//68)*8, suites=results)


if __name__ == '__main__':
    if not __debug__:
        raise SystemExit('assertions required')
    first = first_stage()
    assert first['queries']==495 and first['with_roots_salts_and_direct_B']==729_992
    floor=miss_count(Fraction(2,3),256)
    output = dict(graph_gram_eigenvalue_multiplicities=degree_polynomial_spectrum(),
                  first_stage=first, best_one_third_queries=floor,
                  best_one_third_first_leaf_values_B=floor*2*8*40,
                  frozen_envelope=registered_wire(), first_stage_free_suffix=suffix_floor(),
                  registered_kkw_network=fallback())
    print(json.dumps(output, sort_keys=True, indent=2))
