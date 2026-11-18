"""Deterministic structural checks on synthetic public constants, separate from NI proof checks."""
from itertools import product
import json
from field import K, P, interpolate, dot, poly
from probe import CUBE, mask_weights, GUARD_MATRICES


def outer_rank():
    alpha = [K([7,2,0,1,0]), K([3,0,1,0,4])]
    rows = []
    for j in range(15):
        def mask(xs):
            return mask_weights(xs, 6)[j]
        output = [sum(map(mask, CUBE), K())]
        for i in range(2):
            vals = [sum((mask(alpha[:i]+[K(x)]+list(tail))
                        for tail in product((K(), K(1)), repeat=1-i)), K()) for x in range(6)]
            coeff = interpolate(vals)
            output.extend(coeff[:1]+coeff[2:])
        rows.append(output)
    rank = 0
    for col in range(len(rows[0])):
        pivot = next((i for i in range(rank, len(rows)) if rows[i][col] != K()), None)
        if pivot is None:
            continue
        rows[pivot], rows[rank] = rows[rank], rows[pivot]
        inv = rows[rank][col]**(P**5-2)
        rows[rank] = [a*inv for a in rows[rank]]
        for i in range(rank+1, len(rows)):
            ratio = rows[i][col]
            rows[i] = [a-ratio*b for a,b in zip(rows[i], rows[rank])]
        rank += 1
    assert rank == 11 and alpha[-1]**2-alpha[-1] != K()
    return rank


def guard_control():
    x = K([1, 1, 0, 0, 0])
    z = [K(1), K(1), x, 1-x]
    a,b,c = GUARD_MATRICES
    if any(dot(l,z)*dot(r,z) != dot(o,z) for l,r,o in zip(a,b,c)):
        raise ValueError('public guard-control relation')
    # In EF5/Fp the degree-two sum has first quotient coordinate b-b^2.
    # Verify a nonbase satisfying assignment and the two uniform-challenge roots.
    for b in (0,1,2,3,5,19,P-1):
        value = z[2]*b + z[3]*(b*b)
        assert value[1] == (b-b*b)%P
        assert any(value[1:]) == (b not in (0,1))
    # Exhaust all degree <=2 scalar projections in a 7-element base field,
    # including any precommitted nonbase blind's projected constant.
    max_roots, polynomials = 0,0
    for t,a,b in product(range(7), repeat=3):
        if a == b == 0:
            continue
        roots = sum((t+a*x+b*x*x)%7 == 0 for x in range(7))
        max_roots = max(max_roots, roots)
        polynomials += 1
    assert max_roots == 2 and polynomials == 336
    return dict(extension_assignment_satisfies_unguarded_relation=True,
                quotient_component_polynomial='b-b^2', full_field_good_roots_for_nonbase_assignment=[0,1],
                exhaustive_small_field=7, nonconstant_polynomials_tested=polynomials,
                worst_root_count=max_roots, four_independent_rows_worst=[max_roots**4,7**4])


def main():
    assert (K([0,1,0,0,0])**5) == K(3)
    print(json.dumps(dict(outer_mask_rank=outer_rank(), outer_independent_observations=11,
                          outer_mask_coordinates=15, guard=guard_control()), indent=2,sort_keys=True))


if __name__ == '__main__':
    main()
