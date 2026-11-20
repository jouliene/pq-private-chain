"""Independent lower bounds and constructive checks for FR Protocol 8, Eq. (18)."""
from fractions import Fraction
from math import comb, log2
from pathlib import Path
import json


P = 2**64-2**32+1
BUDGET = 241084
HERE = Path(__file__).resolve().parent


def ceil_div(a,b):
    return -(-a//b)


def min_exponent(numerator, denominator, threshold):
    """Return the smallest positive r with (numerator/denominator)^r >= threshold."""
    if not numerator > denominator >= 1:
        raise ValueError('invalid odds')
    r = 1
    while numerator**r < threshold*denominator**r:
        r += 1
    return r


def words_at_any_tree_size(groups, d, target, tangent):
    w = sum(groups)
    # The infimum in K>=K_min increases by rescaling s = K^(2/3)*u.
    # At K_min replace 1/s by its tangent at r then minimize the quadratic.
    L=Fraction(target,64)
    k=target//64+1
    rho=k
    r=Fraction(tangent)
    quadratic=L/k
    slope=L+rho*(d+1)-k*w/r**2
    intercept=2*k*w/r-rho*(d+1)
    field_bytes=8*(intercept-slope**2/(4*quadratic))
    total=min(field_bytes+64*target,8*w)  # ell<2s (dispersed tree), else raw witness suffices
    bound=ceil_div(total.numerator,total.denominator)
    assert bound>BUDGET
    return dict(witness_words=w,tangent=tangent,degree=d,target=target,
                all_power_of_two_party_counts_B_floor=bound)


def framed(groups, d, h, s, ell, bits, salt):
    parties = 2**h
    if s+parties>P or d*(s+ell-1)>=parties:
        raise ValueError('invalid disjoint evaluation grids or output degree')
    D=s+ell-1
    rho = min_exponent(P,1,2**bits)
    eta = min_exponent(P,1,2**bits*comb(parties,D+2))
    tau = min_exponent(comb(parties,ell),comb(d*D,ell),2**bits)
    packs = sum(ceil_div(count,s) for count in groups)
    hints = rho*(ceil_div((d-1)*D,s)+ceil_div(2*s-1,s))
    # Bit-reversal positions exhibit this frontier for a complete binary tree.
    active={int(f'{i:0{h}b}'[::-1],2) for i in range(ell)}
    siblings=0
    for _ in range(h):
        siblings+=len({i^1 for i in active}-active); active={i//2 for i in active}
    assert active == {0}
    raw=dict(hashes=192,witness=8*tau*ell*packs,hints=8*tau*ell*hints,
             masked_degree=8*tau*(s+ell)*eta,
             nonlinear=8*tau*rho*((d-1)*D),linear=8*tau*rho*(2*s-2),
             opening_salts=tau*salt*ell,siblings=tau*64*siblings)
    return dict(parties=parties,s=s,ell=ell,bits_per_screen=bits,rho=rho,eta=eta,tau=tau,
                packed_witness_columns=packs,degree_mask_columns=eta,hint_columns=hints,
                worst_siblings_per_tree=siblings,proof_B=sum(raw.values()),terms_B=raw,
                single_commitment_leaf_field_payload_B=8*parties*(packs+hints+eta))


def value(coefs,u):
    ans=0
    for c in reversed(coefs):
        ans=(ans*u+c)%P
    return ans


def sum_pivot_control():
    # Two secret points -1,+1 and opened point 0 are distinct. For alpha'=R+XH,
    # the sum functional on H's constant vanishes. The next coefficient suffices.
    secret=(P-1,1); opened=0; remainder=9; H=[123,456,789]
    def reassemble(coeff,u):
        return (remainder+(u-opened)*value(coeff,u))%P
    total=sum(reassemble(H,u) for u in secret)%P
    g=[sum((u-opened)*pow(u,j,P) for u in secret)%P for j in range(len(H))]
    pivot=next(i for i,coef in enumerate(g) if coef)
    public_coeffs=[coef if i!=pivot else 0 for i,coef in enumerate(H)]
    rhs=(total-len(secret)*remainder-sum(a*b for a,b in zip(g,public_coeffs,strict=True)))%P
    public_coeffs[pivot]=rhs*pow(g[pivot],-1,P)%P
    assert g[0]==0 and public_coeffs==H and reassemble(H,opened)==remainder
    return dict(secret_slots=2,opened_parties=1,broadcast_degree=3,
                deterministic_pivot=pivot,first_pivot_coefficient=int(g[0]),
                words_sent=len(H)-1,reconstruction_equal=True)


def qrom_screen():
    # DFM Corollary 13 aggregates the order error over all adaptive statements.
    # This is a sensitivity, conditional on a secure quantum interactive protocol.
    q=2**128
    denominator=(2*q+4)**6
    return dict(ideal_common_hash_range_bits=512,challenge_rounds=3,
                log2_loss=round(log2(denominator)-log2(6),6),
                log2_additive_only_upper_contribution=round(log2(denominator)-512,6),
                minimum_integer_interactive_bits_for_individual_term_below_one=772,
                minimum_integer_common_hash_range_bits_for_individual_term_below_one=775)


def check():
    census=json.loads((HERE.parent/'encoding/CENSUS.json').read_bytes())
    quadratic={}
    compact={}
    stricter={}
    for suite,r in [('MNG1',101),('SLG1',102)]:
        quadratic[suite]=words_at_any_tree_size(census[suite]['r1cs']['packing_groups'],2,256,r)
        stricter[suite]=words_at_any_tree_size(census[suite]['degree7']['packing_groups'],7,768,
                                              60 if suite=='MNG1' else 61)
        compact[suite]=framed(census[suite]['degree7']['packing_groups'],7,20,101,25,256,32)
        assert compact[suite]['proof_B']<=BUDGET
    return dict(quadratic_any_N=quadratic,degree_seven_any_N_stronger_screen=stricter,degree_seven_example=compact,
                near_cap_at_272=framed(census['SLG1']['degree7']['packing_groups'],7,22,105,24,272,32),
                linear_broadcast_control=sum_pivot_control(),dfm_seven_move_sensitivity=qrom_screen())


if __name__=='__main__':
    if not __debug__:
        raise SystemExit('checks require assertions')
    print(json.dumps(check(),sort_keys=True,indent=2))
