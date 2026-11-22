"""Evaluate CDHZ 6.10, 8.3 and 11.3 for the single normalized payment geometry.
All probability calculations are exact rationals; only reported exponents are rounded.
"""
from fractions import Fraction
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent


def log2(value):
    return round(math.log2(value.numerator)-math.log2(value.denominator), 6)


def terms(t, sigma, target_users, rounds, q_pi, q_v):
    # The monetary predicate is a deterministic bit circuit (no calls to f_FS / f_VC).
    # n_y=n'_y=0. Named masses are each bounded by t: a conservative envelope
    # for the maximum over w_FS+w_VC+w_MultiExtract <= t in Theorem 11.3.
    ell, depth, r_min = 4096, 12, 256
    ct = 2*t+1
    mt = 1 << sigma
    rrbr_factor = 320*(t+rounds+1)*(t+rounds)
    finite_challenge = Fraction(4*(t+rounds+1)*rounds,1 << r_min)
    offline = 8*Fraction(160*t*ct**2 + 16*q_pi*depth,mt)
    online_t = t+1+q_v+rounds
    online = 4*Fraction(240*(t+1)*online_t**2,mt)
    commutes = 2*q_v**2*Fraction(240*(online_t+1),mt)
    overhead = finite_challenge+offline+online+commutes
    # Reference half-success unauthorized event; reserve a quarter of probability
    # for this extraction loss. target_users denotes a separate union scenario.
    slack = Fraction(1,4*target_users)-overhead
    kappa_limit = slack/rrbr_factor
    illustrative = Fraction(rrbr_factor,1 << 256)+overhead
    return dict(log2_global_or_per_trial_queries=t.bit_length()-1,comparison_events=target_users,
                log2_multiplier=log2(Fraction(rrbr_factor)),log2_finite_challenge=log2(finite_challenge),
                log2_offline=log2(offline),log2_online=log2(online),log2_commutes=log2(commutes),
                log2_VC_terms=log2(offline+online+commutes),
                minimum_integer_error_bits_for_quarter_slack=(
                    next(b for b in range(1025) if Fraction(1,1<<b) <= kappa_limit)
                    if kappa_limit>0 else None),
                max_log2_RRBR_for_quarter_slack=log2(kappa_limit) if kappa_limit>0 else None,
                log2_unit_example_unclipped_extraction_upper=log2(illustrative),
                merkle_commitment_bits=sigma, longest_vector=ell)


def main():
    trace = json.loads((HERE.parent/"sgm1-security"/"evidence"/"EAR1_TRACE.json").read_text())
    if trace["packet_sha256"] != "e8858eae087cc3bdeccbac25d51b96d2b9e72942fff9aad80d92586625bc73ac":
        raise ValueError("unrecognized funded trace")
    depth=12
    k=trace["interacting_coin_blocks"]
    openings=trace["authenticated_columns"]
    q_pi=openings+k-1
    q_v=k+openings*(depth+1)+k-1
    if (k,q_pi,q_v)!=(215,274,1209):
        raise ValueError("unexpected source geometry")
    lifetime=20*100_000_000*11//10
    return dict(geometry=dict(k=k,q_pi=q_pi,q_v=q_v,proof_oracle_decider_queries=0),
                model="CDHZ conditional upper envelope, no established RRBR for the money IOR",
                one_global_adversary=[terms(1<<b,640,1,k,q_pi,q_v) for b in (32,64,96,128)],
                per_leg_conditional_union=terms(1<<128,640,lifetime,k,q_pi,q_v),
                original_digest_width_sensitivity_only=terms(1<<128,512,1,k,q_pi,q_v))


if __name__=="__main__":
    print(json.dumps(main(),indent=2))
