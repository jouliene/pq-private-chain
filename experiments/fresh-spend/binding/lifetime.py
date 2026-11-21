"""Illustrative resource exponents for ideal games; no implementation-security estimate."""
import json
from math import log2


def screen():
    # Research scenario: 90% ordinary and 10% two-leg swaps, all offers settle.
    annual_legs = 100_000_000 + 10_000_000
    slots = 2 * 20 * annual_legs
    rows = []
    for name,bits,targets in [
        ("one fixed 512-bit image",512,1),
        ("lifetime occupied slots",512,slots),
        ("uniform 512-bit account seeds, pooled million accounts",512,1_000_000),
        ("uniform 256-bit account seeds, pooled million accounts",256,1_000_000),
        ("uniform 256-bit account seeds, aligned maximum target scenario",256,slots),
        ("uniform 128-bit account seeds, pooled million accounts",128,1_000_000)]:
        rows.append(dict(game=name,targets=targets,ideal_quantum_query_bits=(bits-log2(targets))/2,
                         ideal_classical_trial_bits=bits-log2(targets)))
    return dict(offered_per_year=100_000_000,years=20,leg_slots=slots,
                ideal_target_models=rows,
                chosen_claw=dict(classical_birthday_trials_log2=256,quantum_BHT_queries_log2=512/3,
                                 BHT_table_entries_log2=512/3),
                one_attempt_neglog2=128,
                lifetime_union_bound_neglog2=128-log2(slots),
                per_attempt_neglog2_for_lifetime_128=128+log2(slots))


if __name__ == "__main__":
    print(json.dumps(screen(),indent=2))
