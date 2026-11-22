"""Conditional query-model arithmetic for the funded SGM1 schedule, using only the standard library."""
import json
import math
from fractions import Fraction
from pathlib import Path

HERE = Path(__file__).resolve().parent


def bits(x):
    return round(math.log2(x), 6)


def calculate():
    trace = json.loads((HERE / "evidence" / "SGM1_TRACE.json").read_text())
    events = trace["events_by_label"]
    assert trace["packet_sha256"] == "7d824013f097fa234c51bd1343f20034845a2ae6fadf9bfdb4a957f21832a6d7"
    assert events["mixed open column"]["message_calls"] == 60
    assert events["mixed Merkle sibling"]["message_calls"] == 60*12
    assert trace["original_matches"] == 60 and trace["constant_offset_matches"] == 0
    leaves, pack, opens, rows, f_bits, k_bits = 4096, 91, 60, 75, 16, 256
    evaluations = pack+opens
    degree = Fraction(math.comb(leaves, evaluations+1), 1 << (rows*f_bits))
    support_limit = 2*pack+opens-1
    subset = Fraction(math.comb(support_limit, opens), math.comb(leaves, opens))
    # Separate tests. Each assumes a fixed assignment before an independent challenge.
    local_bits = dict(degree_cancel=-bits(degree), subset=-bits(subset),
                      cubic_fold=-bits(Fraction(3, 1 << k_bits)),
                      quotient=-bits(Fraction(15, (1 << k_bits)-8)),
                      AS_square_and_final_weights_union=k_bits-1)
    years, operations_per_year = 20, 100_000_000
    operations = years*operations_per_year
    legs = operations + operations//10
    slots = 2*legs
    n = trace["interacting_coin_blocks"]
    sensitivity, search = [], []
    for log_q in (32, 64, 96, 128):
        q = 1 << log_q
        # t includes the charged verifier expansion in CMS. No fitted constants.
        sensitivity.append(dict(log2_budget=log_q, log2_t_squared_times_example_kappa=2*log_q-255,
                                log2_t_cubed_over_2pow512=3*log_q-512,
                                dfms_classical_intermediate_output_log2_mismatch_upper=bits(
                                    8*(q+1)*math.sqrt(2/2**512) + (40*math.e**2*(q+2)**3+2)/2**512),
                                dfm_log2_factor_loss=round(2*n*math.log2(2*q+n+1)-math.lgamma(n+1)/math.log(2), 6)))
        for targets in (1, slots):
            # Known distinct usable marked preimages in a uniform 512-bit search space.
            upper = min(1, Fraction((2*q+1)**2*targets, 1 << 512))
            theta = math.asin(math.sqrt(targets / 2**512))
            half_iterations = math.pi/(8*theta)-0.5
            search.append(dict(log2_grover_iterations=log_q, marked_candidates=targets,
                               log2_success_upper=bits(upper),
                               log2_iterations_for_half_success=bits(half_iterations),
                               raw_classical_target_list_B=64*targets))
    return dict(case="SGM1 count 13; local algebra and conditional oracle-model sensitivity",
                degree_basis_F_points=evaluations, sampled_columns=opens, usable_subset_limit=support_limit,
                local_negative_log2_error=local_bits, lifetime_years=years, included_operations_per_year=operations_per_year,
                included_legs=legs, output_slots=slots, log2_union_loss_legs=bits(legs), log2_union_loss_slots=bits(slots),
                dfm_hypothetical_interleaved_rounds=n, cms_dfm_sensitivity=sensitivity,
                ideal_marked_search=search, typed_record_flip_log2_at_2pow64_node_records=bits(Fraction(2*(1<<64)+2,1<<512)),
                old_degree_proof_B=64+2*pack*rows, early_degree_proof_B=2*evaluations*rows,
                extra_B_per_leg=2*opens*rows-64,
                projected_extra_TB_100M_90_10=(100_000_000*11//10)*(2*opens*rows-64)/10**12)


if __name__ == "__main__":
    print(json.dumps(calculate(), indent=2))
