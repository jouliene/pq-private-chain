"""Price this concrete split-ANF compiler and the remaining full FS01 payment."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "fresh-spend" / "binding"))
from side import schedule

WIDTH = 512
OFFERED = 100_000_000


def split(d):
    # At >=4 bits keep two variables in each group so the small executable
    # exercises nonlinear monomials on both sides. At 2^40 this is nonbinding.
    choices = range(2, d-1) if d >= 4 else range(d+1)
    def cost(low):
        high = d-low
        return (1<<low)-1-low + (1<<high)-1-high + WIDTH*((1<<high)-1)
    low = min(choices, key=cost)
    return low, d-low, cost(low)


def proof_size(ell, tau, opening):
    raw = (ell+7)//8
    padded = (ell + 3*256 + 16 + 7)//8
    return (48 + (tau-1)*padded + 34 + raw + 64 + (2*tau+opening)*32 + 32+16+4)


def geometry(count, api=None):
    d = (count-1).bit_length()
    low, high, g = split(d)
    base = schedule()
    del base["ordered_paths"]
    base["keccak_chi"] -= 80 * 38400
    # Keep the prior 40-bit slot, 41-bit comparison, private record equality,
    # integer checks, public equality (replace two root checks by selected leaf checks).
    # Only the eighty path arrays/parent permutations and their muxes disappear.
    other = sum(base.values())
    witness = 49233 - 2*40*512
    ell = 2*g+other+witness
    profiles = {}
    for label,(tau,opening) in {"256s":(22,218),"256f":(32,234)}.items():
        proof = proof_size(ell, tau, opening)
        if api:
            actual = int(subprocess.check_output([api,label,"price",str(ell)], text=True))
            if proof != actual:
                raise ValueError(f"upstream mismatch {label} {ell}")
        ordinary = 3990+proof
        leg = 33918+proof
        swap = 2*leg + 20
        profiles[label] = {"proof":proof, "ordinary":ordinary,"signed_leg":leg, "swap":swap,
                           "ordinary_upload_s_at_20_Mbps":round(ordinary*8/20e6,3),
                           "swap_upload_s_at_20_Mbps":round(swap*8/20e6,3)}
    return {"count":count,"bits":d,"low_bits":low,"high_bits":high,
            "unpadded_funded_digest_bytes":64*count,
            "table_coefficient_bytes":64*(1<<d),
            "lookup_ands_per_input":g,"other_ands_per_payment":other,
            "two_input_ands":2*g+other,"private_bits":witness,
            "expected_coefficient_xors_per_input_at_ideal_digests":256*(1<<d),
            "candidate_compiler_xors_per_input_for_combining_groups":512*(1<<high),
            "profiles":profiles}


def growing_year(accepted, year):
    """Repeat nine ordinary and one swap, immediate prior anchor, two seed rows."""
    cycles = accepted//10
    start = 2 + (year-1)*22*cycles
    total = 0
    for slot in range(10):
        first_count = start+2*slot
        last_count = first_count+22*(cycles-1)
        accounted = 0
        for bits in range((first_count-1).bit_length(), (last_count-1).bit_length()+1):
            end = min(cycles, ((1<<bits)-first_count)//22+1)
            delta = end-accounted
            if delta:
                packet = geometry(1<<bits)["profiles"]["256s"]
                total += delta*packet["swap" if slot == 9 else "ordinary"]
            accounted = end
        if accounted != cycles:
            raise ValueError("incomplete growth accounting")
    return total


def prices(api=None):
    sizes = {str(count):geometry(count,api) for count in (53, 209_000_000, 220_000_000,
                                                          2_090_000_000,2_200_000_000, 1<<40)}
    scenarios = []
    for accepted in (95_000_000, OFFERED):
        ordinary_count,swap_count=accepted*9//10, accepted//10
        rows=2*ordinary_count+4*swap_count
        for tag,count in (("year_1_end",rows),("year_10_end",10*rows),("at_capacity",1<<40)):
            packet=sizes[str(count)]["profiles"]["256s"]
            # Constant occupancy snapshots. A growing first year's exact total
            # would sum its changing d and output counts over block order.
            annual=ordinary_count*packet["ordinary"]+swap_count*packet["swap"]
            scenarios.append({"accepted_of_100m_offered":accepted,"snapshot":tag,
                              "ordinary_count_per_year":ordinary_count,"swap_count_per_year":swap_count,
                              "new_rows_per_year":rows,"digest_projection_growth_bytes":64*rows,
                              "receipt_ciphertexts_bytes_per_year":1792*rows,
                              "one_copy_body_bytes_at_fixed_snapshot_for_one_year":annual,
                              "one_copy_Mbps":round(annual*8/(365.25*86400*1e6),3)})
    return {"sizing":sizes,"traffic":scenarios,
            "changing_occupancy_body_bytes": [
                {"accepted":accepted,"year":year,"bytes":growing_year(accepted,year)}
                for accepted in (95_000_000,OFFERED) for year in (1,10)]}


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size-api",type=Path)
    args=parser.parse_args()
    print(json.dumps(prices(args.size_api.resolve() if args.size_api else None),indent=2))
