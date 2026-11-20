"""Reprice the funded frames, retaining the previous mixed-workload block model."""
from fractions import Fraction
import json
from math import ceil, comb
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]/"amplified-spend"))
from traffic import project


def typical_frontier(n, ell):
    # At level b, charge a child exactly when it is empty and its sibling is occupied.
    den = comb(n, ell)
    total = Fraction(0)
    for h in range(1, n.bit_length()):
        count = 1 << h
        size = n // count
        total += Fraction(count*(comb(n-size, ell)-comb(n-2*size, ell)), den)
    return total


def proof(row, use_mean):
    p = row["profile"]
    if not use_mean:
        return row["proof_B"]
    return ceil(row["proof_B"] - p["tau"] * p["digest_B"] *
                (p["max_frontier_hashes_per_tree"] - typical_frontier(p["N"],p["ell"])))


def scenario(name, transfer, leg):
    priced = project(transfer, [leg]*2, name)
    return dict(transfer_B=transfer, signed_leg_B=leg, swap_B=priced["swap_submission_B"],
                mixed=[row for row in priced["scenarios"] if row["swap_percent"]==10])


def main():
    models = json.loads((HERE.parent/"model/RESULTS.json").read_bytes())
    baseline = json.loads((HERE.parents[1]/"amplified-spend/TRAFFIC.json").read_bytes())["live_MNG1_SLG1"]
    base = scenario("funded baseline", baseline["transfer_B"],baseline["swap_frame_B"][0])
    if baseline["swap_frame_B"] != [base["signed_leg_B"]]*2 or base["swap_B"]!=baseline["swap_submission_B"]:
        raise ValueError("baseline framing changed")
    reg = [models[k+"_r1cs"]["practical_2^20_components"] for k in ("MNG1","SLG1")]
    direct = [models["shared_s101_ell25_N2^20"][k] for k in ("MNG1","SLG1")]
    result = {"live_capture":base}
    for name, rows in (("quadratic",reg),("direct7",direct)):
        for mean in (True,False):
            key = name+("_mean_ceil" if mean else "_max")
            pay, leg = (proof(r,mean) for r in rows)
            result[key] = scenario(key, 3841+pay,21060+leg)
    # Keep the lower-work, over-frame configuration separate from the executable baseline.
    sys.path.insert(0, str(HERE.parent/"model"))
    from model import cost
    low = [cost(suite, "degree7", 16, 140, 45) for suite in ("MNG1","SLG1")]
    result["direct7_N65536_max"] = scenario("over-frame geometry",3841+proof(low[0],False),
                                             21060+proof(low[1],False))
    # Counterfactual: remove just both path bodies and terminal links, leaving
    # group padding and all broadcast/degree overhead at this same geometry.
    # A real replacement must prove two bound, hidden occurrences.
    census = json.loads((HERE.parent/"encoding/CENSUS.json").read_bytes())
    space = {}
    for height, s, ell in [(16,140,45),(20,101,25)]:
        row = cost("SLG1","degree7",height,s,ell)
        rp = row["profile"]
        groups = census["SLG1"]["degree7"]["without_two_path_evaluations_and_terminal_links"]["packing_groups"]
        remaining = sum((g+s-1)//s for g in groups)
        saved = 8*rp["tau"]*ell*(rp["witness_packs"]-remaining)
        residual = row["proof_B"]-saved
        space[str(height)] = dict(remaining_witness_packs=remaining,removed_opening_bytes=saved,
                                  residual_B=residual,available_two_paths_and_binding_B=241084-residual)
    result["counterfactual_SLG1_no_membership"] = space
    return result


if __name__ == "__main__":
    print(json.dumps(main(),indent=2))
