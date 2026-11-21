"""Compare the priced pivot with an independently derived transcript decomposition."""

import json
from pathlib import Path
import runpy


def review():
    base = Path(__file__).resolve().parents[2]
    price = runpy.run_path(str(base / "packed-tcith/review/audit.py"))["framed"]
    candidate = json.loads((base / "lattice-spend/pivot/PRICE.json").read_bytes())
    out = {}
    for label, row in candidate["shared_leg_geometry"].items():
        profile = row["profile"]
        suite = label.split("_")[0]
        census = candidate["census"][suite]["degree7"]
        pk = census["private_columns"]
        degree = census["rows_by_degree"]
        groups = [pk] + [degree["2"]]*3 + [degree["7"]]*2
        assert groups == census["packing_groups"]
        cost = price(groups,7,profile["N"].bit_length()-1,profile["s"],profile["ell"],256,32)
        full = cost["proof_B"] + 32 + (3841+6 if suite=="MNG1" else 21060)
        assert cost["proof_B"]==row["proof_B"] and full==row["proof_plus_fixed_frame_B"]
        out[label] = dict(proof_B=cost["proof_B"],complete_frame_B=full,
                          committed_field_bytes_per_tree=cost["single_commitment_leaf_field_payload_B"])
    return out


if __name__ == "__main__":
    print(json.dumps(review(),indent=2,sort_keys=True))
