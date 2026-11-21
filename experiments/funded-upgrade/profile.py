"""Read all four approved public keys and price their fixed, uncompressed proof encodings."""
from pathlib import Path
import json
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "token-profile"))
from parameters import read_key


def wire_cost(key):
    config, common = key["config"], key["common"]
    fri = config["fri"]
    folds = key["folds_bits"]
    oracles = (common["constant_polys"] + config["routed"], config["wires"],
               config["plonk_repetitions"] * (1 + common["partial_products"]),
               config["plonk_repetitions"] * common["quotient_factor"])
    n = key["lde_points"]
    cap = 1 << fri["cap_height"]
    depth = n.bit_length() - 1 - fri["cap_height"]
    # Initial four paths and leaves. All except public preprocessing carry a four-word salt.
    initial = (sum(oracles) + 12) * 8 + 4 * (1 + depth * 32)
    folded = 0
    for fold in folds:
        depth -= fold
        folded += 16 * (1 << fold) + 1 + depth * 32
    fixed = ((3 + len(folds)) * cap * 32 + 16 * (sum(oracles) + config["plonk_repetitions"])
             + 16 * key["final_extension_coefficients"] + 8 + 8 + 8 * common["pi"])
    return fixed + fri["queries"] * (initial + folded)


def profiles():
    refs = {"MNG1": ("managed-assets/native/registry/managed.vk", "ordinary"),
            "SLG1": ("atomic-swap/native/registry/swap.vk", "swap"),
            "MNG2": ("funded-upgrade/registry/managed.vk", "ordinary"),
            "SLG2": ("funded-upgrade/registry/swap.vk", "swap")}
    rows = {}
    for name, (path, kind) in refs.items():
        parsed = read_key((HERE.parent / path).read_bytes())
        proof = wire_cost(parsed)
        inner = 9 + proof + 3584
        frame = inner + (6 if kind == "ordinary" else 107 + 17088)
        rows[name] = dict(verifier_sha256=parsed["sha256"], verifier_B=parsed["bytes"],
                          public_words=parsed["common"]["pi"], config=parsed["config"],
                          trace_rows=parsed["trace_rows"], folds=parsed["folds_bits"],
                          leaf_hiding=parsed["leaf_hiding"], terminal_extension_coefficients=parsed["final_extension_coefficients"],
                          conditional_query_exponent=parsed["hypothetical_fixed_agreement_query_bits"],
                          proof_B=proof, physical_frame_B=frame, spare_frame_B=262144-frame,
                          complete_submission_B=frame if kind=="ordinary" else 13 + frame * 2)
    for a, b in (("MNG1", "MNG2"), ("SLG1", "SLG2")):
        assert rows[a]["public_words"] == rows[b]["public_words"]
        assert rows[a]["config"]["fri"]["queries"] == 26 and rows[b]["config"]["fri"]["queries"] == 32
        assert rows[a]["verifier_sha256"] != rows[b]["verifier_sha256"] and rows[b]["spare_frame_B"] >= 0
    return rows


if __name__ == "__main__":
    if not __debug__:
        sys.exit("Run without Python optimization")
    print(json.dumps(profiles(), sort_keys=True, indent=2))
