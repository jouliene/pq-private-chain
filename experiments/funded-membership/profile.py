"""Decode the two funded C keys and compare their complete encodings against B."""
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
previous = HERE.parent / "funded-upgrade"
spec = importlib.util.spec_from_file_location("funded_cost", previous / "profile.py")
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)


def profiles():
    result = {}
    for suite, role, pi in (("MNG3", "managed", 32), ("SLG3", "swap", 35)):
        name = role + ".vk"
        key = baseline.read_key((HERE / "registry" / name).read_bytes())
        old = baseline.read_key((previous / "registry" / name).read_bytes())
        if (key["common"]["pi"] != pi or key["config"] != old["config"]
                or key["config"]["fri"]["queries"] != 32 or not key["leaf_hiding"]):
            raise ValueError("incorrect C statement or funded B profile")
        proof = baseline.wire_cost(key)
        old_proof = baseline.wire_cost(old)
        inner = 9 + proof + 3584
        costs = dict(
            inner_B=inner, ordinary_frame_B=6 + inner, signed_supply_frame_B=17166 + inner
        ) if role == "managed" else dict(
            inner_B=inner, swap_frame_B=17195 + inner, complete_swap_B=13 + 2 * (17195 + inner)
        )
        result[suite] = dict(sha256=key["sha256"], verifier_B=key["bytes"],
                             statement_words=pi, trace_rows=key["trace_rows"], folds=key["folds_bits"],
                             configuration=key["config"], leaf_hiding=key["leaf_hiding"],
                             proof_B=proof, additional_proof_B=proof - old_proof, **costs)
    return result


if __name__ == "__main__":
    if not __debug__:
        raise SystemExit("run with assertions enabled")
    print(json.dumps(profiles(), indent=2, sort_keys=True))
