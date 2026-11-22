"""Compile all refinement dependencies and ask the Lean kernel for the decisive theorem dependencies."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
EXPERIMENTS = HERE.parent
MODULES = [
    ("funded-conservation", "Conservation"), ("funded-supply", "Supply"),
    ("supply-refinement", "Refinement"), ("occurrence-supply", "Anchored"),
    ("occurrence-supply", "Occurrence"), ("occurrence-supply", "Member"),
    (HERE.name, "Swap"), (HERE.name, "Wire"), (HERE.name, "Bridge"),
]
RESULTS = {
    "SwapWire": ["both_authorized", "one_fee", "rejected_without_frames", "rejected_keeps_rows", "accepted_writes"],
    "FundedSwap": ["LegOpening.wires", "local_amounts", "leg_delta", "PairGuards.afterLeft",
                   "cross_leg_indices", "pair_conservation", "Item.swap_no_registry_write",
                   "cross_item_set_checks", "distinctCount_eq_iff", "checked_block_guards", "Item.emitted_projection", "Item.fee_eq", "Item.checked_guards", "schedule", "Block.fees", "Block.invariant", "selected_history"],
    "SwapBridge": ["leg_guards", "pair_guards", "RealPath.selected", "unique_funded_input", "later_effective_raw",
                   "fees", "authorized_settlement", "packetItem_checked", "packetItem_emitted", "packet_projection", "packet_refines", "registered_history"],
}


def check(lean, cache):
    cache.mkdir(exist_ok=True)
    env = dict(os.environ, LEAN_PATH=str(cache))
    args = [lean, "-DwarningAsError=true"]
    for directory, module in MODULES:
        subprocess.run([*args, "-o", cache / (module + ".olean"), module + ".lean"],
                       cwd=EXPERIMENTS / directory, env=env, check=True)
    subprocess.run([*args, "Replay.lean"], cwd=HERE, env=env, check=True)
    names = [f"{group}.{name}" for group, results in RESULTS.items() for name in results]
    audit = cache / "Audit.lean"
    audit.write_text("import Bridge\n" + "".join(f"#print axioms {name}\n" for name in names))
    output = subprocess.check_output([*args, audit.name], cwd=cache, env=env, text=True)
    for name in names:
        pattern = rf"'{re.escape(name)}' (?:depends on axioms: \[([^\]]*)\]|does not depend on any axioms)"
        match = re.search(pattern, output)
        if not match or (match[1] and set(match[1].split(", ")) - {"propext", "Classical.choice", "Quot.sound"}):
            raise ValueError(f"unexpected theorem dependency: {name}")
    (cache / "axioms.txt").write_text(output)
    return dict(checked_names=names, lean_commit="6caaee842e9495688c1567e78c0e68dbb96942aa")


if __name__ == "__main__":
    root = Path(sys.argv[2]).resolve()
    result = check(Path(sys.argv[1]).resolve(), root / "kernel")
    (root / "kernel-result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Lean checked {len(result['checked_names'])} named results.")
