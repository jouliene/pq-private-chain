"""Check the Lean modules, audit their axioms and verify one private funded path."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
EXPERIMENTS = HERE.parent

BASE_MODULES = [
    ("funded-conservation", "Conservation"),
    ("funded-supply", "Supply"),
    ("supply-refinement", "Refinement"),
]
# Directory, module name, namespace.
MODULES = [
    (HERE, "Anchored", "FundedAnchor"),
    (HERE, "Occurrence", "FundedOccurrence"),
    (HERE, "Agreement", "OccurrenceAgreement"),
    (HERE, "Member", "OccurrenceMember"),
    (HERE / "review", "Boundary", "OccurrenceReview"),
]
REQUIRED = {
    "FundedAnchor.checked_membership",
    "OccurrenceMember.matched_real",
    "OccurrenceMember.slot_wires",
    "FundedOccurrence.same_spend_nf",
    "FundedOccurrence.fresh_nf_implies_unused_position",
    "FundedOccurrence.selected_invariant",
    "FundedOccurrence.selected_from_empty",
    "FundedOccurrence.selected_parent_block",
    "FundedOccurrence.anchored_packet",
    "FundedOccurrence.opaque_token_payment",
    "OccurrenceAgreement.holdings_agree",
    "OccurrenceAgreement.extend_imported_events",
    "OccurrenceReview.compatible_owner_does_not_exist",
    "OccurrenceReview.dummy_marks_only",
}
STANDARD_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}


def run(lean, case):
    cache = case / "kernel"
    cache.mkdir(exist_ok=True)
    env = dict(os.environ, LEAN_PATH=str(cache))

    def check(directory, *args, capture=False):
        return subprocess.run(
            [lean, "-DwarningAsError=true", *args], cwd=directory, env=env,
            text=True, check=True, stdout=subprocess.PIPE if capture else None,
        ).stdout

    for dirname, module in BASE_MODULES:
        check(EXPERIMENTS / dirname, "-o", cache / f"{module}.olean", f"{module}.lean")

    names = []
    for directory, module, namespace in MODULES:
        source = directory / f"{module}.lean"
        check(directory, "-o", cache / f"{module}.olean", source.name)
        public_results = re.findall(r"^(?:@\[simp\] )?theorem (\w+)", source.read_text(), re.M)
        names.extend(f"{namespace}.{name}" for name in public_results)
    missing = REQUIRED.difference(names)
    if missing:
        raise ValueError(f"missing required results: {sorted(missing)}")

    audit = cache / "Audit.lean"
    audit.write_text("import Member\nimport Agreement\nimport Boundary\n"
                     + "".join(f"#print axioms {name}\n" for name in names))
    output = check(cache, audit.name, capture=True)
    for name in names:
        pattern = rf"'{re.escape(name)}' (?:depends on axioms: \[([^\]]*)\]|does not depend on any axioms)"
        match = re.search(pattern, output)
        if not match or (match[1] and set(match[1].split(", ")) - STANDARD_AXIOMS):
            raise ValueError(f"unexpected kernel dependency: {name}")
    (cache / "axioms.txt").write_text(output)

    raw = json.loads((EXPERIMENTS / "funded-membership/reference_constants.json").read_bytes())
    fields = {
        "initial": "INITIAL_EXTERNAL_CONSTANTS", "terminal": "TERMINAL_EXTERNAL_CONSTANTS",
        "internal": "INTERNAL_CONSTANTS", "diag": "MATRIX_DIAG",
    }
    params = {name: [int(value, 16) for value in raw[key]] for name, key in fields.items()}
    param_file = cache / "params.json"
    param_file.write_text(json.dumps(params))
    check(HERE, "--run", "AnchorCheck.lean", param_file, case / "anchor.private.json")
    result = dict(theorems=names, checked_private_wallet_path=True, source="fresh selected wallet")
    (case / "kernel-result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Kernel checked {len(names)} named theorems.")


if __name__ == "__main__":
    run(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
