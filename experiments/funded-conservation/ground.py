"""Instantiate the universal local theorem with the four disclosed amounts and the actual user asset."""
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
THEOREMS = ("local_conservation", "selected_conservation", "ordinary_block", "exact_intermediate_bounds")


def check(row, lean, directory, label):
    numbers = row["opened_inputs"] + row["opened_outputs"]
    if len(numbers) != 4 or any(len(pair)!=2 or any(type(v) is not int or not 0<=v<2**62 for v in pair)
                                for pair in numbers):
        raise ValueError("fixture must contain four pairs of 62-bit amounts")
    limbs = struct.unpack("<4Q", bytes.fromhex(row["test_asset"]))
    if any(x >= 2**63 for x in limbs) or not any(limbs):
        raise ValueError("nonzero user asset and four canonical limbs required")
    fee, reward = row["fee"], row["miner_credit"]
    if type(fee) is not int or type(reward) is not int:
        raise ValueError("integer public fee and credit required")
    # CM/NF symbols are arbitrary here. audit.py checks real selected identities privately.
    # The arithmetic instantiation is valid for every assignment of those opaque symbols.
    fields = [f"⟨cm{i}, nf{i}, {n}, {q}, aid⟩" for i,(n,q) in enumerate(numbers)]
    data = f"""import Conservation
open FundedC
private def aid : AssetId := ⟨{', '.join(map(str,limbs))}⟩
section
variable (cm0 nf0 cm1 nf1 cm2 nf2 cm3 nf3 : Nat)
private abbrev pay := (Payment.mk ⟨{fields[0]},true,nf0⟩ ⟨{fields[1]},true,nf1⟩
  {fields[2]} {fields[3]} aid)
include cm0 nf0 cm1 nf1 cm2 nf2 cm3 nf3 in
private theorem observed (c : Currency) :
    let t := pay cm0 nf0 cm1 nf1 cm2 nf2 cm3 nf3
    value t.i.note c + value t.j.note c = value t.u c + value t.v c + charge c := by
  exact local_conservation (pay cm0 nf0 cm1 nf1 cm2 nf2 cm3 nf3) (by
    constructor <;> simp only [pay, ranged, tag, dummyGate, dummyBit] <;> decide) c
example : charge .native = {fee} ∧ {reward} = 100 + {fee} := by decide
end
"""
    (directory / (label+".lean")).write_text(data)
    subprocess.run([lean, "-DwarningAsError=true", label+".lean"], cwd=directory,
                   env=dict(os.environ, LEAN_PATH=str(directory)), check=True)


def main():
    lean, runtime = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    cache = runtime/"lean-check"
    cache.mkdir(exist_ok=True)
    subprocess.run([lean,"-DwarningAsError=true","-o",cache/"Conservation.olean","Conservation.lean"],
                   cwd=HERE, check=True)
    subprocess.run([lean, "-DwarningAsError=true", "review/Examples.lean"], cwd=HERE,
                   env=dict(os.environ, LEAN_PATH=str(cache)), check=True)
    audit = cache/"Audit.lean"
    audit.write_text("import Conservation\n" + "".join(f"#print axioms FundedC.{t}\n" for t in THEOREMS))
    report = subprocess.check_output([lean,"-DwarningAsError=true",audit.name], cwd=cache, text=True,
                                     env=dict(os.environ, LEAN_PATH=str(cache)))
    for name in THEOREMS:
        hit = re.search(r"'FundedC\."+name+r"' depends on axioms: \[([^\]]*)\]", report)
        if not hit or set(hit.group(1).split(", ")) - {"propext","Classical.choice","Quot.sound"}:
            raise ValueError("unexpected kernel axiom report for "+name+": "+report)
    print(report.strip())
    evidence = json.loads((runtime/"result.json").read_bytes())
    original = json.loads((HERE/"original.json").read_bytes())
    disclosed = json.loads((HERE.parent/"funded-membership/evidence/OWNERS.json").read_bytes())
    if (original["opened_inputs"] != disclosed["historical_note_amounts"] or
        original["opened_outputs"] != [disclosed["recipient_first_note"], disclosed["payer_remaining"]]):
        raise ValueError("original openings differ from the earlier funded-wallet disclosures")
    public = evidence["historical_public"]
    if any(original.get(k)!=v for k,v in public.items()):
        raise ValueError("new public replay differs from the original selected block evidence")
    check(original, lean, cache, "Historical")
    check(evidence["fresh_opened"], lean, cache, "Fresh")
    print("Historical and newly opened funded amounts instantiate the per-currency theorem.")


if __name__ == "__main__":
    main()
