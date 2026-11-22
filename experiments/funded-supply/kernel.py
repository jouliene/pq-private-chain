"""Check the generic invariant and the token/registry projections of the observed C events."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
BASE = HERE.parent / "funded-conservation"


def check(lean, scratch):
    cache = scratch/"kernel"
    cache.mkdir(exist_ok=True)
    env = dict(os.environ, LEAN_PATH=str(cache))

    def compile_at(directory, *args, capture=False):
        run = subprocess.run([lean, "-DwarningAsError=true", *args], cwd=directory, env=env,
                             stdout=subprocess.PIPE if capture else None, text=True, check=True)
        return run.stdout

    compile_at(BASE, "-o", cache/"Conservation.olean", "Conservation.lean")
    compile_at(HERE, "-o", cache/"Supply.olean", "Supply.lean")
    compile_at(HERE, "review/Examples.lean")
    names = re.findall(r"^theorem (\w+)", (HERE/"Supply.lean").read_text(), re.MULTILINE)
    if not {"consistent_path","preserve_supply","selected_supply","registry_delta","selected_fee"} <= set(names):
        raise ValueError("missing top-level monetary result")
    (cache/"Dependencies.lean").write_text("import Supply\n"+"".join("#print axioms FundedSupply."+n+"\n" for n in names))
    output = compile_at(cache, "Dependencies.lean", capture=True)
    for name in names:
        m = re.search(r"'FundedSupply\."+name+r"' (?:depends on axioms: \[([^\]]*)\]|does not depend on any axioms)", output)
        if not m or (m.group(1) and set(m.group(1).split(", ")) - {"propext","Classical.choice","Quot.sound"}):
            raise ValueError("unrecognized kernel dependencies for "+name)
    (cache/"axioms.txt").write_text(output)

    historical = json.loads((HERE/"original.json").read_bytes())
    actual = json.loads((scratch/"result.json").read_bytes())
    words = {r["tx"]:r["encoded_delta"] for r in actual["historical_public"]["events"]}
    records = {e["tx"]:e for e in historical["opened_events"]}
    for stage in actual["stages"].values():
        for event in stage["events"]:
            words[event["tx"]] = event["encoded_delta"]
            if records.setdefault(event["tx"],event) != event:
                raise ValueError("same transaction has different observed openings or ledger transition")
    lines = ["import Supply", "open FundedSupply FundedC"]
    for e in records.values():
        # Token amounts are authorized aggregates. No private identities or synthetic authority witnesses.
        i,o,old,new,word = (e["token_in"],e["token_out"],e["before"],e["after"],words[e["tx"]])
        if any(type(v) is not int or v < 0 for v in (i,o,old,new,word)):
            raise ValueError("invalid public observation")
        high, mag = divmod(word,1<<62)
        if high != int(e["operation"]=="burn") or e["delta"] != (-mag if high else mag):
            raise ValueError("incorrect observed descriptor")
        mint, burn = (0,mag) if high else (mag,0)
        lines.append(f"example : {word} = {high}*B+{mag} ∧ 0 < {mag} ∧ {mag} < B ∧ {new} < B ∧ "
                     f"{i}+{mint} = {o}+{burn} ∧ {old}+{mint} = {new}+{burn} := by decide")
    (cache/"Observed.lean").write_text("\n".join(lines)+"\n")
    compile_at(cache, "Observed.lean")
    print(json.dumps(dict(kernel_checked_supply_theorems=len(names),observed_distinct_events=len(records))))


if __name__=="__main__":
    check(Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve())
