"""Compile 1A/1B/1C and compare original packets and public role replies against committed SQL observations."""
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent/"funded-supply"))
from openings import NETWORK, require


def run(lean, out, fixed=None):
    build = out/"kernel"
    build.mkdir(exist_ok=True)
    env = dict(os.environ, LEAN_PATH=str(build))
    def check(cwd, *args, capture=False):
        cmd = [lean, "-DwarningAsError=true", *args]
        return subprocess.run(cmd, cwd=cwd, env=env, check=True, text=True,
                              stdout=subprocess.PIPE if capture else None).stdout

    for dirname, module in (("funded-conservation","Conservation"),("funded-supply","Supply"),
                            ("supply-refinement","Refinement")):
        check(HERE.parent/dirname, "-o", build/(module+".olean"), module+".lean")
    check(HERE, "Check.lean")
    names = re.findall(r"^theorem (\w+)", (HERE/"Refinement.lean").read_text(), re.MULTILINE)
    require({"preflight_refines","residuals_gates","derive_admission","checked_wire","selected_refinement",
             "latest_after_insert","preblock_to_sql","checked_parent_block","checked_monetary_effects",
             "real_occurrences_distinct","checkPacket_refinement"} <= set(names), "missing refinement results")
    (build/"Audit.lean").write_text("import Refinement\n"+"".join(
        "#print axioms FundedRefinement."+n+"\n" for n in names))
    dependencies = check(build,"Audit.lean",capture=True)
    for name in names:
        m = re.search(r"'FundedRefinement\."+name+
                      r"' (?:depends on axioms: \[([^\]]*)\]|does not depend on any axioms)",dependencies)
        require(m and (not m[1] or set(m[1].split(", ")) <= {"propext","Classical.choice","Quot.sound"}),
                "unexpected Lean axioms for "+name)
    (build/"axioms.txt").write_text(dependencies)
    def compare(directory, private):
        compare_events(directory, lambda *args: check(HERE, "--run", "Check.lean", "--", *args, capture=True), names, private)
    compare(out, True)
    if fixed:
        compare(fixed, False)


def compare_events(out, calculate, names, private):
    funding = json.loads((out/"funding.json").read_bytes())
    observed = json.loads((out/"trace.json").read_bytes())
    if not private:
        require(observed == json.loads((HERE/"fixed-trace.json").read_bytes()), "pinned eight-event public trace")
    old = json.loads((HERE.parent/"funded-supply/original.json").read_bytes())["opened_events"]
    # The original roster's earlier disclosures and this run's newly reopened receipts have different provenance.
    openings = {r["tx"]:r for r in [*old,*funding["opened_events"]]}
    require(len(openings)==len(observed)==8, "four historical and four fresh applications")
    for event in observed:
        tx = event["packet_sha256"]
        directory = out/"public-trace"/tx
        raw = (directory/"packet.bin").read_bytes()
        require(sha256(raw).hexdigest()==tx, "exact packet identity")
        args = [directory/"packet.bin",directory/"reply.bin",NETWORK.hex()]
        if event["issuer_verification"]:
            args.extend([directory/"v-request.bin",directory/"v-reply.bin"])
        args.extend(["--prior", directory/"prior.json", "--state", directory/"state.json"])
        private_burn = private and tx == funding["burn_tx"]
        if private_burn:
            args.extend(["--opening", out/"burn-opening.private.json"])
        actual = json.loads(calculate(*args))
        require(actual["checked_private_residuals"] is private_burn, "scope of checked private residuals")
        obs = json.loads((directory/"observed.json").read_bytes())
        fields, row = obs["fields"],obs["row"]
        require(actual["row"] == {k:row[k] for k in ("mode","authority","sequence","supply","tx")} and
                actual["public_id"] == row["id"] and event["height"] == row["h"], "kernel vs committed row")
        require(actual["public_guards"] is True and all(actual[k] == v for k,v in fields.items()) and
                actual["issuer_request_verified"] == event["issuer_verification"] and
                actual["expected_issue_id"] == (row["id"] if fields["op"] in ("register","fixed") else None),
                "public fields from original frame, verifier reply and signature")
        opened = openings[tx]
        require(opened["asset"] == row["id"] and opened["before"] == (event["previous_supply"] or 0)
                and opened["after"] == row["supply"] and opened["encoded_delta"] == actual["word"]
                and opened["token_out"]-opened["token_in"] == opened["after"]-opened["before"] ==
                (-actual["magnitude"] if actual["high"] else actual["magnitude"]), "opened face value vs SQL")
    result = dict(lean_theorems=names, checked_events=len(observed), historical_disclosures=len(old),
                  fresh_opened_events=len(funding["opened_events"]), signed_calls=sum(r["issuer_verification"] for r in observed),
                  selected_tip=funding["tip"], partial_burn_tx=funding["burn_tx"], checked_fresh_burn_residuals=private)
    (out/"kernel-result.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result))


if __name__=="__main__":
    run(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), Path(sys.argv[3]).resolve() if len(sys.argv)>3 else None)
