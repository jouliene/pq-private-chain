# Independent review of Phase 1C

I reproduced the funded two-input partial burn and the four supply operations from an anonymous HTTPS clone of `d449aeae595b6563e2e2551fcecdbe9fcdcaca2c`. Public main and the fixture tag both resolved to that revision. The clone started in an empty directory with system/global Git configuration, credentials and local transport disabled. It had no alternate object store. The published command used a new private directory, a fresh upstream checkout and all four default archive downloads. The fixed suffix archive contained nine public block bodies and matched its SHA-256 pin. The source checker regenerated all 12 source pins and matched the registered managed executable and verification key. [Observed digests](observations.json)

```sh
bash experiments/supply-refinement/reproduce.sh "$(mktemp -d)/case"
```

## Funded observations

Each replay started at genesis, recovered the same four historical C events and verified four additional supply events at H38–42. I independently decoded the two selected databases, checked 42 compact history records per branch against mined blocks, reconstructed all eight 3,798-byte proof replies per branch and recomputed the four issuer request frames per branch. For each operation the selected asset, quantity, revision, authority and packet identity agreed with the Lean row calculation. Both H42 stores had 92 outputs, 50 spent identifiers, 11 supply events, six assets and 69 cumulative native fees. The fixed trace matched the published JSON byte for byte. [Public trace](../fixed-trace.json) · [Independent observations](observations.json)

| Fresh operation | Height | Registry transition | Observed authorization |
|---|---:|---|---|
| Managed registration | 38 | Absent → 30, revision 1 | Issuer signature and derived asset ID |
| Holder burn | 41 | 30 → 18, revision 2 | Two real funded inputs, unsigned burn envelope |
| Fixed issuance | 41 | Absent → 5, revision 1 | Derived asset ID and fresh first nullifier |
| Managed mint | 42 | 18 → 20, revision 3 | Same issuer, signed revision 2 and preceding burn transaction |

The fresh H41 burn consumed 16 tokens and 17 native units. Two restored wallet roles covered all 12 encrypted outputs in the new suffix. Reopening the burn outputs recovered 4 tokens and 14 native units in change. The node credited 106 native units for H41, including the two fees of 3. The registered wallet role built the holder payment through its low-level payment interface. The standard redemption command retains its exact-return policy. The fresh burn's private per-slot amounts passed Lean's arithmetic check. Replaying the fixed suffix used the previously published aggregates for its private amounts. [Wallet and replay methods](../README.md)

Two independent changes to local copies exercised different rejection paths. Changing only the selected prior revision rejected the genuine signed mint at issuer preflight. Changing only token change in the private projection of the genuine burn rejected its monetary equations. Both checks exited 1. The original packets and signed requests remained byte-for-byte the same. I also compared Lean SHA-256 against Python on 20 binary inputs spanning padding boundaries, checked reversible byte encoding on the same inputs and checked 60 eligible anchor counts around quaternary depth thresholds. [Observed checks](observations.json)

### Repeat the two rejection checks

Run this from the clone root after the fresh walkthrough. Set `case_dir` to its private output directory. To retain that path when starting a new walkthrough, use `case_dir="$(mktemp -d)/case"` followed by `bash experiments/supply-refinement/reproduce.sh "$case_dir"`. The commands below use temporary private copies and print only the check outcomes.

```sh
python3 -IB - "$case_dir" <<'PY'
import json, os, subprocess, sys, tempfile
from pathlib import Path

case = Path(sys.argv[1]).resolve()
load = lambda p: json.loads(p.read_bytes())
funding = load(case / "funding.json")
network = (case / "suffix" / (funding["burn_block"] + ".bin")).read_bytes()[8:40].hex()
lean = case / "lean-4.19.0-linux/bin/lean"
check = Path("experiments/supply-refinement/Check.lean").resolve()
env = dict(os.environ, LEAN_PATH=str(case / "kernel"))
os.umask(0o077)
with tempfile.TemporaryDirectory(dir=case) as scratch:
    for op in ("mint", "burn"):
        tx, = [e["tx"] for e in funding["opened_events"] if e["operation"] == op]
        d = case / "public-trace" / tx
        cmd = [lean, "-DwarningAsError=true", "--run", check, "--", d/"packet.bin", d/"reply.bin", network]
        prior = d / "prior.json"
        extra = []
        changed = Path(scratch) / (op + ".json")
        if op == "mint":
            cmd += [d/"v-request.bin", d/"v-reply.bin"]
            data = load(prior)
            data["sequence"] += 1
            prior = changed
            expected = "rejected original packet or pre-block issuer policy"
        else:
            data = load(case / "burn-opening.private.json")
            change, = [o for o in data["outputs"] if o["qty"] > 0]
            change["qty"] += 1
            extra = ["--opening", changed]
            expected = "private monetary residual rejected"
        changed.write_text(json.dumps(data))
        test = subprocess.run(cmd + ["--prior", prior, "--state", d/"state.json"] + extra,
                              capture_output=True, text=True, env=env)
        if test.returncode != 1 or expected not in test.stdout + test.stderr:
            raise SystemExit(op + " did not reach the expected rejection")
        print(op, expected)
PY
```

## Formal boundary

Lean 4.19.0 checked 16 named refinement theorems. Their dependencies contained only `propext`, `Classical.choice` and `Quot.sound`. The packet checker reconstructed the actual inner worker requests and signed issuer requests. The event theorem derived the former gates, admission, wire and policy facts and the resulting supply equality. Its private premises require a compatible opening for the same payment, a faithful selected inventory and separation of true note identifiers from other births and spent marks. The chronological projection ties one note to each selected commitment and locates real inputs inside the actual ancestor count. The supply-only block theorem allows distinct assets in the same block. The actual reward, selected SQLite writes and verifier I/O were checked by executing the pinned software. [Lean definitions](../Refinement.lean) · [Source correspondence](../OBLIGATIONS.md)

An arbitrary output recipient digest need not come with a known compatible spending-key opening. Collision resistance alone supplies neither that opening nor a faithful identity assignment for every inherited and newly created note. Full witness extraction from hostile proof bytes, signature security and public-to-private history binding remain separate assumptions. A successful run confirms the recorded finite transitions. The aggregate comparison on the original fixture uses historical owner disclosures. [Historical opening provenance](../../funded-supply/review/PUBLIC.md)
