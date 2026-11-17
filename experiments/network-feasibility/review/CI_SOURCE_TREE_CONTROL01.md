# CI source-tree ordering control

**The failed legacy-smoke-before-isolated-wallet ordering is incompatible with
the required source-tree database exclusion.** This public-only discriminator
reproduced the incompatibility; it did not recover the sanitized historical
exception from CI44088764296.

The actual command, complete inline public control and source SHA256 pins are in
[CI_SOURCE_TREE_CONTROL01.json](CI_SOURCE_TREE_CONTROL01.json)
(SHA256 `c355d548936020a6cc2966bff04f5be9caab136b1a4101803d0924fe126680ad`).
One `python3 -I -B -c` subprocess exited0 in0.041866702s, below the10s allocation.
It imported the existing `isolation.py` with bytecode writes disabled and used a
disposable scratch directory:

| Control | Actual result |
|---|---|
| Minimal source tree with the legacy evidence directory shape | `inspect_tree` accepted and returned exactly that tree |
| Same tree after creating an8192B public SQLite sentinel at `experiments/cp03-private-cycle/evidence/private01.public/ledger.sqlite` | `ValueError: no database in wallet mount` |

The sentinel contained only a newly created public table and integer1. No existing
database contents were opened or read. Scratch files were removed by
`TemporaryDirectory` cleanup. No keys, proofs, wallet, original Controller,
native build or network request ran.

The source chain independently explains the ordering problem:

* `scripts/private_smoke.py` runs the installed `source/wallet/cp03/cycle.mjs` with
  the private-smoke attempt label.
* `cycle.mjs:176–188` creates `experiments/cp03-private-cycle/evidence/LABEL.public`
  under that source root and chooses `ledger.sqlite` there for the public ledger.
* `run.py:224–229` calls `isolation.command` on the **whole installed source tree**
  before `Popen`. `isolation.command` invokes `inspect_tree`, which rejects regular
  database filenames before launching the isolated process.
* The failed CI revision `c5e2f36` ran legacy `private_smoke.py --attempt private01`
  before its isolated-wallet step, using the same `ci01` installation. The earlier
  successful smoke can therefore create precisely the filename rejected by the
  later launch preparation. Root concurrently reordered the workflow while this
  source-tree discriminator was being recorded: the workflow SHA256 in the actual
  JSON record begins `a9b56d4` and identifies the **corrected isolated-first order**,
  not the historical failing order. The discriminator imports only unchanged
  `isolation.py`; this workflow timing does not affect its actual result. The raw
  JSON is preserved unchanged.

The narrow correction, now present in that pinned workflow, is to run the isolated wallet check against the fresh
approved installation **before source-mutating legacy smoke steps**, preserving
all existing checks and later legacy/witness coverage. Keep the database
exclusion; do not delete its suffix checks, skip tree inspection, silently prune
generated databases, or treat public ledger state as an allowed wallet mount.
This control establishes a concrete source-order defect and a justified ordering
repair. An actual corrected CI run is still required; neither that run nor the
historical exception attribution is claimed here. Only this report and its JSON
record were written to the owned review area; no workflow or accepted source was
modified.
