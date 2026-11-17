# Reproducible architecture mechanisms

These are real current mechanisms from research source revision
`360fc54e6b76dc864131f5c17b80c93b02c8bc67`. The public tree includes their source
and generators, not historical machine installations, private material, internal
conversations or large proof archives. `IMPORT.json` records the exact import.

First prepare, approve and build a disposable core installation using the root
README. Every command below consumes that installation's reported path and
explicit SHA256. Its source/runtime/toolchain/program/proof checks remain active.
Installation identities are local; they are separate from unchanged algorithm
identities. Only an operator chooses an installation, never a transaction.

- [Witness stream](witness-stream/README.md): construct selected paths locally
  from complete public leaves with an independent sparse oracle. The ordinary
  three-proof private smoke emits a compatible public workload; no extra proof
  generation is needed for a short witness check.
- [Distinct producer](role-pipeline/producer/README.md): generate32 new genuine
  credit/payment proofs with disposable private material confined to RAM.
- [Public role](role-pipeline/public-role/README.md): validate both full16-body
  blocks, reject a late invalid proof atomically, archive/evict, retrieve the
  actual archived bytes and replay them in a fresh independent Ledger.

Do not infer that all experiments were rerun during publication. The compact
[historical results](HISTORICAL_RESULTS.md) name the original measurement scope.
Any new public-clone smoke results are recorded separately by the root delivery.
These mechanisms do not implement distributed consensus, continuous wallet
witness updates, annual recovery or a composed PQ/privacy theorem.
