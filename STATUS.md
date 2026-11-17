# Development status

The selected CP03 implementation has passed a clean local source build and focused
reproduction at source baseline `b3121208b47484917a887041c376f4a5840a81b4`.
[LOCAL_VALIDATION.json](docs/LOCAL_VALIDATION.json) records the actual checks and
the preserved initial isolation-recipe failure. All5784core-manifest file hashes
and the final witness source approval are fixed; the release preparation after
that source commit changes only top-level delivery documentation/evidence.

Actual local checks: four newly built executables, eight native-provider controls,
53public CLI calls plus four native signature controls, three newly generated
private proofs, receipt, backup-only restoration in a new process followed by a
new spend, and three witness checkpoints/four negative controls. The build and
smokes ran with the original research/staging trees and Cargo registry/git caches
unavailable. Independent public-byte/receipt/SQL checks confirmed the results.

The immutable [publication delivery](https://github.com/jouliene/pq-private-chain/releases/tag/publication-2026-11-17)
records the exact **public** tested commit, anonymous-public-clone build/smoke
outcome and any actual CI result. Use its `delivery-result.json`, full SHA and
permanent commit URL for the milestone handoff; a local check or an unexecuted
workflow is not a public-clone or CI PASS. Later milestones follow
[DELIVERY.md](docs/DELIVERY.md), with new immutable commits/tags and compare links.

Implemented mechanisms: genuine CP03 all-arity proofs, exact atomic ledger/source/
nullifier/fee rules, encrypted receipts, public history, backup-only new-process
spending, the real distinct16-payment block/archive experiment and fixed-endpoint
local witness construction. The historical32-proof campaign and99negative proof
campaign were not repeated for this short publication smoke; their source/entry
points and the distinction are retained.

Not implemented/qualified: distributed consensus, permissionless reward issuance,
network relay privacy, live private witness/reorg integration, annual100M capacity,
whole FP2 resource success, complete formal PQ/privacy composition or production
security. The custom cell representation remains a backlog hypothesis.
