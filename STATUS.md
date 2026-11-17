# Public delivery status

Initial public release candidate is being assembled from research revision
360fc54e6b76dc864131f5c17b80c93b02c8bc67. Publication, clean local build/smoke and
clean public-clone verification remain pending. This file will be updated from
actual outcomes before the milestone handoff.

Implemented and historically executed: genuine CP03 all-arity private proofs,
exact atomic ledger/source/nullifier/fee rules, encrypted receipts, public history,
backup-only new-process restored spend, distinct16-payment block/archive role and
local fixed-endpoint witness construction. Those historical measurements are
summarized in docs/ARCHITECTURE.md; they are not new-public-revision test results.

Not implemented/qualified: distributed consensus, permissionless reward issuance,
network relay privacy, live private witness/reorg integration, annual100M capacity,
whole FP2 resource success, complete formal PQ/privacy composition or production
security. The custom cell representation remains a backlog hypothesis.

The publication smoke will build from included pinned sources and dependencies,
run focused genuine public checks and create three fresh private proofs with new
keys, receipt and backup-only recovery followed by a new spend. It need not
repeat the whole historical32-proof role campaign. Exact commands: BUILD.md.
