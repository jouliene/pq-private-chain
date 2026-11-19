# Current architecture and implementation boundary

## Payment selection for a local PoW devnet

Use standalone APV2 wallet proofs and direct producer intake as the first local payment path. On the measured hardware a sender making an offer every 12 seconds continued to pay as a two-second local block clock advanced with the preferred builder offline. A four-wallet aggregate verified but arrived after its eighth eligible opportunity on the same clock. Direct service needs 230,358 archive bytes per occupied singleton block. Four-way packing would use 62,787.5 B per payment at full occupancy; the measured service and eligibility limit prevent crediting that cost to the full network. At 100M inclusions the low and busy mix projections are 19.1523 and 7.0807 TB for one archival copy. The owner has not accepted an annual archive or traffic budget. Retain CP03 and the complete WHIR wallet as executable comparisons. The cumulative work rule, issuance, remote failover, globally consistent bootstrap/fork selection and formal post-quantum/privacy qualification remain open. [Decision and reproduction](../experiments/advancing-payments/DECISION.md)

## Prior wallet-created payment decision

Both research candidates have executable complete payment paths. Masked WHIR preserves CP03 ordinary-payment constraints and averaged 263,292 B per wallet submission. Two independently controlled native wallets each sent 147,324 B and retained one 157,220 B pair packet, including all four ciphertexts. Defer network activation of both pending cryptographic qualification and a credible role/availability design. The 1/5 TB archive sizes remain research comparisons. [Measured results and decision](../experiments/wallet-created/DECISION.md) · [Independent node and wallet costs](../experiments/wallet-created/ROLES.md)

## Prior validation-cost decision

Retain CP03 for executable payment research. Defer integration of both the masked wallet proof and transparent block-aggregate candidates tested from public revision `7c2d0fc8b68c566d13e3e341c1f49bacaad527f4`. A reviewed masked-proof schedule projects 262,850 mean bytes and 272,556 maximum for a complete ordinary body. Independent block-only relay fits the chosen link profile. The measured generic matrix/guard/first-fold computation already costs 0.245–0.261 CPU seconds per payment, against a two-validation-core catch-up allowance of 0.12476. Joining public CP03 proofs in a block could preserve independent wallet secrets and cut canonical traffic, while the pinned transparent fallback has a weaker component soundness budget and requires thousands of accelerator subproofs for a 96-payment workload. Its 200 kB final receipt is an unmeasured sensitivity.

Prioritize a structured, verifier-owned computation of the identical folded public matrix claim, including the guarded base-field constraints. Test exact agreement with the sparse evaluator, the remaining verifier cost and the joint simulation/extraction argument before integrating or funding full wallet proving. The projected primary 26.292 TB/year canonical copy and aggregate 0.711 TB/year canonical copy are conditional design alternatives; the unchanged CP03 reference still prices its 175.127 TB/year first copy. [Decision, measurements, service model and reproduction](../experiments/node-validation/DECISION.md).

## Preferred research path

Retain individual complete CP03 private-payment proofs for the measured finite
research participation model. Authenticated common-history continuation is now
implemented; its independent acceptance/publication status is in STATUS.md.
The [complete-payment size experiment](../experiments/payment-size/RESULTS.md)
reduced complete 2x2 payments to about 1.48 MB with verifier-reconstructed
preprocessing and transcript-derived deduplication. Preserve CP03 and defer
ledger integration of this encoding. The tenfold screen remains open. The
payment/history cost decision precedes a full consensus build.
Standalone accumulated-valid-work PoW
remains the preferred eventual consensus direction, not global optimality
or a deployed permissionless network. The owner prefers CPU-friendly public work
entry. RandomX is a leading puzzle candidate requiring qualification; no PQ
security, economic advantage or portable/optimized agreement is inferred here.

The ordinary, archival, mining and wallet roles must be costed separately. PoS
would pay the same payment proof, state and data-availability costs and would
add stake acquisition/launch, live quorum, signing safety and cold-bootstrap
premises. No PoW/PoS hybrid is proposed. Replacing classical signatures alone
would not resolve those PoS assumptions.

## Implemented payment and history

A sender commits two output notes and creates fixed-size encrypted receipts bound
to the canonical payment context. A spender proves ownership, funded occurrence
membership, nullifier derivation and bounded integer value conservation together
with the same private witness. One or two inputs/two outputs are supported.
Arity0 synthetic credits additionally require a registered entitlement and a
real public ML-DSA-87 signature. A valid relation alone cannot authorize issuance.

The public ledger verifies canonical encoding, a fixed trusted proof program,
current accepted anchor, source authority/one-time entitlement, unique nullifiers
and cores, receipt binding and fees. Durable state changes are atomic. Outputs
are append-only funded occurrences in a depth40 tree. Spend identity binds the
actual occurrence; it is not a fixed sixteen-member ring or a decoy multiplier.

Visible information includes arity, transaction size/timing, fees, encrypted
receipts, output commitments, nullifiers, accepted roots/counts and synthetic
source identities. Ordinary amounts, recipient identity and selected ownership/
membership indices are intended hidden under the specific assumptions in
[SECURITY.md](SECURITY.md). A tiny smoke scenario is not an anonymity measurement.

The current version4 research adapter supports0..128 bodies with an additional
256MiB encoded-body cap. The preserved earlier adapter supported sixteen.
It uses registered laboratory genesis sources and has no distributed consensus.
Its anchor at height h is accepted
for inclusion in h+1 through h+256; that window does not expire old balances or
permit forgetting old nullifiers. Reorg undo and current spentness are explicit.

## Receiving and recovery

The current backup is a canonical private key inventory: a40-byte spending
secret, all retained independently random ML-KEM keys/descriptors and wallet/
chain/version metadata. It is not an implemented mnemonic or master-seed wallet.
A backup before random key rotation cannot recreate the later key.

Recovery additionally requires public key inventory, complete public receipt/
nullifier history and an independently supplied endpoint. The reduced history
commits bytes/order but does not itself prove payment validity, consensus,
freshness or availability. A validity-trusting wallet explicitly delegates
omitted validation; a fully verifying wallet pays the full validation cost.

The earlier fresh private smoke restores a pre-receipt backup containing a rotated key
in a new process and proves/adopts a new spend. Its membership lookup is to its
trusted local full ledger. Moving that owned-index API to a remote service would
leak selected indices. The current fixed native selective frontier and joint
wallet coordinator construct paths locally while discovering receipts from common
history. The coordinator leases key inventory and jointly journals openings,
spentness, paths and full cursors for bounded selected-branch rewind. Source
review, clean build and13JS/5Rust component controls passed. The isolated small03
scenario passed actual receipt, local-witness spending and a backup-only
new-process spend. The full01 campaign then generated264 distinct genuine proofs
and exercised changing-root expiry, refreshed old-note spending, joint branch
rewind, orphan rejection, deep replay and another backup-only new-process spend.
Independent public-evidence review confirmed all264 proof associations and all14
final SQL tables. Both typed Anchor rejections left all14 tables unchanged.
An independent clean build, new isolated five-proof cycle and fresh public replay
of every full01 proof also passed. Publication/CI status is recorded in STATUS.md
and the milestone delivery record.
Two earlier observer failures and the bounded same-process observation repair
are retained as evidence.
The current continuation path starts from the wallet's own authenticated joint
cursor and fetches indexed public ranges directly. At 260 one-block appends,
actual responses total 1492866 bytes and 260 blocks are authenticated, compared
with an exact old-path obligation of 181853424 bytes and 33930 blocks. Requests
add 113360 bytes. Unchanged heads trigger no history request; shallow changes use
retained authenticated joint checkpoints. Deep changes revoke stale capabilities
and require explicit replay. Cold recovery still scans complete history; the
prototype's joint cursor/journal is process-local. See the
[results](../experiments/incremental-sync/RESULTS.md) for scopes, resource counts,
genuine spending/recovery, independent review and reproduction commands.

## Roles and measured limitations

The newer network-feasibility experiment passed its declared finite workload:
eight96-ordinary-payment batches, including a burst and validator restart, reached
durable full retention with empty queues. This provisionally retains CP03 for an
explicit model of full-retaining validators plus separately provisioned opaque
archives. It does not establish affordable annual participation, a pruned ordinary
node or year-long capacity. The current role-cost decision and complete measured
scopes are in [RESOURCE_DECISION.md](network-feasibility/RESOURCE_DECISION.md).
The16-payment measurements below are preserved historical evidence, not the
new adapter's capacity or a repeat of its resource test.

A full validator independently checks proofs, current state and data availability;
it retains nullifiers/occurrence state, undo/recent anchors and a body cache.
Cache eviction transfers full-body responsibility to a separately provisioned
archive. It does not eliminate system-wide history. A commitment or replica count
alone does not guarantee access. Mining adds dataset/CPU and economic exposure;
it must eventually be measured with validation, not credited as free.

Historical distinct-payment evidence generated32new complete proofs: sixteen
credits then sixteen ordinary2x2payments spending32distinct funded occurrences.
Its two full blocks reached64leaves,32nullifiers and fee escrow67,664,368 with
zero remaining source liability. A changed last proof was rejected with exact
fourteen-table state invariance. Actual publication/eviction, archive retrieval
and a fresh public ledger replay reached equal canonical state.

For the ordinary16block, four nonoverlapping local calls measured0.473067s
fixture intake,0.849106s admission/commit,1.062415s archive preparation/verification/
fsync and0.089639s publication/eviction:2.474226s total. Separate archive retrieval
and new-ledger admission averaged56.010ms and56.139ms per body. These are finite
block arithmetic, not transaction latency distributions. The whole instrumented
mixed/control run was15.480441s/272396KiB, with warm/uncontrolled page cache,
public body/snapshot oracles in RAM and tiny state. The new destination did not
perform its own archival publication. This publication smoke does not repeat that
campaign or inherit its timings as newly measured public-revision results.

The ordinary sample averages1,750,350B:175.035TB/year for one copy at100Mpayments.
The earlier audited fixture gives174.7478TB/year. Six full relay copies in that
scenario cost about266Mbit/s mean egress; three archives hold roughly524TB/year.
They are researcher scenarios, not required topology or owner budgets. Raw two
nullifiers/two commitments add25.6GB/year before indexes/tree/undo. Wallet reduced
scan framing projects about0.5TB/year; receiving-key scan costs add separate work.

Ideal constant-service projections of one year's backlog while accepting live
arrivals are79.05days for destination admission alone,201.44days for same-host
archive-fetch plus admission and351.19days for the full co-located four-call path.
They are not annual observations. The earlier researcher90day complete catch-up
profile did not pass. No free archive, implicit pipeline overlap, unpriced
checkpoint trust or raised budget is used to declare it passed.

## Alternatives and next implementation gate

A public full-verifier/state checkpoint path is the historical-bootstrap fallback.
It first needs a genuine proof of the actual complete CP03 verifier, including
SHA3, extension-field arithmetic, transcript and codec, with invalid-proof
rejection; then state/nullifier/source/fee transitions and history availability.
It does not remove initial data availability or receipt history costs.

A native lattice complete-payment relation is the materially different initial-
data challenger. Its prior full attempt produced no proof; exact sparse-prior,
rotation, verifier and target-parameter correspondence need repair before another
bounded attempt. That is not evidence the construction family is impossible.
Tiny partial AIR rewrites gave only3.9–7.9% predicted byte savings with more arrays;
they were not selected. The old MITH ordinary proof was389MB; it is preserved as
research evidence elsewhere, not a dependency of this published backend.

The version4 adapter now implements the proposed0..128body entries plus256MiB
encoded-body cap. A hypothetical30s cadence remains a research scenario.
Historical16/30s ordering offers
only16.8192Mslots/year;128/30s offers134.5536M, which is still not measured service
capacity. Genuine96-payment batches, separate archive/destination processes,
bounded transport and finite burst/restart queues have now been tested. Actual
private local-witness refresh, recent-anchor expiry, recovery and selected-branch
rewind have passed the full finite campaign and independent evidence review.
The complete proof relation and security parameters are preserved. The network
milestone's clean reproduction, publication and CI are closed historical evidence.
Current incremental-synchronization acceptance and its distinct publication/CI
checks are recorded in STATUS.md.

Permissionless launch needs zero-source genesis and empty work blocks. Proposed
reward entitlement is derived from the fully known non-genesis parent's identity
and committed reward key, registered once in the child, with branch-aware undo.
Gross parent transaction fees move once from escrow to reward liability; only
scheduled subsidy increases issued supply. Preserve integer T=V+L+E. Exact
emission/maturity/framing needs a reviewed contract; none of this adapter is
implemented by the present synthetic source mechanism.

At100M/year the mean is3.170979payments/s. A96-payment batch allows30.27456s.
Failure to drain the declared finite workload rejects that configuration. The
90day live catch-up scenario requires16.031061payments/s, an ideal62.379ms
complete-destination budget with an actually provisioned archive source. Correctness,
privacy or supply failures stop integration regardless of timing. Pivot on the
measured constraint rather than weakening parameters or silently raising budgets.
