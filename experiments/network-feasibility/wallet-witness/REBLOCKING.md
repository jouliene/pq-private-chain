# Conditional proof reuse for the later wallet gate

This is source/schedule preparation only. No real body was reblocked, no private
key/backup was read and no new proof or ledger admission was run. Resource
retention remains a prerequisite for actual Gate3 integration.

## Exact current-source observations

- `Statement::core/output_origins` in the arity crate depend on chain, kind/arity,
  nullifiers, commitments, fee, nonce and (for credits) source identity/credit,
  plus output ordinal. They have no block ID/height input. The funded leaf hashes
  origin+commitment; tree nodes hash level+children. `tree::append` uses height
  for storage/undo, not for the leaf/node hash.
- The complete payment proof **does bind its exact statement root/count** through
  projection and frame bytes. Reuse means preserve the entire body verbatim:
  statement, receipts, authorization and proof. Retargeting the anchor is not a
  header edit and needs a new genuine proof.
- Body identity and source authorization are body/statement-bound, not block-ID
  bound. The new block headers/parent chain must nevertheless be reconstructed
  and genuinely revalidated; old headers cannot be copied.
- Admission checks anchors against the **block parent's** count and unchanged
  anchor table. Anchors are published only after every body passes. An accepted
  original batch therefore cannot depend on outputs newly created inside that
  same block. Source/nullifier/core consumption is still sequential and atomic.
- The current retained table at tip t covers heights `max(0,t-255)..t`. An anchor
  at h permits next inclusion through h+256. Reblocking changes heights and can
  expire a previously valid body. Root/count, not an alleged transaction-origin
  branch, is the anchor identity.

`reblock_schedule.py` records exact hashes of the inspected source and checks the
named field/call boundaries. This is an executable consistency alarm plus review
evidence, not a formal Rust analysis or proof-verification substitute.

## Necessary conditions for reuse

1. Use the same chain, fixed Network04 rules/programs/fees, genesis entitlements
   and complete bodies. Keep validity/source/signature/proof checks active. No
   height-dependent reward/maturity or other new issuance rule may be assumed
   neutral; this observation concerns today's laboratory adapter only.
2. Preserve the complete funded-leaf order, including funding order and each
   body's output0/output1 order. Keep every required original batch-boundary
   root/count as a published new block boundary. Merkle order is not a set.
3. Keep source/nullifier/core order and uniqueness; a repeated spent body is not
   background load. Do not merge away an anchor boundary or use a body before
   its original funded prefix is present. Each actual block must still fit the
   count and encoded-byte bounds.
4. For every body, locate its unchanged anchor on the new branch and check the
   new inclusion height against the256-block window. Splitting a batch of96
   bodies into96single-body blocks is safe *conditionally* when each batch uses
   its immediately preceding preserved boundary: maximum inclusion age96.
   An older common anchor is not automatically safe under the new schedule.
5. Authenticate replacement ordering/endpoints and reconstruct wallet witnesses
   from common history. An independent actual Ledger replay must establish all
   dynamic checks and equal intended boundary state. Symbolic prefix equality
   below is stronger input-order equality, not an executed Poseidon/admission.

## Small public calculation and counterexamples

```sh
python3 -I experiments/network-feasibility/wallet-witness/reblock_schedule.py \
  --output /absolute/new/reblock-schedule-result.json
```

The public toy model has97funding pairs (96active+one reserved), then three batches
of96ordinary payments. It stores symbolic public leaf prefixes, **not actual
wallet mappings or CP03 roots/proofs**. Funding remains one97-body block; ordinary
bodies become288single-body blocks. Original batch boundaries then occur at
heights1,97,193,289 with counts194,386,578,770. Every ordinary batch's own anchor
age is1..96. The reserve's funding anchor at height1 is eligible at tip256 for
inclusion257, absent at tip257 for inclusion258, and absent at tip289; its two
toy outputs remain unspent across288real-changing-prefix model steps. Actual
changing CP03 roots and old-anchor rejection/refresh/spend remain unexecuted.

The calculation rejects four invalid schedules: swapping two bodies changes a
later ordered-prefix anchor; moving a next-batch body before its boundary uses a
future count; merging across that boundary removes the required parent anchor;
duplicating a body hits consumed inputs/core. All model inputs are public toy
labels and the result records no real private ownership mapping.

## Reserve and key custody are additional requirements

The current Gate1 generator spends every funded pair. It has no old unspent
reserve and cannot be retrospectively called an expiry fixture. Design the Gate2
successor's reserve **before locking the proof chain**. Adding a reserve later
can change leaf positions and later root/count anchors; no assumption that old
proofs can be retargeted is allowed.97sources fit today's128-source genesis cap,
but this is a proposed successor workload, not a campaign already executed.

Proof bodies alone are insufficient for the private recovery test. The reserve's
backup must contain its actual spending secret and independently random rotated
ML-KEM receiving keys (rotation before backup, receipt afterwards), plus documented
public inventory/context. Existing producers wipe keys when they finish. If
reuse spans the resource decision, the minimal reserve backup needs a separately
reviewed **bounded RAM-only** custody/handoff between immutable approved processes;
no file, raw log, debug hash, hidden seed or reconstruction from public bodies.
That handoff is not implemented here. If the keys are gone, regeneration is an
explicit new private experiment, not a claimed successful recovery/reuse shortcut.

Once a backend is retained, use the real reserve for an old-anchor genuine proof,
observe rejection after actual changing-root expiry, locally refresh, prove/admit
the new spend and restore/spend from only the documented backup in a new process.
A small separately proved branch alternative can then exercise orphan-only and
common-prefix cases. Keeping the source/schedule insight does not waive any of
those Gate3 checks or establish a resource/participation or security PASS.

## Proposed97-credit/eight-batch fixture and custody lifecycle

This section is a design for a future separately reviewed producer, not a change
to the frozen producer or an allocation to generate proofs. The existing public
generator has already destroyed its keys; none of its bodies can supply this
reserve retrospectively.

Use97distinct source entitlements in one funding block:96rolling lanes and one
reserve credit. Generate eight consecutive96-body ordinary batches. Each lane
spends its own previous pair and sends both outputs to the next lane-owner wallet;
both outputs in a pair must remain controlled by one wallet for the next2-input
payment. Each batch uses its immediately preceding complete batch root/count.
Permute lane order privately, but freeze the actual resulting body sequence before
reblocking. Publish no lane, reserve-source or owned-index mapping. Public body
order is sufficient for replay. With100,000,000units per source, the current fees
leave `100000000 - 2116775 - 8*2112248 = 80985241` per rolling lane after eight
batches. The current40..50million send range remains affordable through these
eight rounds if both outputs stay in that lane; still check the actual remaining
balance before every split. The reserve has97,883,225units after its credit and
remains untouched.

The original ledger has nine blocks and865genuine proofs:97credits+768ordinary.
Keep the funding block whole, and split only ordinary batches into single-body
blocks in exactly their original order. At the end of batch b, b=0..8, the new
height is `1+96*b`, count is `194+192*b`; final height769/count1730. Every ordinary
body's unchanged anchor is only1..96inclusions old. The reserve's funding anchor
at height1 is absent starting at tip257, while its unspent outputs have survived
768subsequent nonempty blocks. This is a source-derived schedule, not an observed
CP03 root-change, proof-replay or expiry result. Actual replay must compare all
nine original boundary roots/counts and check each successive reblocked root is
different; an unchanged-root empty-block renewal is insufficient.

The smallest proposed private handoff is one backup, not the producer's wallets,
notes, recovered views, paths or membership queries:

1. Start a bounded private byte-holder and private pipes before generating keys.
   Create the reserve wallet, rotate once using the real random ML-KEM key API,
   obtain the rotated public descriptor and export the documented backup before
   constructing its funding receipt. This gives two independently generated
   receiving keys in the backup, not a seed claiming to recover future rotations.
   Send the backup only through a dedicated private pipe to the holder. A proposed
   two-key payload cap is64KiB, tightened from the existing API's16MiB maximum;
   establish actual serialization size in the future reviewed implementation and
   fail closed if it exceeds the cap. Do not silently increase it.
2. Fund the reserve's outputs to that rotated descriptor. The credit payment can
   be constructed with another producer wallet because it has no spending
   inputs; `preparePayment` accepts public output descriptors. Dispose the
   original reserve wallet immediately after the descriptor/backup transfer.
   Dispose all other producer wallets, views and payments after generation, and
   wait for the producer process to terminate. Its success must be independent
   of the still-idle holder. Existing cleanup drops KeyObjects and wipes mutable
   spending bytes but does not prove erasure of JS strings/native objects; process
   exit is required before claiming the original wallet process is gone.
3. Keep only that bounded backup byte payload alive in the holder during resource
   review. Its idle lifetime is distinct from measured generation and node service
   work. No proof work, receipt scan, account lookup or ledger access belongs in
   this process. No file, secret hash, log, environment/argv serialization, crash
   dump or persisted restart token is permitted. Bound private copies/framing and
   authorized deliveries; the future supervisor must account for simultaneous
   holder/consumer copies. There is no physical-memory erasure or host-swap theorem.
4. If resource review retains the backend, start a fresh approved Gate3 wallet
   process and deliver only the backup through a new private pipe. It imports the
   keys with `restoreBackup` and discovers reserve/change notes from the common
   authenticated history, not from a retained note opening, index, old producer
   map or a local-ledger membership response. The holder supplies no witness.
   Endpoint/chain/genesis and the public source's validity delegation must be
   independently specified. Inventory completeness remains the documented
   `unknown`/conditional basis; parsing a backup's self-declared inventory is not
   evidence about omitted random keys.
5. For the full gate, the fresh wallet may reconstruct the old funding witness at
   height1 from common history, retain a bounded selected copy, then follow the
   same common stream through actual changing roots. Submit a genuinely proved
   old-anchor spend and observe atomic expiry rejection; independently establish
   the proof itself is genuine, since ledger anchor rejection may precede proof
   verification. Refresh locally and prove/admit the first new spend. Send its
   wallet change only to a descriptor already covered by this pre-receipt backup.
   Dispose that wallet process. A second fresh process then receives the same
   backup, scans the selected common history including that spend, and proves/
   admits another new spend. A holder bounded to these two authorized deliveries
   can then wipe its mutable buffer and exit. No post-backup unknown key rotation
   or copied recovered-state handoff may substitute for backup-only recovery.

The exact private channel/size/lifecycle supervision still needs source review
before execution. This proposal gives no crash-resumable secret fixture: if the
holder or host dies, the pipe breaks, the backend is rejected or the operator
aborts, close consumers, wipe reachable mutable buffers and terminate the holder.
Public bodies and measurements remain useful, but cannot recover the reserve
secret. A later recovery/expiry run then requires fresh keys and an explicit new
fixture; there is no disk fallback, historical key reuse or deterministic seed
shortcut. Do not extend a keeper indefinitely just to avoid admitting this limit.

## Comparison with a separate257-changing-block fixture

Reusing this future Gate2 workload saves **background Gate3 proof generation**:
zero new history proofs rather than257new ordinary proofs. It does not save the
865proofs already required to create this proposed Gate2 workload, replacement
header construction, actual sequential revalidation/retention of865bodies or the
new genuine wallet/expiry/recovery/branch proofs. Reblocking is a new public-ledger
test, not an extra claim of measured96-body throughput.

For a comparable eight-batch Gate2 baseline,96credits+768ordinary bodies require
864proofs. Reserve reuse adds one credit, for865total. Keeping that baseline and
generating the separate fixture below costs864+259=1123proofs. Reuse therefore
saves258new proofs overall, excluding the same later wallet/branch controls in
both options; the zero-versus257comparison above concerns only ordinary
background proofs, not the complete marginal cost.

A separate post-resource-review expiry fixture can instead use one rolling credit
and one reserve credit in its funding block, then257ordinary single-body rolling
payments. This specified257-subsequent-changing-block scenario needs259history
proofs (two credits+257ordinary), followed by the same new wallet/branch controls.
This is not a universal expiry minimum: the height1 anchor is already absent at
tip257 after256subsequent nonempty blocks. Every rolling payment
uses the latest parent anchor; the untouched reserve's height1 anchor is absent
at final tip258. The rolling credit must exceed544,964,511units to cover its
credit fee plus257ordinary fees and leave a positive final balance;100million is
insufficient for this alternative. This costs new
proofs and a separate history but avoids custody across the resource review and
is simpler to restart. If "257proofs" instead means total including funding, it
does not by itself specify257changing blocks after the reserve is funded.

Neither choice reduces the required security checks. Prefer reuse only if the
eight-batch workload is independently justified by Gate2, the bounded holder is
approved and survives, and actual replay confirms all conditions above. Otherwise
run the explicitly allocated fresh fixture; do not redesign Gate2 solely to make
an expiry demonstration appear cheaper.
