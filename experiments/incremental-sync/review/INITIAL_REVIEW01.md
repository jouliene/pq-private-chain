# Incremental synchronization: independent acceptance boundaries

Source-only review, 2026-11-18. The reviewer does not implement the serving or
wallet path. No new proof, native test, build or historical campaign was executed.
Root owns exact source freeze, allocations, Git, acceptance and publication.

Read the complete INCREMENTAL_WALLET_SYNC_GOAL.md, shared/canonical AGENTS,
RESOURCE_DECISION, POST_GATE3_INVESTMENT_DECISION and current serving/recovery/
joint-witness code. The old milestones remain closed evidence, not new execution.

## Concrete seams and required contract

1. `recoverLocalWitnesses` currently authenticates its private base by encountering
   the exact cursor again in the full stream. Removing that prefix must replace
   this check with the session's own previously authenticated JOINT checkpoint,
   not a supplied cursor/native-state import. Bind chain, genesis, block version,
   height/id/root/count/fees/liabilities. Cursor provenance is not established by
   well-formed bytes or a matching root alone. A request is a detached public copy;
   applying its reply must derive/check the private base again.
2. `Ledger::scan_frame(height)` already performs indexed header/reduced-record
   queries. New range serving must use these or equivalent direct queries, not
   `export_scan` followed by slicing. Include base/end lookup and bounded startup
   reads separately in counters. `Ledger::open` reads genesis/registry/tip/tree
   metadata, including tip body lengths; these are not zero work or prefix scan.
3. Apply first to a private bounded candidate. Exact selected endpoint, EOF,
   accounting cursor, lease/revision and cleanup must all pass before joint
   publication. A malformed tail after an entire parser window is decisive:
   early receipt discovery or spentness deletion must not leak into committed
   state. Preserve the prior state on ordinary interrupted append. On selected
   branch change, old views/drafts stay revoked even if replacement fails.
4. Proposed 432B request/response headers are arithmetically coherent: 8B magic,
   two u16 fields, chain32, genesis64, two160B cursors and u32 count. Count must
   exactly equal target-height minus base-height with explicit supported bounds.
   Request and response domains differ; an empty range requires exact full-cursor
   equality, not merely equal heights. Preserve existing canonical block bytes.
5. A page endpoint supplied by the server is NOT authenticated merely because it
   links forward from a trusted base. If a total256-frame cap creates pages,
   preserve one tentative candidate until the originally selected endpoint and
   final EOF, or supply a separate justified authority for intermediate heads.
   Simpler: stream a bounded-per-frame/window range with an explicit total range
   bound, without implying a256-block total cap from the256-record parser window.
6. Same-head fast path is valid only for ready state, exact full cursor/identity
   and a live inventory lease. It must not reactivate selected-replay/deep-replay
   state. No file read or new packet/revision churn is necessary. Empty blocks
   still advance height/anchors and cannot change root/count/accounting.
7. Server request bytes must depend only on common base/target, never ownership,
   recipient inventory, selected paths or target notes. Same endpoints with two
   distinct wallets must produce byte-identical public requests. No membership
   RPC, DB mount/FD or child network escape is admitted for the private actor.

The authors proposed retaining the old committed image REVOKED until replacement
commit, rather than wiping it immediately at branch selection. This can preserve
failure atomicity without making the old branch spendable. selectedBase must stay
private and live, repeated selections must not accumulate snapshots, and every
view/draft/prepare entry point must reject the revoked mode. A deep selection
requires explicit genesis replay; no stale capability survives a missed lookup.

## Minimal decisive validation, not another large proof campaign

| Directive validation | Actual evidence needed |
|---|---|
| 1: state equivalence | On the NEW genuine small fixture, incremental and full-reference sessions using the same key inventory compare cursor, live discoveries/unspent notes, origins/indices,40 siblings, anchors and accounting IN RAM. Emit only fixed booleans/counts, no private state or its digest. Public long-trace target/path comparisons are separately labelled structural. |
| 2: receive/spend | Fresh keys, actual receipt opening and local witnesses after an append-only update; create a new complete proof and genuinely admit it. |
| 3: backup/new spend | Backup after relevant random rotation before receipt; original process actually exits; fresh isolated process restores only backup/public inventory/genesis/common history and proves/admit a new spend. Charge its full scan. |
| 4: expiry/branches | Reuse full01's genuine changing-root trace and old public drafts for suffix/anchor/linkage checks. NEW small private fixture exercises shallow replacement/joint undo plus deep selection/replay, followed by valid retained spending. Explicitly distinguish long public structural expiry checks from an actual newly generated private expiry-refresh spend. Root must settle this combined scope before execution, not relabel a public surrogate as receiving. |
| 5: malformed continuation | Wrong full base, chain/genesis/version, endpoint, count, omitted/swapped/duplicate frames, truncated prefix/body/tail, trailing bytes; include same-root different-height and altered accounting. Fail after at least one entire candidate window and compare committed state privately. |
| 6: interruption/retry | Writer interruption plus wallet truncated-file failure, retry the exact range successfully once, then unchanged-head no-op. No cursor advance, duplicate notes/spentness, or leftover output falsely published. |
| 7: stale capabilities | Old view and pending packet after shallow/deep branch selection fail; a delayed reply with a different recomputed base/selected endpoint fails. Byte-identical common public data matching both may be revalidated but never revives old capabilities. Revoked state remains blocked after invalid replacement. Failed ordinary append without branch change preserves its previous ready state. |

A candidate bounded genuine fixture needs seven proofs rather than264: two
credits, receiver payment, branch spend A creating a receiver output, positively
admitted orphan child, alternate common-prefix spend B, backup-restored spend A.
Rollback child and parent, install alternate branch, reject orphan child's
anchor. The original A transaction can also be positively re-admitted and rolled
back on the alternate branch to establish common-prefix eligibility. R=1 allows
an actual deep selected-genesis replay without extra proofs. Root owns the final
scenario and must check amounts/fees/selected-note ordering before allocation.

The old public full01 closure cannot restore its destroyed private keys. Using
new keys against that trace cannot prove nonempty owned-note discovery/path
state equivalence. Keep that boundary explicit. No new264/864 regeneration is
justified solely to obtain a longer public append trace.

## Scaling and completion gates

Use fixed genuine public prefixes (for example32,128,260 blocks) and the same
append partition schedule. Record exact request/response bytes, directly fetched
header/reduced bytes/rows, blocks authenticated, and startup work. For ordinary
appends, sum of served/authenticated suffix blocks must equal total new blocks;
constant framing/base/end queries are reported per request. Returning a small
response while reading the old prefix fails. Charge warm-up, oracle preparation,
reorganizations, replay, retries and cold recovery separately, not as free or
as ordinary append work. Measure CPU/wall/peak-memory scope and bounded retained
journal/state; no private state hashes. One unchanged-head repeat verifies zero
history reads/authentication, not just zero returned records.

Completion1 requires the real serving + wallet paths. Completion2 requires the
above measured counts, not timing ratios. Completion3 combines genuine small
payment/recovery/branch execution and explicitly scoped long public history.
Completion4 requires adversarial controls on changed boundaries. Completion5
requires this non-implementing reviewer to execute a clean-build decisive suffix
trace and a fresh genuine private cycle after allocation, inspect actual receipts
and source/runtime correspondence, with old checkout/DB/private inputs excluded.
Completion6 remains Root's actual CI/commit/publication gate. None is currently
passed by this source proposal.

Do not weaken payment parameters/verification, endpoint delegation, isolation or
inventory assumptions. Incremental history does not fix first-copy175TB/year,
remote pruning, availability/bootstrap, consensus or the missing whole-protocol
privacy/PQ argument. Stop at the directive's accepted synchronization result.

ABI clarification with wallet author: no additional opaque request-plan token is
required. Public request/response bytes carry no private authority; synchronize
recomputes the session-owned base/selected endpoint and guards its active revision.
A valid identical public replay after branch selection can create a NEW view only
after full validation. Zero-block selected replay still validates header and EOF;
it is not the ready-mode no-op.
