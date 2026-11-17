# Gated local wallet / selective-frontier bridge

Status: source-only contract for a later Root resource decision. This is not an
integration allocation, implemented API or Gate3 result. No canonical source,
producer, transport or profile changes accompany it. The running 864-proof
producer has no reserve/backup keeper and destroys its keys; this document does
not recover its secrets or change that workload.

## Closed work and the remaining boundary

SOURCE02 already supplies the depth-40 selective frontier, discovery-at-append,
bounded rewind/anchor journals, endpoint epochs, empty-block handling and one
active epoch. Its 25 diagnostic controls and the earlier four-block actual-CP03
correspondence are closed component evidence; neither is rerun or called actual
wallet discovery. Network04 parsing/version/empty-cursor compatibility is also
already implemented. REBLOCKING.md is conditional fixture design, not private
recovery evidence. This contract does not repeat those implementations.

Root's separately implemented SOURCE03
(`b0dcf037a98a7f0a4f8f6611088d63e3d652f950c5da8df9c38016781b44792a`)
corrects the prototype's outside-journal revocation. Existing public receipts
`evidence/deep-rewind-regression01.json` and `evidence/structural03.json` report
14 new lifecycle checks and the 25 structural checks passing. This contract only
reads those receipts; it does not rerun them or infer joint opening-map,
inventory-lease, capability-isolation or actual Gate3 integration from them.

The precise new gaps found in current source are:

1. `source/wallet/cp03/recovery.mjs::recoverHistory` has the needed ordered parser,
   contexts and actual receipt discovery, but its block application is internal
   and its public result appears only at EOF. `withRecovered` exposes openings,
   NF, origin, CM and index, not paths. Feeding this EOF result into the frontier
   is too late to register a target at its incoming leaf.
2. `stream.py::State` checkpoints only head/frontier/anchors. It does not checkpoint
   Node's opening/NF/balance state. Current recovery immediately wipes an opening
   on a matching spend; sharing that buffer with a new rewind journal would
   destroy its preimage. A joint private lifetime/commit boundary is missing.
3. The trusted native hash helper and JS wrapper currently expose AUTH, NOTE, NF,
   one statement and statement batches (opcodes 1..5). They return origins/CMs,
   **not TreeLeaf or TreeNode**. The scalar fixture supplies those operations via
   its pinned reference; that is not a current native wallet API. Both operations
   remain a real integration gap, not a request for a ledger membership service.
4. `source/wallet/cp03/cycle.mjs::inputsFor` and `restoreWorker` still obtain paths
   from `client.membership`. Those calls must be replaced in the later acceptance
   path. The producer's latest-block-only fixture optimization is not a substitute
   for complete ordered wallet recovery, spentness or local witness construction.
5. SOURCE02's `WalletWitnesses.rewind` looks up the prefix before abort/revision
   changes. An outside-journal exception therefore does not itself revoke an old
   epoch/view. The bridge must handle authenticated branch selection before that
   lookup; Root's SOURCE03 corrects that isolated prototype lifecycle. Also,
   `keys.mjs::rotateReceivingKey` and `disposeWallet` have no epoch lease guard.
   Binding prepared recipients only once cannot freeze a changing inventory.

## Types and authority

These are logical local types, not new consensus encodings or assigned helper
opcodes. Native wire allocation/installation approval requires later review.

| Type | Required representation / bounds |
| --- | --- |
| `Chain` | 32 bytes; the wallet and actual genesis chain must agree |
| `BlockId`, `GenesisId` | 64-byte typed SHA3 identities; not field digests |
| `Digest` | 64 bytes = eight little-endian u64 values, each `< P`, `P=18446744069414584321` |
| `Height` | u64; JS `bigint`, not floating Number |
| `Count` / `Index` | u64; count `<=2^40`, index `<count` and `<2^40` |
| `Origin`, `CM`, `NF` | canonical `Digest`; occurrence identity is `(origin,CM)`, not CM alone |
| `NoteOpening` | private note160, CM64, memo0..128 bytes; actual decoded note asset/owner/amount checked by receipt adapter |
| `OwnedToken` | opaque local handle; if crossing a private pipe, a fixed 16-byte random identifier, not a note/selection debug hash |
| `Path` | exactly 40 canonical digests = 2560 bytes, level0 first |
| `Head` | `{height,id,count,root}` plus enclosing chain/genesis/version context; map to Python `Head(height,identity,count,root)` without truncation |
| `ValidatedBlock` | `{height,parent,id,count,root,fees,liabilities,orderedRecords}` from the canonical reduced-history parser |
| `AppliedCursor` | `{height,id,leafCount,root,fees,liabilities}` exactly as `recovery.mjs::position`; fees/liabilities are bounded u64 values and part of the joint checkpoint |
| `Owned` | `{token,nf,origin,cm,index,opening}` private map entry; key inventory is referenced from the wallet, not copied into every checkpoint |
| `InventoryLease` | wallet handle identity plus `publicInventory` chain/wallet_id32/version-u64/key_count/inventory_id64; private capability binding, not a secret-key digest |
| `AuthenticatedBranchChange` | independently selected `{commonPrefix:Head,replacement:TrustedContext}` plus monotonically changing local selection revision |
| `WitnessInput` | existing `preparePayment` shape `{note:Buffer160,origin:Buffer64,index:bigint,siblings:Buffer64[40]}` |

The bridge fixes the chain, actual genesis bytes/hash, block version and trusted
tree-hash implementation before intake. Network04 uses depth40, at most128
payments / 256 funded leaves per block, zero allowed explicitly, raw reduced
block cap1,224,804 bytes and header cap8408. Retain current parser's exact body
IDs, reduced proof-digest binding, receipt lengths/digests, encoded-full-size
reconstruction and 256 MiB complete-block limit. Legacy defaults/callers remain
unchanged; no peer header may select the trusted profile.

`TrustedContext` contains actual genesis bytes, independently established genesis
root, chain/genesis IDs/version, target `Head` and a validity/canonicality basis.
For the lab, the target comes from separately validated selected-branch state,
not the scan being consumed. Existing `recoverHistory` only requires height/ID;
the frontier's final `Head` additionally needs root/count. Obtain those from that
trusted head. If only height/ID is independently supplied, fetch the terminal
public header by that common ID before opening the epoch, check its typed hash
against the trusted ID, then extract root/count. That fixed header fetch is at
most8408 bytes and does not depend on owned indices. It authenticates committed
metadata, not omitted payment validity. Do not call the peer's own claimed
endpoint an independent checkpoint.

Reduced history links ordered data to that endpoint. It does not verify omitted
payment proofs, consensus, freshness or availability. Keep the exact existing
delegation label `delegated-to-independently-supplied-endpoint`; no bridge result
upgrades it. For a rewind, the branch controller/consensus supplies an exact
selected common-prefix head and independently selected replacement endpoint.
Matching height, root or count alone does not establish the common prefix.

## Minimal missing local calls

The recommended boundary reuses the existing frontier implementation behind one
opaque local builder capability; it does not introduce a second history parser.
The capability may use a bounded private RAM pipe to the pinned Python code.
No key, decrypted note or receipt recipient KeyObject needs to leave Node. Only
local selected tokens/index mappings and witness paths cross that private
boundary. Do not use a public subprocess logger for these messages.
Its future grammar must be fixed and bounded, not pickle/eval or a callback/
program supplied by history; the discovery callback belongs to installed code.

```text
beginJoint(wallet, TrustedContext, {K,R,A=256}) -> PrivateCandidate
applyValidatedBlock(candidate, ValidatedBlock) -> private success/failure
sealAtExactEOF(candidate) -> unpublished JointView
publishJoint(view) -> opaque RecoveredWithWitnesses
withLocalWitnesses(view, ownedTokens[1..2], selectedAnchor, callback)
rewindJoint(view, authenticatedBranchChange) -> private success | ReplayRequired
abortJoint(candidate) / disposeJoint(view)
```

These names denote new missing interfaces, not exports present today.
`beginJoint` binds a frozen `InventoryLease` and empty tree, or clones the one
current committed joint state for incremental intake under that same lease.
`keys.mjs::publicInventory` already supplies the exact public inventory fields;
its identifier hashes public descriptors/metadata, never backup/key bytes. The
future coordinator must exclusively own the wallet handle during an epoch and
mediate rotation/disposal: reject those mutations while the lease is active, or
revoke the epoch/views/borrows before performing them. Current key APIs do not
enforce this lease; a caller convention alone is not an implemented guard.
Check actual handle/inventory identity at begin, after every async worker return,
and before sealing, publishing, borrowing or preparing/submitting a spend. A
detected mismatch or disposed handle fails closed and disposes the candidate;
it cannot reuse prepared recipients from the old inventory. Rotation requires
new complete authenticated replay under the new inventory, since a newly added
random key may open older receipts. Disposal requires a fresh valid restore/key
source before replay. Neither event returns a complete empty wallet.

Only one candidate epoch may be active; there is one caller-visible committed
view and at most one bounded
witness/draft borrow. Do not expose raw `epoch.state` or Python path dictionaries.

The future internal hook belongs inside `recovery.mjs::applyWindow`, after its
whole-block parsing and complete checked helper context response. Its existing
four/five-argument API can continue producing its old opaque recovered result;
the new joint capability is opt-in and separately reviewed. Sharing the parser
and receiving operations is preferable to copying the fixture reader or making
the caller parse the same scan again.

For each block, enforce this order:

1. Validate its framing, chain, parent, next height, output count and body order
   using the canonical parser. Preserve parser lookahead separately from the
   applied cursor. A complete helper response may cover several blocks, but its
   original statement ordinals must remain aligned with those exact records.
2. Match **all** public block nullifiers against the candidate's previously owned
   NF map, reject duplicates in the block, and stage owned spends. Remove their
   live frontier targets before appending any new leaves. Retain undo references
   to old openings; do not call current recovery's immediate wipe on a buffer
   still referenced by an allowed checkpoint.
   Duplicate sets are bounded: per-block nullifiers at most256, occurrences at
   most256, plus the K live-owned map and declared journal. There is no all-history
   `seenNF`/CORE/receipt set. Complete global replay/source/CORE uniqueness remains
   delegated to the validating source, as in current reduced-history recovery;
   the bridge's local duplicate checks do not establish it independently.
3. For every statement/output ordinal, use actual `contextsBatch` +
   `contextInfo` to derive origin/CM; check `digest(context,envelope)` against
   the canonical parsed receipt. Try all retained receiving keys with actual
   `prepareRecipient` / `collectLocalCandidates`. Their ML-KEM, KDF, KC, AEAD,
   plaintext, owner and commitment checks remain active. The one-block pending
   candidate set is bounded even if many receipts are owned.
4. Associate each opened candidate with its exact `(origin,CM)` occurrence and
   global index `prior.count + 2*recordOrdinal + outputOrdinal`. Reject duplicate
   occurrences/NFs, a candidate NF in `spentHere`, invalid ownership/amounts or a
   K overflow. Assign the opaque token locally. Do not deduplicate equal CM at
   different origins or turn an operational decryption error into a receipt miss.
5. Compute **every** funded leaf, including outputs not owned by this wallet, in
   canonical order. Before appending an owned leaf, register its token at that
   incoming index. In `Epoch.apply`, the discovery callback must return that
   staged token synchronously for exactly this index/value; it cannot return a
   target after append or use an external path lookup. Supply the locally matched
   spent tokens with this same block. Check computed root/count against the
   authenticated block head before recording its joint checkpoint/anchor.
6. Advance tree, owned map and full `AppliedCursor` tentative state together.
   The Python `Head` alone lacks fees/liabilities and is not a complete recovery
   checkpoint. Journal the actual applied values, not a later parsed lookahead
   cursor. Empty blocks advance
   height/ID, the 256-anchor ring and rewind journal, while root/count, owned map,
   fees and liabilities stay unchanged. No receipt context helper call is needed
   for an empty-only window. After the target, require exact EOF, final head and
   stable input-file identity as current recovery does. Close resources and pass
   the approved source/runtime postchecks before publishing one joint capability.

There is no externally visible partial receipt balance or witness. `Epoch.finish`
currently mutates its owner: the adapter must keep that owner private to the
candidate until joint publication, or retain the old committed state until both
sides are ready. It must not publish a Python success while a Node map/cleanup
failure leaves a different head. If a private worker ACK is lost, abort/dispose
the candidate rather than replaying a non-idempotent append. An unrecoverable
worker failure invalidates its capability and requires authenticated replay;
it never returns a complete empty wallet or guesses that commit succeeded.

## Fixed tree hashing gap

Required logical operations are:

```text
treeLeaves(Chain, [(Origin,CM)] <=256) -> Digest[]
treeNodes(Chain, [(level0..39,left:Digest,right:Digest)] <=256) -> Digest[]
```

They must call the existing fixed CP03 Poseidon2 framing and constants:
`source/experiments/compact-payment-v1/src/hash.rs`, reexported by the arity crate.
Leaf is `hash(chain,LEAF=4,origin||CM)`; internal node is
`hash(chain,NODE=5,[level]||left||right)`. Absent leaf is eight zero fields;
the leaf payload is exactly16 canonical field words, and the node payload is
exactly17 (one bounded level followed by16 child words), with chain32 fixed in
the typed framing. Neither payload contains an index or a caller-selected role.
Empty subtree values are derived successively, not supplied by the server. The
semantics match `source/crates/ledger-cp03/src/tree.rs::{append,node,empty}` and
the payment witness relation. No general peer-selected domain/hash program is
accepted. A returned record count/order/length/noncanonical field mismatch poisons
the epoch; no partial native response may update it.

Neither operation exists in current `hash-core.mjs` / `hash-core/src/main.rs`.
Adding a fixed native interface requires a coherent future CORE_MANIFEST/source
closure, reviewed rebuild and new helper/ELF/installation approvals, with current
provider and pre/post pin checks preserved, after the live producer has ended.
Do not substitute an unrelated hash, Node crypto digest or full-ledger path. The
current wrapper spawns and rehashes an ELF per call; assuming one such child per
tree node is cheap would be an unmeasured performance assumption. Bound/chunk the
later local hash work and measure it; this contract does not select or execute a
new persistent helper protocol. The old scalar probe remains correspondence
evidence, not integrated resource evidence.

## Spend, branch and restore lifetimes

`withLocalWitnesses` returns at most two `WitnessInput`s from the same selected
eligible root/count and jointly committed opening map. Check each selected token
is currently unspent, its index is in range, its occurrence agrees, and its
locally folded 40-sibling path reaches that root. Current
`WalletWitnesses.witness()` returns the current head path; it is not an arbitrary
historical-path API. An older draft may keep one bounded saved path/anchor; it
must still pass selected-branch eligibility and unspent checks before submission.

Pass those inputs directly to unchanged `payments.mjs::preparePayment`. Its
owner/amount/shape checks and private packet copy remain valid. A successful
return means the packet owns its required bytes; only then release a temporary
path/opening borrow. Keep the candidate/map buffers alive until that copy, and
never expose the spending key as a bridge message. Continue using unchanged
`provePayment` / `consumePrivatePacket`: one consumer, private stdin only, actual
child termination, packet wipe, genuine proof output and fresh public admission.
The current maximum packet is6544 bytes for arity2 (existing128 KiB upper guard).
Proof failure does not mark inputs spent; only newly authenticated selected
history does. A block or reorg advancing the revision invalidates an in-flight
borrow; a prepared draft is rechecked against the selected state before submit.
The trusted borrow callback is synchronous and cannot retain arbitrary path/
opening copies; `preparePayment` is synchronous today. Reject an async callback
and recheck revision/lease before accepting its result. If authority changed,
dispose any resulting prepared payment before proving rather than publishing it.

The later acceptance wallet and **all descendants** must have an actual denied
capability boundary for every producer, validator, historical fixture and oracle
Ledger DB. Removing the database config field or a `client.membership` call is
insufficient. Isolate filesystem/mount/proc access, close non-allowlisted inherited
FDs and deny network/Unix-socket membership/owned-index routes, including indirect
RPC fallbacks. A known DB pathname, inherited readable FD or reachable membership
endpoint must not remain usable. Keep public body submission and selected-head
admission in a separate controller; return only common history and public endpoint
context. This replaces the current restore worker's DB dependency as well as its
explicit `inputsFor` call.

The future actual run must retain PID/namespace/mount/FD/network-policy readback
covering wallet and helper/prover descendants, and an attempted fixed public
fallback (for example a non-owned test index) that cannot open any denied DB or
obtain a membership response. Check denial of an inherited-handle bypass, not
just `ENOENT` for one pathname. Do not print FD contents or private requests in
that evidence. At the same time explicitly permit pinned source/runtime/helper/
prover dependencies, approved public common data and Parent public output paths;
the boundary must still execute the genuine unchanged private-packet pipeline.
An external full oracle can compare results, but sends no path or note-selection
map into the wallet. These are future acceptance requirements, not a sandbox
already implemented or a claim derived from source inspection.

An **authenticated selected-branch change** first increments the selection
revision, revokes all old current-view/borrow authority, disables new spends and
publication, and aborts any active epoch. Do that before looking for its exact
common prefix in the journal. Invalid/untrusted scan data alone is not authority
to select a branch. A pending proof is marked non-submittable; cancellation still
waits for actual worker termination and wipes through the unchanged private
Parent lifecycle. A prepared/public draft may be reconsidered only after fresh
selected-state validation, not by retaining an old borrow capability.

If the prefix is retained, restore frontier/anchors, private opening/NF/balance
map and full applied cursor (including fees/liabilities), remove orphan discoveries
and undo owned spentness. Reset the parsing cursor to that same prefix and discard
all old-branch lookahead/window buffers; any resumed source/offset must belong to
the selected authenticated stream, not an orphan file position. Otherwise an
empty replacement block can be checked against orphan fees/liabilities despite
having the correct tree root/count. Re-enable a
current view/spending only after the selected replacement endpoint has been
independently authenticated, completely applied and jointly published (or the
trusted target is exactly that common prefix). If the prefix is outside R,
`ReplayRequired` leaves the coordinator explicitly replay-required/unavailable:
no old spendable view, witness, epoch finish or current-view publication remains
authorized. Dispose abandoned candidates and rebuild from genesis under the
selected context and frozen inventory. It is insufficient to discard only a new
candidate while the old committed view stays usable. Another branch change
during replay revokes that replay revision too.

Checkpoint references keep spent notes alive while rewind may restore them.
Wipe openings only after the last live view, journal, candidate and allowed borrow
reference is released. R is separate from anchor window A=256; no owned-index
request, secret disk checkpoint or old producer mapping is a fallback. The
inspected SOURCE02 outside-R lookup/abort ordering does not satisfy this
selection-revocation contract. Root's SOURCE03 and its named diagnostic receipts
now address that isolated ordering; they do not implement the joint cursor,
opening/inventory lifecycle or process boundary specified here.

For backup restore, the existing `keys.mjs::{exportBackup,restoreBackup}` remain
valid. The documented private bytes contain spending secret plus independently
random ML-KEM receiving keys/descriptors and inventory version. Existing cap is
16 MiB /1024 retained keys; an acceptance fixture must declare any tighter bounds.
Back up after the needed random rotation and before the receipt, dispose the old
wallet/process, then restore in a fresh process from only those bytes and the
documented public chain/inventory context. Derive receipts/NFs/frontier/paths by
replaying common history anew. No stored opening, witness, note index, old wallet
DB, or post-backup secret may accompany it. Independent expected inventory gives
only the existing conditional completeness basis; an unknown later random key
cannot be reconstructed from a seed or self-declared inventory. No Gate2 keys
are retained for this path.

## Explicit bounds and failure examples

Declare K (live owned notes), R (rewind blocks), key inventory, candidate intake
and caller-held draft bounds before an actual run. SOURCE02's K=4/R=8 controls are
not production requirements. Keep at most one active epoch and one witness/draft
borrow. The union of committed/candidate journals is bounded by two `(R+1)`
checkpoint sets, plus fixed current/view work; reference sharing can reduce that
but must not be assumed as an RSS measurement. A conservative state bound is
`O((R+1)*(D+K*D+A+K*openingBytes))`, including journaled openings/maps, plus fixed
intake, keys, one packet and one bounded private bridge response. Python/JS object
overhead and duplicated pipe buffers are additional and must be measured.

Keep current intake at most256 statements and256 blocks per window; a block has
at most256 pending discoveries/leaves. Drain or discard that pending set before
the next block, rather than retaining openings for every lookahead window.
Cap bridge messages by those widths; apply backpressure, not an unbounded queue.
K overflow fails the whole candidate; never silently skip a received note.
No O(N) public tree/leaf vector enters the algorithm.

With the internal one-pass hook, no funded-leaf spool is required. If only the
current EOF discovery API is reused instead, a second complete common-history
pass is mandatory, with its bytes/time/availability priced. A public leaf-only
spool costs64N bytes plus block context (12.8 decimal GB/year at200M leaves), as
already noted in README; it is not a free alternative or a selected-leaf fetch.
Common-history requests must be independent of ownership. No selected token,
index, NF ownership map, witness, unique subtree or receipt-hit pattern leaves
the wallet for a server. A local full oracle may compare results outside the
wallet, never supply its paths. Network/IP anonymity remains separate.

Concrete contradictory cases that constrain the bridge:

- A window can contain block h with a receipt and block h+1 spending it. Register
  it at h before append, then forget it at h+1. Waiting until EOF loses the moment
  to build its path; applying all window nullifiers before all discoveries instead
  can resurrect an already spent note.
- A note spent on an orphan branch can become unspent at the selected common
  prefix. If its shared opening was wiped immediately, rewinding only Python's
  path journal cannot restore a spendable wallet. Conversely an orphan-only
  discovery must disappear even if its old path still folds to the orphan root.
- A final EOF/endpoint mismatch after valid early receipts aborts the joint
  candidate. No early balance or path escapes. A stale epoch cannot overwrite
  a rewind selected while native work was pending.
- A branch change with a prefix older than R must revoke the active epoch and
  old witness authority even though journal lookup fails. Catching
  `ReplayRequired` and continuing to spend from the former tip violates selected
  branch authority. This differs from a malformed scan that never selected a new
  authenticated branch.
- Rotating to key2 while an async epoch retains recipients for key1 can miss a
  key2 receipt yet report complete recovery. Freeze the inventory or revoke and
  replay; the existing key-rotation API alone does not prevent that race.
- A replacement starts with an empty block at a common prefix. Retaining the
  orphan tip's fees/liabilities while rewinding only Python `Head` can reject the
  valid empty block or check it against the wrong state. Restore the complete
  applied cursor and discard lookahead, not just root/count.
- An old-branch draft whose inputs and `(root,count)` are in an eligible selected
  common prefix need not be rejected merely for its origin. Orphan-only funding
  or an absent/expired anchor does fail. At tip t the ring covers t-255..t;
  unchanged-root empty blocks may renew the same wire anchor and do not establish
  changing-root expiry. Actual new proof/rejection/refresh/spend remains required.

Parse/helper/native/cleanup failures use fixed typed private failures and dispose
candidate resources; they do not log, hash or serialize a note, key, backup,
selection, witness, raw private stream or diagnostic exception containing bytes.
An empty wallet is returned only after complete successful intake, never as an
error fallback. This contract leaves implementation, fresh installation, actual
receipt/witness/proof/expiry/reorg/backup acceptance and integrated memory/traffic
measurement explicitly gated on Root's resource decision.
