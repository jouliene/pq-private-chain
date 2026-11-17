# Joint local witness integration candidate

Source implemented; not executed with native op6, fresh proofs or acceptance yet.
Root owns the new reviewed installation, capability-denied wallet process,
public admission controller and real expiry/reorg/backup fixture. Existing
SOURCE03 Python controls remain separate evidence and are not rerun here.

## Caller contract

Import these modules only from the approved installation's `source_root`:
`wallet/cp03/keys.mjs`, `payments.mjs`, `local_witnesses.mjs`. Current helper ABI is
fixed `treeAdvance`, not an arbitrary hash/provider callback. Its continuation is
unpadded; root/paths come from its padded clone and native path folds. The opaque
state cannot be imported through this coordinator, exported or used as backup.

```js
const session = createLocalWitnessSession(wallet, helperSha256, {
  trustedGenesis: {chain, genesisId, blockVersion: 4},
  genesis: genesisBytes, genesisRoot, maxOwned: 8, rewindBlocks: 8,
});
const recovered = recoverLocalWitnesses(session, scanFile, selectedHead,
  'unknown'); // or conditional-on-independent-current-inventory
const prepared = withLocalWitnesses(recovered.state, 1, {
  outputs: [{descriptor: destination, amount: send},
            {descriptor: backedUpChangeDescriptor, amount: change}],
});
// Unchanged provePayment -> completeBody -> public controller admission.
// Do not refresh/select a branch until a wanted proof and body are collected.
await disposeLocalWitnessSession(session);
disposeWallet(wallet);
```

`selectedHead` and each branch prefix/endpoint are the **full actual native head**:
`{chain:Buffer32, genesisId:Buffer64, blockVersion:4, height:bigint,
blockId:Buffer64, leafCount:bigint, root:Buffer64, feeEscrow:bigint,
unconsumedLiabilities:bigint}`. They are independently selected by the declared
validating controller; the reduced scan does not establish payment validity,
consensus/freshness or availability. Delegation labels remain unchanged.

A session freezes the actual key inventory until **awaited session disposal**.
`rotateReceivingKey`, `disposeWallet` and a second session for that wallet reject
while leased. The lease binds handle, chain/wallet identity, version/key count/
public inventory identity and installed helper SHA. It contains no copied key
inventory. Keys must already include every independently random rotated key
required by the selected history; backup restore uses unchanged `restoreBackup`.

`recoverLocalWitnesses` returns an opaque view and the explicit receiving/
delegation labels. It publishes only after exact EOF/cursor/root/count, input
stability, recipient cleanup and lease/revision checks. It uses the shared
canonical public history parser, genuine receipt adapter and fixed native tree
bridge, never a local Ledger path API. The actual wallet/descendants must still
be denied all ledger DB/FD/membership capabilities by Root's harness.

To stop initially at a prefix, supply a common scan ending at **exactly that
prefix EOF** and its full selected head. Later supply the full common scan from
genesis and the later selected head. The implementation reparses the whole scan,
checks the saved full prefix cursor, and applies only its suffix to the continued
frontier. This is bounded-memory continuation with **complete history reread
traffic/time**, not a suffix-only or constant-traffic recovery API. Price every
read; do not offer a selected-note/subtree fetch as an optimization.

## Private inspection and payment lifetime

`inspectLocalWitnessView(view, syncOperation)` provides ephemeral private
`{head,balance,notes:[{token,index,amount,origin,cm}]}`. It never returns an opening
or path. All token/origin/CM copies are wiped on callback return. No logging,
hashing or persistence belongs in this trusted callback. Async functions and
thenable results are rejected. Retained amounts/other caller copies are outside
the erasure claim; use the fixed bounded acceptance caller.

`withLocalWitnesses(view, selection, {outputs})` accepts a count1/2 or a trusted
synchronous metadata-only selector returning one/two token16 buffers. It calls
`preparePayment` itself and returns that branded prepared payment. There is no
external operation callback receiving notes/paths or allocating an unknown
packet. Fresh zero-leaf native derivation checks current root/count/token/index
and native-folded paths before a private borrowed copy feeds `preparePayment`.
Returned statement chain/anchor/arity/NFs must match those selected entries.
Borrowed copies are wiped after the synchronous packet copy.

The session tracks **one** prepared payment. A second unconsumed/in-flight one
is rejected. Caller `disposePayment` can discard an unconsumed payment; an already
consumed handle is retired before the next prepare, so collect its public body
first. `paymentLifecycle` exposes only used/inFlight/retired booleans, no bytes.

Branch change, successful refresh or session disposal retires the tracked
payment. Pending unconsumed packets wipe immediately. An active consumer becomes
non-submittable, but its packet is not wiped while the unchanged awaited private
operation is active. Retirement waits for `consumePrivatePacket`'s existing
finally after that operation/actual approved Parent termination, then wipes,
deletes and resolves. The pending slot stays occupied while it drains. Existing
`disposePayment` rejects an active consumer. Session disposal revokes logical
capabilities immediately and releases the key lease only after retirement settles.
Always await it. This is not a general asynchronous child-cancellation proof:
current `provePayment` uses synchronous spawn inside an async boundary. Its fixed
callback still owns actual child waiting, provider/source checks and cleanup.

For old-anchor rejection, create and genuinely prove/assemble one public draft
at the old selected prefix, leaving inputs unspent. The private packet is consumed
and wiped. Retain that **one public body/statement/proof**, not a saved secret
witness. After later real changing-root history, `localDraftEligible(session,
statementBytes)` checks selected anchor eligibility and owned unspent NFs. It is
not a verifier. Root's public controller must establish genuine proof validity,
observe atomic expiry rejection, then use a newly prepared current path/spend.

## Rewind and bounded private state

`selectLocalWitnessBranch(session,{commonPrefix,endpoint})` takes full independently
selected heads. It immediately revokes revision/view/borrow/payment authority
before journal lookup. An in-journal prefix restores native continuation,
openings/NFs, complete fees/liabilities cursor and anchors from independent
mutable copies. Replacement history still needs full authenticated replay before
any view is spendable. Outside R throws `LocalWitnessReplayRequired`, wipes the
old state and leaves only replay-required authority. The next recovery rebuilds
from genesis toward that exact selected endpoint. No old view can inspect/spend
or authorize a draft meanwhile. Eligible common-prefix drafts are reconsidered
by NF/root/count, never rejected merely for old-branch origin.

MaxOwned is1..64; rewindBlocks0..64 (declared experimental bounds, not production
requirements). A block has at most256 leaf/candidate records. Duplicate sets are
per-block/live/journal only. The recent anchor ring is256, independent of R.
Native state is at most173248bytes. Checkpoints deep-copy both native state and
owned opening/path buffers, so spending/wiping the current copy cannot corrupt
allowed undo. Keep only R+1 private checkpoints per committed/candidate history,
one active candidate, one exposed view and one borrow/prepared packet. Invalidated
view handles retain no old state. Global token generation uses a session-private
random prefix plus monotonic counter and never resets on replay, avoiding token
reuse without an all-history set. JS strings/GC/native keys have no erasure theorem.

`joint_controls.mjs` supplies source-only focused assertions for **real approved
module namespaces and handles**: lease mutation/second-session rejection, stale
view and replay revocation, sync inspection, refusal of operation callbacks and
one pending packet. It generates no keys/proofs and runs nothing on import; these
assertions have not been executed. Actual receiving, owned-note joint undo,
changing-root expiry, backup-only new-process spend and capability denial remain
Root's genuine fixture and independent acceptance obligations.
