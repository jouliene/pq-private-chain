# Early wallet witness discriminator

Open question: can common authenticated history drive discovery, local witness
refresh and branch rewind without an external owned-index/path query or a hidden
full-ledger path oracle? This work is the cheap algorithm boundary allowed before
the backend resource decision. It does **not** satisfy Gate3's actual wallet,
genuine spend, accepted-anchor expiry, backup or reorg acceptance requirements.
Canonical wallet/proof/ledger code is unchanged.

`stream.py` has no file/network/ledger API. Its inputs are bounded ordered public
funded leaves, block context, local discovery tokens and locally matched spend
tokens. It hashes public tree digests, never selection metadata. A new target is
registered when its leaf arrives, so completed left siblings come from the
append frontier. Future right siblings are captured as subtrees complete.
`view()` pads a clone; it does not consume or mutate the live frontier. There is
no historical leaf vector or oracle-path callback inside the algorithm.

Block changes remain tentative until the independently selected endpoint matches.
Ordering, parent identity, count and root mismatches poison the epoch and discard
its working references; committed state is unchanged. Discovery/opening cleanup
in the future real wallet must additionally wipe newly allocated private openings.
A revision check prevents a stale in-flight epoch from overwriting a branch change.

## Bounds and recovery costs

Let D=40, K be a declared live owned-note cap, R the private rewind depth and
A=256 the retained anchor window. Current frontier/path/waiting-reference state
is O(D+KD); no O(N) public tree is hidden in it. Non-consuming views temporarily
copy O(D+KD) state. The simple private checkpoint journal costs conservatively
O((R+2)(D+KD+A)) state/references, plus shared empty subtrees and fixed block intake.
Only one active epoch is permitted. Finished/aborted epoch handles release their
working state/journal; valid rewind aborts the in-flight epoch. Caller-held view
copies and proof buffers must also be bounded by the eventual integration; this
is not a claim against arbitrary caller allocation or Python memory erasure.
This deliberately pays for rollback rather than assuming it is free. Digest
payloads are64bytes for CP03; Python object/set/dict overhead is additional.
The controls use K=4,R=8, not an owner-approved production wallet limit. Capacity
overflow aborts the entire epoch; no received note is silently dropped.

The recent public anchor ring and private rewind journal are separate. Rewind to
an exact known common-prefix head restores discoveries, unspentness and paths;
orphan-only targets disappear. Rewind outside R raises `ReplayRequired` without
changing state. The supported fallback is authenticated common-history replay
from genesis (or an explicitly trusted retained wallet checkpoint), not a node
membership request. The initial key-only backup has no frontier/checkpoint and
cannot skip historical reconstruction merely because old anchors expired.

With in-stream receipt discovery, one pass suffices and no funded-leaf spool is
needed. If integration keeps the old API that only returns discoveries at EOF,
it must declare a second pass: either refetch the same common history, or spool
**all public funded leaves**, not selected paths. A leaf-only spool costs64Nbytes
plus block identity/count metadata, i.e.12.8decimalGB/year at200Mfunded occurrences.
That is in addition to receiving history, private note/key state and undo. It is
not175TB/year of proof bodies and it does not remove archive/availability costs.
This prototype implements the one-pass interface; it does not implement or claim
to measure a durable spool, annual wallet service or simultaneous-tree RSS.

Anchor eligibility uses the wire's `(root,count)` on the selected recent branch,
not a transaction's alleged origin branch. At current tip t, the retained set is
heights `max(0,t-255)..t`, matching inclusion in the next block. An old branch
draft can remain eligible if its common-prefix funding/anchor remain selected
and its nullifier is unspent. Orphan-only funding/anchors are rejected. Advancing
unchanged roots could reintroduce the same wire anchor; the diagnostic expiry
control appends leaves and changes roots at every height instead.
The explicit `allow_empty_blocks` option supports Network04 head/anchor/journal
advance while preserving root/count and owned spentness. It defaults false for
the legacy diagnostic contract. Actual empty fee/liability and wire checks belong
to the canonical authenticated history adapter, not this tree-only prototype.

## Executable cheap controls

```sh
python3 -I experiments/network-feasibility/wallet-witness/controls.py \
  --output /absolute/new/structural-result.json
```

The public generator and full sparse oracle are in `controls.py`, outside the
algorithm. They intentionally use a **diagnostic hash, not CP03**, for260changing
roots. The original18named SOURCE01 controls check dynamic late discovery, refreshed paths, spent
removal, policy eligibility at heights256/257, branch replacement, orphan-only
versus common-prefix drafts, stale epochs, malformed ordering/count/roots,
endpoint atomicity, capacity and explicit deep-replay requirements. Passing this
control does not demonstrate actual ledger expiry/reorg rejection or new proofs.
`evidence/structural01.json` is an actual successful cheap SOURCE01 control result.
SOURCE01 and its exact bytes/results are preserved in the Root checkpoint and
`evidence/cp03-correspondence01.sources/`. SOURCE02 adds explicit empty-block,
single-active-epoch and released-state controls; it must use a new result label.
The old result does not claim execution of those successor controls.

The separate short fixture bridge uses actual CP03 hashes and the existing
published genuine public bodies:

```sh
python3 -I experiments/network-feasibility/wallet-witness/cp03_fixture.py \
  --output /absolute/new/cp03-fixture-result.json
```

It verifies fixed public-input identities, complete body/proof-digest/header
binding, chain/parent/order/count, the independently published endpoint and the
actual Poseidon2 roots/paths. Its full oracle is harness-only. Public diagnostic
selections are not real receipt discovery; no private key is read and no new
proof is generated or admitted. Hash linkage does not establish payment validity,
consensus, freshness or availability. Those remain delegated to the declared
validating source; published fixture provenance is retained in the result.
Do not run a long scalar Poseidon history to simulate resource acceptance.

## Gated actual wallet integration API

Only after Root provisionally retains a backend/participation model:

1. Add an internal fixed witness-builder hook inside `recoverHistory`'s ordered
   block/window application. Match public nullifiers first; locally open receipt
   envelopes using the retained receiving-key inventory; register a selected
   occurrence before appending its public leaf. Feed every funded leaf, not only
   selected ones. Publish the recovered wallet and witnesses together only after
   final endpoint authentication. The parser/version/count/byte bounds remain the
   transport adapter's responsibility; this CP03 fixture reader is not that adapter.
2. Replace `cycle.mjs::inputsFor` calls to `client.membership` with a private
   `withLocalWitnesses(recoveredView, selectedEligibleHead, operation)` capability.
   Return the existing `{note,origin,index,siblings}` shape to `preparePayment`.
   Keep all complete relation/prover/public-admission checks; forbid the old
   membership API in the acceptance test. A fixed Rust tree-hash/builder bridge
   is required: the current hash helper has no general tree-node opcode. Do not
   turn a Python/hash callback or producer code into a verifier-selected program.
3. Bind witness state to chain/genesis/selected branch, exact root/count and
   funded occurrence. Keep a bounded private undo journal with explicit lifetime
   of spent/orphan openings: do not wipe data still needed for allowed rewind;
   wipe new abandoned discoveries and expired last references. Keys stay in the
   wallet key inventory, not duplicated in each checkpoint. No private snapshot,
   mapping, witness or debug digest is logged/published by the acceptance runner.
4. In a new restore process, the documented backup supplies the spending secret
   and **all independently random rotated receiving keys/descriptors** needed for
   the selected history. Retain independent current public inventory/chain/version
   metadata and replay common receipt/nullifier history. A backup predating an
   unknown random rotation cannot recreate that key; this is not mnemonic recovery.
5. Actual Gate3 must prove/admit an old unspent note after more than256real
   changing-root blocks, observe the old anchor's real rejection, then refresh
   locally and spend. Actual branch control must reject orphan-only funding or an
   ineligible anchor, retain an eligible common-prefix draft, rewind spentness and
   discover replacement receipts. Only genuine new proofs/admissions and a fresh
   backup-process spend can close that gate. The cheap model controls above cannot.

Common-history requests must be independent of ownership: no owned index, unique
subtree or equivalent hint leaves the wallet. The local full ledger is allowed
only as an external test oracle. Network/IP metadata anonymity, full consensus
and hostile-host protection remain separate unimplemented obligations.
