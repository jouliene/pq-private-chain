# Stateless whole-block wallet tree boundary

Disposition: **GO for an exact bounded interface and later implementation review**.
No structural blocker was found in using one fixed native `treeAdvance` call per
block/genesis instead of a persistent Python worker. This is source review only:
no helper build, private input, proof, or new native performance measurement was
executed. Actual Gate2 accepts the finite, costly full-RETAIN research model;
it does not implement this wallet boundary or establish Gate3 acceptance.

Reviewed: current `hash-core/src/main.rs`, `hash-core.mjs`, canonical
`recovery.mjs::applyWindow`, `ledger-cp03/src/tree.rs`, SOURCE03 `stream.py`, and
`BRIDGE_CONTRACT.md` SHA256
`41ac77e6326a318343f6ac9ea5fc7c046344173157a827b1a85054788cd88107`.
The contract's Python-worker wording is a proposal, not a requirement to keep
that process. Its joint-state, inventory, branch and capability obligations remain.

## Necessary interface invariants

1. **Continuation is unpadded.** Serialize the live prefix forest and partial
   target siblings; produce current paths/root from a temporary padded clone.
   Never serialize the result of `view()` back as continuation. Concrete failure:
   discover leaf0, project the count1 tree, then append leaf1. Saving the padded
   empty right sibling as a completed live sibling either rejects the real leaf1
   or retains a false path. Two targets awaiting the same right subtree must both
   receive its completed value. Forgetting one must not delete the other's work.

2. **Decode a canonical bounded state, not a generic object graph.** Fix depth40,
   K64 and at most256 incoming leaves. Check all arithmetic before allocation,
   count through `2^40` inclusive, field words `<P`, exact EOF/version, forest
   ordering/alignment/nonoverlapping dyadic coverage of `[0,count)`, unique
   token/index entries, and path-presence masks consistent with completed sibling
   intervals. Check the full-tree boundary explicitly. Do not serialize hash
   callbacks or a mutable dependency graph. `wanted` can be derived from target
   indices, count and unresolved path slots; omitting it removes a redundant
   consistency obligation. Arbitrary externally supplied checkpoint bytes are
   not an authenticated wallet bootstrap merely because parsing succeeds.

3. **Bind native state to the local wallet capability.** Node privately retains
   checkpoints together with chain/genesis/profile, exact applied cursor,
   inventory lease and selection revision. No public getter, log, digest or disk
   backup exposes opaque state, token/index mappings or paths. Native validates
   the state/request chain and computed prior/new root/count; Node validates them
   against its joint checkpoint and exact parsed block. Native tree arithmetic
   cannot decide selected-branch validity, receipt ownership or completeness.

4. **Preserve real receipt order and identity.** Match block nullifiers to the
   existing owned map first, remove exactly those local live targets, then append
   every public `(origin,CM)` occurrence in canonical order. Discover only at that
   incoming index, never by later registering an arbitrary old index. Reject
   duplicate tokens/indices, unknown or repeated spent handles, target mismatch
   and K overflow. Node validates actual receipts and token-to-opening/NF mapping;
   native must not interpret a peer-selected token or supplied path as authority.
   Empty blocks have no spends/discoveries and preserve tree state; Node still
   advances height, anchor eligibility and the complete cursor journal.

5. **Use the exact payment tree.** Absent leaf is eight zero fields. Funded leaf
   is CP03 LEAF role4 over16 words `origin||CM`; NODE role5 hashes17 words
   `level||left||right`, level0 first, under the fixed chain. The current approved
   helper exposes only opcodes1..5 (AUTH/NOTE/NF/statement/batch), so this is a real
   new fixed opcode and approved helper build, not an existing API. Existing
   opcodes/receipt behavior remain compatible. Validate selected paths against
   their actual owned occurrence and common root before spend; do not label an
   untested native port equivalent solely because it follows the Python design.

6. **Atomicity remains in Node.** A complete successful child response only
   updates the private candidate. Exact history EOF, endpoint, process/resource
   cleanup and source/runtime postchecks precede joint publication. Journal copies
   are owned, not aliases into a mutable request/output buffer. Openings survive
   while a permitted checkpoint/borrow references them. Authenticated branch
   selection revokes old epochs/views/borrows before journal lookup; deep rewind
   stays unavailable until a new selected replay. Inventory mutation/disposal is
   guarded and checked around helper returns and publication/spend. The helper
   never repairs a failed candidate by returning an empty wallet.

## Concrete sizing and acceptance boundary

The existing wrapper caps request/response at135723/82434 bytes. Merely64 full
depth40 paths require163840 bytes, before tokens, forest, input leaves or a second
state copy. Therefore the current caps/decoder cannot implement this proposal.
Define exact new mode-specific maxima from the frozen serialization; bound native
allocation and Node capture consistently. Keep old mode bounds and typed failure
behavior intact. Current five-second child timeout and per-call ELF hashing are
operational costs to measure, not evidence that whole-block work fits. Include
empty-tree construction, projection, process startup, validation, capture copies
and journal copies in actual resource accounting.

No separate general LEAF/NODE API is required if the fixed tree operation performs
them internally. An optional smaller response can return checkpoint/root/count
per block and project only up to two requested paths at spend using a fixed
zero-append projection mode. This reduces repeated response duplication but adds
an operation; it is not necessary for safety or automatically the better design.

The required controls are discriminating: canonical malformed-state rejection;
round-trip continuation after projection; multiple waiting targets; removal and
rewind; empty and capacity boundaries; actual CP03 root/path correspondence; and
joint failure/revision/lease controls. Reuse closed Python evidence rather than
calling another diagnostic port test actual wallet acceptance. The genuine wallet
must still run with DB/filesystem/inherited-FD/proc/network membership capabilities
denied for itself and descendants, with negative fallback attempts and actual PID
readback. External oracle comparisons may supply no witness or owned-index map.

No material contradiction requires abandoning this boundary. Exact wire review,
native-port review and actual isolated receipt/witness/proof/restore/branch/resource
evidence remain necessary before any Gate3 acceptance.
