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

## Exact opcode6 proposal follow-up

The proposed `CPTRQ006`/`CPTRST06`/`CPTRP006` grammar resolves the sizing and
continuation questions at the design level. Its bounds calculate exactly:

- State: `64 + 40*80 + 64*(96 + 40*64) = 173248` bytes.
- Entire request: `41 + 24 + 173248 + 64*16 + 256*152 = 213249` bytes.
- Response: `92 + 173248 + 64*2584 = 338716` bytes.

Index-sorted target records, exact completed masks determined by sibling interval
end versus count, derived waiting references, lexicographically sorted unique
existing forget handles, and rejection of token reuse even when forgotten in the
same call make this a concrete canonical grammar. Stored target leaf digests and
projected-path folding bind native path results to the retained target; Node still
binds that target to the actual discovered `(origin,CM)` occurrence and opening.
Reserved bytes, flags, field words and exact EOF must be checked on both sides.
Count `2^40` is valid as one level40 forest root; hashing NODE still uses only
levels0..39. Initialization, empty-block advance and zero-leaf projection must
have explicit permitted forms and cannot implicitly reset an existing wallet.

**Returning the previous root is not required.** The requirement is that only a
private branded immutable checkpoint from accepted initialization/advance enters
the call, with its Node cursor/revision/inventory binding intact. Native checks
canonical state and prior projected-path consistency; Node checks returned
`count == prior.count + incomingLeaves` and the exact validated block root/count.
An empty advance also preserves prior root/count. Echoing a previous root would
not authenticate an externally imported checkpoint and adds no missing authority
to this local capability model. A new epoch or journal restore cannot bypass that
binding by accepting arbitrary serialized state.

The native author is still implementing this proposal at this review point.
These conclusions approve the grammar direction, not unseen source, native
correspondence, the five-second operating budget, or actual wallet integration.

## Frozen native source readback

Reviewed the implemented candidate at:

- `hash-core/src/main.rs`: `0aac46589d038fac7ad1845472d2eb0b42653f94b11e1bb15a4e76355add4ffd`
- `hash-core/src/tree.rs`: `f1fb839a66c93708ab0b6388bf70b04d2d5106442a9eeefba9e7e9545fb3c989`
- `hash-core.mjs`: `fbe9c59f2ba1edf26f2948dcab61527a6c269d98f07995b8e138a6d06ae58b97`

The actual implementation enforces the proposed bounds/grammar, canonical prefix
forest, completed-sibling masks, unique index/token and forget/discovery rules.
It folds stored target leaves through padded paths before and after advance;
only the unpadded state is serialized. The clone-padding capture loop preserves
multiple targets sharing a sibling and accepts the full-count level40 root.
The JS wrapper sorts a private forget copy, derives expected target index/order,
and checks the returned state/witness mapping. It clears transient request/output
copies and returns operational failures. Native input limit selection preserves
old opcode bounds. There is no caller-selected hash program or path oracle.

Read the five Rust control bodies and13 JS control groups: they include the
padding-continuation trap, a small full-tree path/root oracle, malformed state,
forget/discovery, full-count geometry, real wrapper/native framing and legacy
AUTH/NOTE/NF. They remain **unexecuted by this reviewer**; source assertions are
not runtime PASS. Actual whole-block work folds up to64 paths twice and rebuilds
empty hashes, so resource/timeout claims still require execution.

Disposition: **source GO for Root's new pinned build and bounded component
controls**. Source/ELF closure must include the new `tree.rs`; actual installed
correspondence and wallet same-witness proof/recovery remain later gates.
