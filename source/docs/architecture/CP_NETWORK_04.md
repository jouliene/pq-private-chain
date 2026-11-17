# Network04 research adapter contract

Status: normative candidate for NETWORK_FEASIBILITY_GOAL.md, subject to source
review and actual gated experiments. This changes the block/history/transport
adapter around the unchanged CP03 complete payment relation. It is not a new
cryptographic proof profile, permissionless issuance or distributed consensus.

## Fixed authority and compatibility

The installed verifier owns exactly two compiled protocol manifests: historical
CP_PROTOCOL_03.json and CP_NETWORK_04.json. The four exact base contracts named
by the former manifest are included alongside these files; their old task
allocation/status paragraphs are historical, not current orchestration rules.
Keep the former bytes and protocol ID
unchanged. A Network04 genesis selects the latter fixed identity, whose manifest
also binds the complete base CP03 protocol ID. Neither a body, genesis, peer nor
runtime request may supply an arbitrary manifest, program or proof parameter.
The verifier validates the selected fixed profile and all three program IDs
against the compiled CP03 registry. A database's genesis, stored schema and every
block/history record must agree on one version. Cross-version mixing is rejected.

CPGEN003/version3, CPBLOCK3/version3 and CPSBLK03 retain their original rules,
including 1..16 bodies and original source limits. Network04 uses
CPGEN004/version4, CPBLOCK4/version4 and CPSBLK04. Network04 database schema3 is
distinguished from historical schema2. The new explicit manifest overrides the
old block/genesis/history limits only for version4; the old normative contract
must not be silently reinterpreted.

## Unchanged payment and issuance invariants

CPBODY03, complete statement/program/profile IDs, fixed fees, proof cap, source
authorization message/context, commitments, receipts and all cryptographic
parameters remain unchanged. A genuine complete same-witness proof, current
accepted anchor, unique source/core/nullifiers, exact integer value accounting
and full-block atomicity are required. No same-block output spending is added.
One invalid final payment prevents the whole block's consensus-state transition.
Operational failures are not acceptance and cannot silently lose accepted state.

Network04 genesis retains sorted unique source IDs, one registered laboratory
ML-DSA-87 authority per entitlement, exact checked total and MAX bounds. It permits
1..128 source records; encoded size is exactly 376 + 2648*n bytes (maximum
339,320). This is synthetic funding, reported separately from ordinary payments.
No later entitlement registration, PoW reward or unrestricted issuance is added.

## Complete block encoding and limits

Network04 permits 0..128 bodies, subject independently to a complete encoded
full-frame limit of 268,435,456 bytes (256 MiB). Per-body CP03 caps also remain.
An individual body count or proof cap never bypasses the aggregate frame cap.

The Network04 header preserves the original 208-byte fixed prefix structure with
explicit version4 magic/version and inserts `encoded_full_block_bytes:u64le`
after that prefix, before the ordered 64-byte body IDs. Its exact length is
216 + 64*n. The canonical full transport frame is:

```text
"CPNET004" || u32le(header_length) || header
             || for each ordered body: u32le(body_length) || canonical_body
```

The complete frame length is exactly 228 + 68*n + sum(body_length). Reject
inconsistent counts, lengths, reserved fields, body order/identity, overflow,
trailing bytes and over-cap values before unbounded allocation and before commit.
Stream readers may use a bounded spool; a short/disconnected transfer is never an
accepted block. Reduced scan validation recomputes the same full-frame size from
each canonical prefix and its declared proof length, rather than trusting the
header's asserted size. All permitted byte encodings remain canonical.

An empty Network04 block has header216/full frame228 bytes. It advances the
canonical height and block identity; root, leaves, nullifiers, source use/liability and
fee escrow do not change. It adds the current anchor pair at that height and has
explicit reversible undo. An unchanged root/count repeated in a recent block is
still a recent eligible anchor; it is not evidence of anchor expiry.

## History, anchors and wallet boundaries

The 256-block accepted-anchor policy remains unchanged. An anchor is eligible
only if its root/count pair occurs within the selected branch's eligible window.
A real expiry control must advance changing roots and show absence of the old
pair from that window. Old unspent notes persist and may be spent with a refreshed
eligible witness. Rewinding must undo orphaned discoveries, spends and witnesses;
a transaction based on still-eligible common-prefix funding/anchor is not invalid
merely because it was first prepared on the replaced branch.

Reduced blocks must authenticate version, genesis/chain, parent, ordering, body
identities, counts and expected endpoint. These bindings delegate omitted payment
validity to an independently supplied validating source; they do not establish
consensus, freshness or availability. Wallet buffering has both payment and block
count bounds. Empty-only/trailing-empty sequences advance the validated cursor
without a receipt-worker invocation or unbounded pending window.

The integrated wallet must construct selected paths locally from common history,
without remote owned-index or unique-subtree queries. The full local ledger is
allowed only as an independent test oracle for this algorithm. Receipt keys,
openings, backup and witnesses remain in bounded local private memory/pipes, never
logs or public hashes. Recovery needs the backed-up random key inventory, public
inventory/history and an independently supplied endpoint. No mnemonic or recovery
of unknown later random key rotations is implied.

## Local retention and transport roles

Retention mode is explicit persisted local policy, never a proof-validity or
consensus parameter. Gate1 may choose RETAIN: keep all admitted full bodies,
prohibit eviction and account for real disk growth. RETAIN must not manufacture
archive acknowledgements or leave mandatory pending exports while claiming a
drained queue. Counts for retained, pending and durably archived data must retain
their actual meanings through crashes and reopening.

The existing archive-publication mode retains its durable-ACK-before-eviction
requirement. Its 16-item I/O batch and 64 MiB segment are separate local bounds
from the 128-body block limit. All block ordinals, schema checks, cache reservations,
scan limits, CLI inputs, archive readers and undo bounds must handle the selected
version coherently. Export loops finish all mandatory work or explicitly report
the unresolved queue; a content hash alone establishes no availability guarantee.

Separate producer, archive and receiving validator processes exchange bounded
application frames. The receiver cannot read the producer database or fixtures.
An archive acknowledges durable publication only after bounded staging, file
fsync, atomic publication and directory fsync. Archive durable-object ACK and destination canonical-admission ACK are distinct.
A destination retry may acknowledge an already-canonical exact height/header ID
after checking current selected-branch state; it does not cache a verifier verdict
for a different or rewound state. After rewind or conflicting branch, ordinary
eligibility/verification rules apply again. Archive presence never authorizes
admission. A post-commit lost reply must not double-apply the exact still-canonical
block. A controlled persistence-boundary fault tests this rule.
Correctness snapshots/oracles remain outside measured role intervals/processes.

Initial bandwidth/latency/CPU/memory/disk assumptions are researcher scenarios
recorded before execution, not owner budgets or measured WAN performance. Report
actual proof generation, transport, verification, commit, retention, CPU/RSS,
bytes and backlog by role. A local finite pass cannot establish year-long capacity,
decentralized participation or production/PQ/privacy assurance.
