# CP03 authenticated complete history and reduced scan

Root source contract, 2026-11-16. This specifies the missing history transport
boundary for CP_INTEGRATION_03, not consensus, proof acceptance, funded recovery
or an implemented resource PASS. It changes no payment/proof/receipt bytes.
Historical R2 IDs remain distinct. Implementation and independent review follow.

## Commit exactly the full body and its reduced representation

Use CP_INTEGRATION_03's Tag, blob and H64 definitions. Let `prefix` be exactly
the CPBODY03 header, statement, both envelopes and authorization, excluding the
proof. The header still contains the actual complete proof length. Define:

```
proof_digest = H64(PROOF, blob(actual_complete_proof))
body_id = H64(BODY, blob(prefix) || proof_digest)
genesis_id = H64(GENESIS, blob(exact_canonical_genesis))
```

Full intake requires a nonempty proof within2,097,152 bytes, exact prefix/body
lengths and canonical statement/envelope headers. It recomputes proof_digest
from actual proof bytes. This hash does not replace genuine proof verification,
source signature, receipt binding, fee, anchor or current-state checks.

A reduced record is `ASCII(CPSCAN03)[8] || blob(prefix) || proof_digest64`.
Its exact lengths are9,499/4,888/4,952 bytes for credit/1x2/2x2. It retains the
actual proof length and digest, both encrypted envelopes, all public nullifiers,
commitments, source/fee fields and source authorization. It contains no proof,
descriptor, receiving key, opening or producer verdict. Reduced intake recomputes
the same body_id but cannot establish proof validity. No declared proof digest
may be substituted on a full-validator path.

Full and reduced intake use one shared strict prefix parser, including nonempty
capped declared proof length, exact arity/statement/authorization lengths and
canonical envelope headers. Reduced intake cannot skip these checks merely
because proof bytes are omitted. Use the existing canonical Statement::parse;
do not accept shape-only projection,
reduce noncanonical limbs, pad absent inputs or introduce a second statement
grammar. Transport parsing alone does not authorize issuance or validate the
receipt digest; those remain explicit integration calls on the exact same bytes.
Expose parsed objects as unverified transport data, never as admitted payments.

## Canonical local block header

```
ASCII(CPBLOCK3)[8] || version_u16=3 || reserved_u16=0 || chain32 ||
parent_id64 || height_u64 || body_count_u16 || reserved_u16=0 ||
leaf_count_u64 || root64 || fee_escrow_u64 || unconsumed_liabilities_u64 ||
ordered_body_ids64[body_count]
```

The fixed prefix is208 bytes. There are1..16 bodies, so the maximum header is
1,232 bytes. Height starts at1 and increases by one; the first parent is the
installed genesis_id. Root is eight canonical field limbs; leaf_count<=2^40,
fee_escrow and unconsumed_liabilities each<=MAX. Their actual arithmetic/root
correspondence is a ledger check, not an implication of canonical syntax.
`block_id = H64(BLOCK, blob(exact_header))`.

The local16-body bound is a bounded research admission unit inherited from the
reference; it is not a selected permissionless consensus or launch block policy.
No empty block, signature-only finality or new trust service is introduced.

The full validator derives every ordered body_id from actual full bodies and
installs this header only with a complete atomic verified state transition.
The header, full-body objects, reduced records and state/undo indices share one
logical commit. An exported record must be byte-derived from that admitted body,
not independently supplied by the producer. Durable archive export and eviction
remain a separately implemented gate.

## Bounded scan stream and independent endpoint

A scan block is `ASCII(CPSBLK03)[8] || blob(header) ||
repeated(blob(reduced_record))`, with exactly the header's body_count records,
in header order and exact EOF. Absolute maximum is153,292 bytes; an all2x2
16-body block is80,540 bytes. File/stream framing is repeated `blob(scan_block)`.
Check each declared length and count before allocation and enforce max+1 input
limits. Including its outer u32, a maximum framed block is153,296 bytes. Read
one bounded frame at a time, never the whole history. EOF after one to three
bytes of an outer length is truncation, not successful end of stream. Reject
unknown versions, reserved bits, truncation and trailing data.

A scan session receives operator-configured chain, installed genesis_id, and an
independently held expected endpoint `(height, block_id)`. None comes from the
archive server or scanned bytes; copy and freeze them for the session lifetime.
A zero-height endpoint must equal genesis_id.
Starting at genesis, each block must match the configured chain, exact next
height and previous block_id. Each reduced record must have that same chain and
recompute its ordered header body_id. Leaf count must grow by exactly twice the
body count from zero, with checked arithmetic and the depth40 bound.

Parse and check a whole bounded block before changing the session cursor. A
late-invalid record changes neither cursor nor pending consumer state. At end,
require exact expected height/id and EOF; reject extra blocks or bytes. A failure
poisons the session so a caller cannot skip a rejected block and later finish it.
No prefix yields a complete-history token. Before finish, any decoded material
is tentative and cannot credit a wallet or assert complete balance.

Finish certifies only byte completeness and linkage relative to that explicitly
trusted endpoint, under the hash-binding assumption. It does not certify honest
consensus, proof validity, source authorization, current-state semantics or the
Merkle root. A reduced wallet trusts the full validation behind its independently
held endpoint. If the server also chooses the endpoint, a valid stale prefix is
indistinguishable from the requested history; retain this explicit counterexample.
A later reorganisation unknown to the endpoint holder is not detected by this
codec. A different independently supplied canonical endpoint requires a new scan
or separately authenticated rollback/resume protocol, never a mid-session change.

Full-stream retrieval has no key/recipient-specific requests. It does not hide IP,
activity or timing. Receipts may be examined tentatively in bounded batches; helper
or provider operational failure aborts the batch/scan without a complete result.
Native decapsulation, NOTE/NF, authenticated spentness/path reconstruction and
all-key inventory validation remain real work, not free effects of this codec.

## Next executable discriminator and integration gates

Implement a small Rust transport/stream component reusing canonical arity parsing
and a separately written Python byte/hash reference. Use bounded public codec
fixtures explicitly labelled non-admitted; they are not mock proofs or substitutes
for a payment cycle. No proof-verification API is mocked or returns success here.
Exercise full-body/reduced ID agreement, exact lengths, deletion, duplication,
reordering, substitution, wrong chain/parent/height, stale endpoint, suffixes,
oversize declarations, late failure with no cursor advance and poisoned-session
finish. Distinguish the deliberately server-chosen endpoint counterexample.

Freeze source before the actual component control run; preserve raw outcomes and
have another agent review the exact implementation. This can close a transport
mechanism question, not48h recovery or final integration. Follow with genuine
admitted history, incremental tree/nullifier/source/CORE store, complete inventory
and backup-only fresh spend once the proof/receiving gates pass. No full-history
in-memory clone, unbounded batch or missing archive may receive FP2 credit.
