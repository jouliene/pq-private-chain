# Incremental common-history contract v1

This contract implements INCREMENTAL_WALLET_SYNC_GOAL.md. Payment proofs,
statements, block versions3/4, hash domains, genesis, fees and ledger admission
are unchanged. Reduced history delegates validity/canonical selection/freshness
and availability to the same independently selected validating source. Linkage
alone establishes none of those properties.

## Exact public wire

Both request and response start with436bytes. All integers are unsigned LE.
Request magic CPHREQ01; response magic CPHCONT1 (8bytes). Then format_version:u16=1,
block_version:u16=3|4, chain:32bytes, genesis_id:64bytes, base_cursor:160bytes,
target_cursor:160bytes, frame_count:u64. Each cursor is height:u64, block_id:64,
leaf_count:u64, root:64bytes (canonical8Goldilocks limbs), fee_escrow:u64,
unconsumed_liabilities:u64, in that order. frame_count is exactlytarget.height-base.height;
base<=target, all context/arithmetic/canonical bounds remain required.

The response echoes the exact request context/cursors and appends exactlythat
many existing length-prefixed CPSBLK03/04 records. Per-frame size and existing
count/body/byte caps are unchanged. Every sequential link, body ID, endpoint and
exact EOF must authenticate. Parser windows cap blocks/payments at256; no buffer
of the whole range or prefix is permitted. Cumulative byte arithmetic is checked.
Range size is determined by the independently selected endpoint, not an untrusted
frame count. Existing experiment deadlines/memory guards remain separately named.
There is no trusted peer-selected intermediate page or implicit page commit.

## Authority and atomicity

Only the wallet's private session creates a trusted base from its own committed
receiving/spentness/witness/cursor state or its exact retained joint checkpoint.
The wire base is an equality check, never a state import. External public request
bytes confer no authority. The target includes the complete externally selected
context. Different ownership at the same base/target produces identical ranges.

Updates stage bounded candidate state and journal; no note, path, spentness or
cursor publication precedes exact endpoint/EOF and successful cleanup. Failed
or interrupted replies discard candidates and preserve previous committed state.
A ready unchanged head emits no request and performs no history read/authentication;
it preserves the existing view. Branch selection intentionally revokes prior
private views/packets immediately. A failed replacement cannot restore their
spendability. Old committed state remains held but revoked while the candidate
uses only a retained authenticated checkpoint; deep rewind requires explicit
charged full replay. Even zero-range selected replay validates header+EOF before
a new capability. Revalidated public bytes are not a stale private capability.

## Serving and measurements

The real ledger server fetches base/target headers and only requested height/ordinal
rows by indexed queries. It never exports then slices the whole prefix. A single
read snapshot may hold a DELETE-mode read lock across its fixed CLI-owned output;
writer blocking and failure/rollback semantics must be disclosed and tested.
Outputs remain tentative until successful serving; create-only publication guards
prevent partial output being represented as complete.

Count exact request/response/framing bytes, selected header and reduced-record
rows/blob bytes, base/endpoint lookup costs and actual SQLite fullscan steps.
Report bounded ledger-open/genesis/source/tip and runtime pin checks separately,
including actual reads where practical; do not hide prefix work in startup.
Wallet counters separate bytes read, authenticated blocks/records and no-op work;
CPU/elapsed/tree RSS/journal payload counts have explicit non-overlapping scopes.
Oracles and fixture construction stay outside measured roles. Public retained
proofs are reused; private equivalence is checked in RAM without exporting hashes,
notes, keys, witnesses or backups. Real new proving/admission is separately required.
