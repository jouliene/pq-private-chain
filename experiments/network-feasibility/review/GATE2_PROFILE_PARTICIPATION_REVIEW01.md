# Independent Gate2 profile and participation review

Disposition: GO for source implementation of the declared finite queue experiment.
This is not source approval of its unfinished producer/controller, execution
authorization, Gate2 acceptance, or ordinary-node participation acceptance.
Actual reviewed profile SHA256:
`9b86ab766d8d30e7948d2566f5b1eff4b8ba2b9b6f9bbe57a9d1c90f91c4aee8`.
The assignment/proposal supplied earlier `0a1edf72...`; a final direct hash check
rejected that identity. Root was notified before any execution. This review
applies to the actual bytes, including the explicit short diagnostic schedule.
No native execution, generation, build or cryptographic parameter change was
performed for this review. Gate1 evidence is reused, not rerun.

## Exact experiment and acceptance boundaries

The declared eight batches contain768 new ordinary payments, separately funded
by96 credits:864 genuine proofs. T=30.27456s, offers at[0,0,T,2T,3T,4T,5T,6T],
stop after ordinary2 canonical ACK for3T, fixed end12T=363.29472s. These are
researcher choices. The2-lane/3-batch diagnostic has8 proofs, offers[0,0,0.5],
1.5s stopped time and12s observation; it cannot pass the full capacity profile.
Outer watchdogs120s/600s permit setup and bounded cleanup, not a later offered
deadline. Pregeneration is not live wallet throughput.

The design addresses the measured Gate1 uncertainty:13.949979421s upload plus
20.837565988s destination service exceeded T when serialized. Actual overlapping
roles may resolve that scheduling barrier; a maximum-of-stages estimate cannot.
The current profile does not justify a cryptographic backend pivot by itself.

The successor source and actual receipts must establish:

1. Offer timestamps and the fixed end advance despite blocked I/O, native
   validation, external SQL oracles and restart. The controller must not hide
   offered arrivals behind synchronous request completion. Future inventory is
   separate from due pending work. Every due ID occupies one disjoint state.
2. Two credits cover uploading, archive-durable-ready and fetching/admitting
   together. GET completion does not release a credit. Only exact canonical ACK
   does. The already-admitted current-tip retry neither creates a new admission
   nor releases a second credit; its bytes and service remain charged.
3. Record actual stop completion and fresh restart timestamps, plus the unchanged
   offer epoch. If control/launch delays lengthen downtime, report them. Credit
   metadata survives the controlled validator restart in the declared controller;
   this does not test controller-crash recovery or distributed allocation.
4. Freeze queue/ID/byte accounting at12T before teardown. A commit without an
   observed ACK is still outstanding to the controller. Late ACKs, in-flight
   ambiguity and cleanup work are separately classified and cannot repair an
   on-time drain failure. Final SQL equality with the full producer is expected
   only when all batches were admitted; otherwise report the accepted prefix.
5. Count source bodies, producer DB/scans, Parent public proof copies, prepared
   frames, archive objects, validator DB/journal and temporary copies. Files
   outside the transport work directory cannot escape the8GiB role watchdog.
   Logical, allocated, sampled-peak and raw-cache sizes remain distinct.
6. Show actual monotonic PUT/GET interval intersections and connection peaks;
   retain shared archive CPU contention and each direction's pacing budget.
   One sender per PUT must not create an undeclared parallel link budget.
   Charge all role incarnations, native lifetime and waited-helper work,
   retries, controller/oracle overhead and teardown; never add nested stages.
7. Check864 proof/96 source-signature attempts only for a completed full workload;
   truncated/failing runs retain actual attempt counts. Exact canonical state,
   supply, fees, unique nullifiers, ordered roots and full RETAIN bytes must agree.

The proposed public held-FD `init-retain` helper can select2GiB without changing
the canonical wallet/core. It still needs executable identity pre/post checks,
typed exit/output validation and the unchanged client API. The latest-block
receiving optimization is fixture-specific: each fresh receiving inventory has
no earlier receipts. Every wallet must actually attempt the complete receiving
composition on all latest192 envelopes, obtain exactly its two notes, and check
opening/origin/path/balance. This is neither backup recovery nor Gate3.

## What canonical pruning currently does

`source/crates/ledger-cp03/src/cache.rs` implements local Archive and Retain
policies. Retain prohibits eviction/archive sessions. Archive evicts only an
oldest full-body prefix with matching durable catalog objects; a missing export
blocks eviction rather than skipping younger work. `schema-network04.sql`
enforces this and retains archive objects even after branch rollback.

`store_archive.rs:122` captures at most16 bodies and performs genuine historical
proof/source checks before export. `PendingPublication::publish` checks the
durable batch, commits local catalog entries and evicts in one SQL transaction.
`archive_io.rs:34` binds the catalog to chain/genesis/catalog ID and a concrete
database path/device/inode. `LocalArchive::open` binds a local archive directory,
holds its exclusive lease and checks/fsyncs its marker. This is an actual local
filesystem API, not a remote archive receipt interface.

`store_archive.rs:463` checks retrieved bytes against local canonical body IDs,
reduced records and genuine historical proofs; the association is rechecked
after I/O. Historical verification is not current-state admission or external
fork choice. Rollback uses local undo and requires available historical bodies.
Fresh catch-up must still perform genuine ordered admission.

The Gate1/2 TCP archive instead stores opaque full Network04 frames. Its durable
byte ACK is not a canonical `DurableBatch`, cannot authorize the local SQL
archive catalog, and cannot enable eviction in a Retain ledger. No automatic
remote-backed pruning integration has been demonstrated. Existing local archive
tiering can bound the raw body cache on one volume, but the same operator still
provides the archival volume. It does not transfer175TB/year to a remote role.

Even canonical body eviction only sets `bodies.full=NULL`. It retains reduced
history/body identities, headers, source state, nullifiers, cores, funded leaves,
tree nodes and undo rows. Only the recent-anchor window is bounded this way.
Bounded raw cache is therefore not bounded total validator disk. Archive catalog
growth and orphan-retained objects also remain charged; no implicit archive GC.

## Minimal supportable participation direction and missing mechanisms

A technically coherent proposed ordinary validator validates every new full
block, keeps a bounded recent full-body cache plus explicitly growing public
state/common history, and obtains older bodies from provisioned archives.
Authenticated body/header identities prevent silent substitution; unavailable
archives must cause a typed inability to serve, replay or perform a deep rewind,
not acceptance without data. Archive replication, repair, retention and service
incentives remain explicit operator/economic assumptions. A durable ACK alone
does not guarantee future access.

Implementing that direction needs a reviewed remote publication/retrieval
adapter tied to canonical identities, restart-safe catalog/eviction rules and
availability/failure controls. The current local binding must not be bypassed
with fake catalog entries or an opaque TCP ACK. Migration/retention policy and
old-history/undo treatment also need a coherent contract. This can remain a
bounded next implementation question; the present queue experiment should not
pretend it already supplies the mechanism.

The cost decision must still include about175TB/year of initial full-body traffic
and one archival copy at100M ordinary payments, relay fan-out and each additional
replica. Reduced wallet history remains about0.5TB/year before scans, state/index
overhead and receiving-key work. Body pruning does not remove those costs.
New full validators currently need full genesis replay and genuine verification,
or must explicitly trust a checkpoint. Opening a trusted local SQLite database
is not authenticated bootstrap from an adversary. The full-verifier checkpoint
construction is unimplemented and cannot be priced as free. Common history also
needs a trusted lab endpoint now and a future consensus/freshness context; no
distributed fork choice or permissionless issuance is inferred.

After actual Gate2 results, Root must distinguish retaining CP03 for this finite
provisioned research model from owner acceptance of an ordinary-node/storage
model. Gate3 integration can use the explicitly stated validating-source and
common-history premises if the backend is provisionally retained. It cannot
establish annual participation or erase the remote pruning/bootstrap obligations.

## Smallest remote-pruning pivot after the queue decision

Reuse the current safety boundaries rather than build a second ledger:

| Existing seam | Bounded necessary extension |
|---|---|
| `prepare_inputs` and canonical header/body association | Capture an exact immutable publication set. A frame object must bind frame hash/length and its ordered body IDs/full lengths; do not equate the frame SHA256 with a canonical body ID. |
| Local `DurableBatch` / `PendingPublication::publish` | Add an explicitly different remote receipt and persisted locator/catalog representation. Bind chain/genesis, configured archive identity, object identity/length and captured associations. A remote fsync claim is a provisioned-server trust assumption, not a cryptographic proof of durable future storage. |
| `cache::evict` and SQL triggers | Permit eviction only under the new explicit policy after committed matching publication metadata. Keep oldest-prefix accounting and failure on insufficient exported space. Preserve existing Archive/Retain modes and reject unsupported migration. Never fabricate local segment offsets/markers. |
| `verified_history` / `full_block_with_archive` | Add bounded remote byte retrieval feeding the same canonical length/identity/reduced-record/genuine-verification checks and post-I/O canonical recheck. Fetch full common blocks or public fixed chunks; do not expose wallet-selected note indices. |
| `rollback_tip_with_archive` | Reuse local authoritative undo only after required historical bytes are retrieved and checked. An archive does not supply trusted state/undo or fork choice. |

No payment/proof parameter, fee or nullifier rule needs to change for this pivot.
Persisted policy/locator changes nevertheless need explicit schema/version
dispatch; current stores cannot be silently reinterpreted. A connection to a
configured remote role must have an explicit authentication/trust boundary;
the present isolated loopback TCP experiment establishes no Internet peer
authentication. Hashes detect substituted content but do not authenticate a
server's durability promise or make unavailable bytes available.

The smallest decisive genuine test reuses two or more already valid distinct
blocks under the new explicit storage policy, a raw cache small enough to force
eviction, and separate archive/validator processes. It must demonstrate:

- Actual full-body NULL/cache reduction only after remote durable publication
  and local catalog commit, with pending/export/cached bytes conserved.
- Failure before publication, durable publication with lost ACK, and crash
  between remote ACK/local catalog commit/eviction. Fresh reopen reconciles or
  retries idempotently; a forged/wrong-object/wrong-chain/extra-byte ACK cannot
  authorize eviction, and no partial/unknown publication is treated as success.
- Producer fixtures and local full-body copies unavailable to the receiver.
  Fetch an actually evicted old block through the remote service, genuinely
  verify it, and admit it into a fresh ledger to equal canonical state. Charge
  fetch, verification, source archive and destination responsibilities separately.
- With the archive unavailable or its object corrupted/truncated, fail closed
  without state mutation. Restore access and demonstrate successful historical
  fetch and rollback using local undo. Recheck canonical association if the
  selected branch changes during a fetch; stale bytes cannot mutate new state.
- All remote objects, catalog rows, cached/reduced bytes, orphan objects and
  physical writes remain accounted. A bounded body cache is not a claim of
  bounded total state, remote catalog size, availability or year-long service.

The256-block accepted-anchor window is not authorization to prune spent
nullifiers, funded occurrence state or deep-reorg undo. Notes remain spendable
after their old anchor expires using a current witness. A bounded-undo/finality
policy, authenticated state accumulator or checkpoint would be a separate
protocol/state mechanism, not a cache optimization. Until such a mechanism is
implemented, the proposed model must retain and price growing public state and
undo, and make historical availability failures explicit.
