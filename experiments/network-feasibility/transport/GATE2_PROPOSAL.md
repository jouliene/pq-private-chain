# Source-only Gate2 successor proposal

Status: Root accepted the full researcher profile in GATE2_PROFILE.json
(SHA2560a1edf72c03f518c51296742a54d97ed1508691cfb5b64dc75fcd1409111f42c).
Implementation ownership follows a separate assignment; no Gate2 transport code,
generation, build or run has begun here. SOURCE02 and actual Gate1 stay unchanged.
The producer successor is owned by arch_private_repro.

## Named question and workload

Can one bounded producer PUT overlap one archive GET/destination complete service
sufficiently at96ordinary offers per30.27456s, while a finite burst and a stopped
validator create measurable backpressure and every offered payment remains
accounted? Gate1's34.787545s serialized stage-cost sum exceeds the comparison
interval; its20.837566s isolated destination stage suggests possible overlap,
without proving actual concurrency or queue stability.

Propose eight sequential blocks of96fresh distinct ordinary2x2 proofs, plus a
separate new96credit funding block. Existing public Gate1 bodies cannot supply
new spends: disposable keys/openings were cleared, and repeating them is not new
throughput. A new generator keeps bounded private state in RAM across eight
rounds, privately shuffles the96owner-pairs/lane order each round (the two input
occurrences within a payment must share its owner),
uses the preceding accepted common anchor and produces balanced positive output
values sufficient for subsequent fees. No private pairing, key, opening or
witness is written/hashed. The test producer can use its own local ledger paths;
this is not Gate3 witness integration. Price all864 new proofs separately.

The agreed successor uses new explicit `CP04-NETWORK-PIPELINE-WORKLOAD01`:
`{format,block_version,ordinary_count,batch_size,ordinary_batch_count,chain,
genesis,blocks,endpoint}`. `ordinary_count` is the total, not per-block count.
Full shape is96lanes×8batches=768ordinary/9blocks including funding; diagnostic
is2lanes×3batches=6ordinary/4blocks including funding. Every block remains
`{header,bodies}`, every public entry remains manifest-relative `{path,sha256}`,
and endpoint remains the existing exact six fields. The first block is funding;
all later blocks must have exactly batch_size ordinary bodies. SOURCE02's old
parser stays frozen and does not silently reinterpret this new format.

Expected source oracle after funding+eight rounds: height9,1728leaves,
1536ordinary nullifiers,864cores,96consumed sources,fee escrow1,825,416,864,
liabilities0 from9.6B laboratory credit. Actual bytes/fees must corroborate these
projections; no generation is authorized until Root accepts the profile.

## Concrete finite schedule and limits

Retain Gate1's two100Mbit/s application-byte links,40ms perRPC, CPUs0/1/2,
4GiB AS per process, explicit sampled role-tree qualification and8GiB finite disk
watchdogs. Keep one producer PUT, one archive PUT+oneGET,64KiB chunks and requested
socket buffers with actual readback, one validator frame/API copies. Do not
silently enlarge these limits or add a hidden service queue.

Set T=30.27456s exactly. After separately completing funding and baseline queue
checks, start an externally timestamped offer epoch. Propose eight batch offer
times **[0,0,T,2T,3T,4T,5T,6T]**: a declared two-batch initial burst followed by
six ordinary cadence offers, total768 distinct offered payments. These are
pre-generated proofs driving a node test, not live wallet/prover throughput.

The producer pending queue holds at most8public batch IDs, with immutable source
payloads on its charged disk. The fixed inventory of8future scheduled IDs is
not accepted work. One pending batch may move to uploading only after reserving
one of **two unadmitted archive credits**. A credit remains occupied through
PUT, durable archive ACK, GET and validation, and is released only by exact
current-canonical destination admission ACK. Thus:

- pending-not-uploading≤8; uploading≤1;
- uploading + durable-ready + fetching/validating≤2;
- fetching/validating≤1; actual archive application connections≤2.

Each offered ID has exactly one disjoint state: pending, uploading, durable-ready,
fetching/validating, or canonically admitted. Assert their sum equals offers
actually due; future scheduled offers are separate. Log queue counts/bytes and
all transitions/timestamps. When credits are full, producer pauses before PUT;
record blocked time and source backlog. Archive GET completion is not admission
and does not free credit. No pending payload or bytes disappear from accounting.

Stop the validator cleanly **after the second ordinary block's durable canonical
ACK**; there is no destination frame active at that stop. Hold it stopped for
**3T=90.82368s** while the producer/archive and offer schedule continue, then start
a fresh isolated validator and genuine `Ledger::open`. Keep pending credit state
in the bounded test controller across this validator restart. Retry the exact
current canonical second block once, price its full transport/parser work and
require zero additional proof attempts; resume the remaining ordered blocks.
This is a controlled process restart, not distributed fork choice or a new
power-loss claim. Gate1 already exercised archive publication-before-lostACK.

Propose observation end **12T=363.29472s after offer epoch**, including restart
and drain. A separate outer watchdog must allow declared setup/funding and
finite cleanup; its concrete number awaits Root. At observation end require
768due/768admitted ordinary payments, all queues/credits/inflight0, no unexplained
work, destination pending publication0 and full RETAIN bytes present. If backlog
remains, preserve and price it as a failed finite service profile; do not change
end time after seeing the outcome. Count offered-to-enqueued, durable publication,
GET start/end and canonical ACK latencies individually; no service-cost sum is
reported as observed sojourn. Actual PUT/GET overlap, archive CPU and time blocked
must be visible, not inferred from separate timings.

## Minimal source boundary and costs

A successor keeps canonical verification and Network04 unchanged. Expected
transport-only changes are a fixed8batch controller with independent sender and
validator progress, offer/credit states, clean stop/reopen and external oracles.
The existing sender can remain one public process per PUT; the native validator
remains a persistent genuine Ledger client. Controller scheduling/credit metadata
is experimental orchestration, explicitly reported; archive bytes are not a
validity oracle. Receiver deny masks/private PID namespace still cover every
new producer proof copy and public DB, including after restart.

Provision **explicit2GiB local RETAIN** for both producer and destination, subject
to the actual encoded bytes.512MiB is insufficient (funding+three similar
ordinary blocks exceed it). The native init CLI already accepts an explicit local
quota; the transport runner currently hardcodes512MiB and must expose a reviewed
profile-bound quota. The canonical wallet wrapper has no quota argument, but also has no hidden
initialized flag. A generator-only PUBLIC fresh-init helper can call the already
supported CLI `init-retain DB CHAIN GENESIS 2147483648` through an approved binary
FD, preserving O_NOFOLLOW, inode/hash-before+after and typed-output checks, then
use unchanged `client.head()/admit()/...`. No canonical wallet/core/installation
edit or SQL quota update is needed. The helper needs independent review. This is local policy,
not a genesis/proof/consensus parameter. Eight ordinary blocks plus funding are
roughly1.51GB raw bodies by Gate1 projection, not a measured Gate2 result. Source
public bodies, producer DB/scans, Parent public proof copies, prepared frames,
archive objects and destination DB/journal all remain individually charged and
bounded. Do not reuse a larger quota as annual participation acceptance.

Persist public event records/failures without secret data. Keep actual native
lifetime counters, individual direct-sender CPU, wrapper-only wait4 labels,
archive cumulative counters and perRPC bytes; never sum nested stages or
cumulative RSS peaks. Compare exact14 canonical SQL tables excluding only random
local catalog ID, full body bytes, every scheduled ID and final retention. Across
two validator incarnations sum physical attempts and require864proof/96source
signature attempts for funding+ordinary admissions, with the current-tip retry
adding0. Recovery must not trust an archive's historical admission verdict.

Acceptance would provisionally support only this tiny-state finite load and
retained storage profile. It would not establish100M/year service, a viable
pruned participant, free archive availability, PoW cost or a PQ/privacy theorem.
Root must separately retain an explicit participation model before Gate3's full
wallet integration, and the global blockchain Goal remains ACTIVE.


## Existing concurrency and smallest successor delta

The actual current `archive.py` already starts at most two worker threads, with
one nonblocking PUT semaphore and one GET semaphore. Counter/stdout locks do not
cover transfer/hash/fsync work. Objects are immutable published links, so GET of
a durably acknowledged object can run while PUT creates another object. There
is no program-wide transfer lock. Gate1's observed connection peak was1 because
its controller serialized phases; source capability is not overlap evidence.
Keep the archive oneCPU shared between those threads. Its listener backlog2 is
a separate requested kernel queue, not another admitted application queue.

Necessary successor changes are narrow:

1. A new fixed multibatch public parser/framer accepts only the two reviewed
   shapes above, validates all entries/arity/IDs/order/count/encoded bounds, and
   charges every prepared frame. It need not generate an extra invalid candidate:
   the genuine final-proof rejection was already tested at96 in Gate1.
2. A fixed event-loop controller advances the declared offer clock independently
   of sender and validator completions, polls at most one sender and one native
   validator, enforces the two-credit invariant, and records disjoint ID/byte
   states and exact remainders at the fixed end. No generic server framework.
3. Make local native RETAIN quota an explicit reviewed successor invocation
   argument, fixed2GiB for these fresh stores; no proof/ledger source change.
4. Add common-host monotonic start/end timestamps to archive PUT/GET records,
   including crash/error paths, so actual interval intersections prove overlap.
   Existing durations and record order alone do not establish concurrency. Record
   controller offer/enqueue/upload/ACK/restart stamps on that same clock. Native
   command ACK receipt defines observable acceptance latency; commit precedes it.
5. Preserve all SOURCE02 lifetime/namespace/EOF/byte/failure controls; add a
   clean stop-after-second-ordinary ACK, same-DB fresh native open, fully priced
   current-tip retry, then normal genuine admission for remaining new blocks.
   Record both native incarnations and assert total proof/signature attempts.
6. At fixed observation end freeze queue/offer accounting before teardown.
   Declare any bounded teardown grace separately, and price its bytes/work;
   completions after the observation boundary cannot repair a failed drain.

The queue/credit test controller is trusted experimental orchestration, not a
consensus verifier or a public Sybil-resistant archive allocation protocol.
Archive ACK remains bytes-only; only native canonical ACK releases credit.
Its metadata/events must be priced/documented separately from payment service.
No sender process may queue a second payload in RAM or grant a new100Mbit/s
budget per extra consumer. Full-duplex overlap is the two declared independent
links, not a shared100Mbit/s aggregate host-link claim.

## Cheap and genuine diagnostics before scaling

Before heavy execution, source/unit controls should check disjoint offer-state
conservation, two-credit reservation/release, finite queue bounds, fixed-end
classification, monotonic retry/restart transitions and truncated/extra-byte
framing. Such arithmetic tests are not measured network throughput.

The real producer diagnostic uses2lanes/3batches:8genuine proofs, three successive
ordinary states and a fresh final endpoint. The real transport diagnostic must
show actual PUT/GET interval overlap/connection peak2, stop/reopen after ordinary2,
exact-tip retry with0extra proof attempts, subsequent ordinary3 genuine admission,
all14 canonical equality/retained bytes and complete drain with all6ordinary
offers accounted. This diagnostic cannot satisfy the768ordinary load profile.
A short diagnostic-only schedule is still to be frozen by Root: Root selected T=0.5s,
offers[0,0,0.5], stop1.5s, end12s, outer120s. Full outerwatchdog is600s including
separatelypriced funding/setup and cleanup, without extending fixed observation.
These diagnostic choices do not modify
to Root's full T=30.27456s/12T profile or a service claim. No implementation or
native/proof job starts on this document's authority.
