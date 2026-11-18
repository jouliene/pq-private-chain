# Payment role costs at 100 million annual offers

The owner supplied 100 million offered payments per 365-day year. This model
prices all offers before inclusion and uses 100% inclusion as the sizing case,
with 95% as sensitivity. The missing five million in the sensitivity still
consume wallet uploads and pre-inclusion service. Annual throughput, network
behavior, remote pruning, and either new proof route remain unexecuted.

## Run and check

```sh
python3 -I experiments/node-validation/roles/project.py \
  --masked-body-bytes 262850 --masked-max-body-bytes 272556 \
  --aggregate-proof-bytes 200000 > /tmp/node-role-estimate.json
python3 -I experiments/node-validation/roles/check.py
```

The calculator takes rounded complete masked-WHIR body bytes. It leaves the
whole candidate cost outside this input visible in the public evidence and the
optional CPU arguments. For a fixed-rate sizing row, the integer is an input
scenario. The independent review supplies the separate modeled upper wire
bound for staging. The emitted values use exact bytes and rational fractions. Rates are application-level
bits/s. Reported decimal TB/GB and Mb/s below round the exact output.

The run rereads and hashes six committed public data files. It independently
reconciles the ordinary producer aggregate with the sum of eight measured full
frame lengths after removing block overhead, checks the retained Gate1 reduced
record and scan-frame sizes, and checks continuation framing against the
260-block trace. It reproduces historical byte counts with arithmetic. It
performs no proof generation or verification and makes no new system
measurement. If `dimensions/MATRIX.json` is present, the calculator also reads
and hashes the current component receipt. `--matrix-evidence` supplies a
replacement receipt.

## Actual input evidence

| Public observation | Measured scope |
|---|---|
| 768 CP03 ordinary proofs, 1,344,972,096 full body bytes, mean 1,751,265.75 B | Separate pre-generated Gate2 2x2 bodies. Ordinary proof workers used 1,418.702798 CPU seconds in total, with 168,308 KiB maximum individual RSS. Enclosing wallet, funding, and provider costs differ. [Producer readback](../../network-feasibility/producer/evidence/GATE2_FULL_GENERATION01_READBACK.json) |
| 96-payment durable admission span 5.444–5.851 s, 411,572 KiB measured receiver tree peak | The complete CP03 Gate2 receiver ran paced loopback, with separate archive and unpruned RETAIN. Its actual final DB is 1,523,658,752 logical B and the opaque archive has 1,513,872,156 logical B. The spans include state and durable writes and give no isolated mempool verification or year-sized disk profile. [Role readback](../../network-feasibility/transport/GATE2_FULL01.json) |
| 4952 B ordinary reduced record, 482,152 B for one 96-payment scan frame | Gate1's exact encoded lengths. The CP03 reducer stores the public prefix and proof digest, and the block scan includes public identities and context. Gate1's tiny retained database page census is an evidence reference only. [Resource readback](../../network-feasibility/evidence/RESOURCE_MODEL01.json) |
| 0.2451–0.2608 thread-CPU s for public sparse-matrix contraction, guard and first main fold | Three public statements on the local i7-8700K. Reusable matrix preparation took 0.5954 s wall separately. This component omits later folds, masking and OOD entries, codec, PCS and transcript verification, and ledger work. [Component receipt](../dimensions/MATRIX.json) · [Metered source](../dimensions/matrix.rs) |
| 113,360 B requests and 1,492,866 B replies across 260 incremental single-block requests | The actual 260-block trace authenticated 261 reduced records. The emitted SQL counters are logical reads. A separate backup-only fresh process scanned 94,218 B, 259 blocks, five records and spent with a new proof. Measured restore CPU covers the finite wallet process, including work outside the history scan. [Continuation trace](../../incremental-sync/evidence/trace01/RESULT.json) · [Backup-only restore](../../incremental-sync/evidence/sync-private01/RESULT.json) |

## Research home profile

[PROFILE.json](PROFILE.json) specifies one four-physical-core host with an
allocation of two core-seconds/s for validation, 16 GiB RAM, and 4 TiB usable
disk. Its 100/20 Mb/s downstream/upstream line provides 80/16 Mb/s of useful
application throughput. The 80% allowance represents a planning allocation,
with no measured WAN-loss or transport efficiency. Block packing is 96 ordinary
2x2 payments per nonempty block with one final partial block per year. Funding,
issuance, empty blocks, consensus messages and miner resource use require
separate accounting. The profile compares one-year validator catch-up while
live to 90 days and key-only, validity-delegating wallet recovery to 48 hours.
The burst is 10 times mean offers for 600 s, draining the extra demand within
one hour. The background is adjusted for the same annual volume. The 100/s
600 s sensitivity stays separate. These are researcher scenarios. [Previous role decision](../../../docs/network-feasibility/RESOURCE_DECISION.md)

An active mempool peer receives each submitted body once and relays to one
requesting peer per role in the default profile. It also fetches and relays
complete blocks. An independent block-only validator skips the mempool and
fetches full uncached block data, including capsules and the aggregate for the
fallback. Six peers exchange a 72-byte inventory and 72-byte request per
requesting edge. Each transmitted object has 12 bytes of relay framing. The
calculator applies one payload receive and the actual outbound payload copy
count per phase, with inventories still charged to all six peers even when
only one requests. The six-payload-peer and perfect cross-phase cache cases are
explicit sensitivities. Cross-phase reuse can reduce payload transfer while the
recipient still obtains a complete logical block and runs the required public
verification. All canonical proof bytes are charged to the archive and cold
replay. Distinct payload receives and retries above the declared profile add
bytes. A node taking the archive stream uses it in place of the matching
block-gossip payload. Wallet-to-intake, downstream relay, and archive replica
transfers are separate links. The model has no network-wide peer population
graph, so multiplying each node's symmetric view would count both sides of the
same transfers.

## Direct masked WHIR and the CP03 fallback

The primary sizing uses the modeled complete masked-WHIR body (proof plus
4,876 B of CP03-equivalent frame, statement and encrypted receipts). It carries a
standalone proof before inclusion and in the selected block. A 96-payment full
block is `228 + 68n + sum(body lengths)`. Common wallet scan frames are
`232 + 5020n`. The projections assume a succeeding candidate keeps the same
public record widths and independently selected history semantics. The independent reviewer’s separate salted terminal and nonuniform rate schedule
projects a mean 262,850.011 B and an exact combinatorial wire maximum of
272,556 B for the modeled codec. It charges 1,772,093,440 B of RS values,
385,875,648 B of tree nodes and 192,937,984 B of salts, 2,350,907,072 B in sum.
An earlier independent schedule projected 266,122.355 B mean and 276,044 B
maximum with 2,296,381,120 B of those components. The source-side nonuniform
schedule projects 263,190.651 B, including 3,376,414,720 B of raw RS values.
The older uniform guarded Johnson estimate is 269,536 B with 5,730,467,840 B
of raw RS values. Earlier explicit-guard projections remain in the table as
sensitivities. These byte counts describe proof geometry. Implemented peak RSS
and a production codec need actual measurements. [Independent sizing](../review/schedule-check.json) · [Source nonuniform sizing](../primary/selected-profile.json) · [Older guarded sizing](../primary/guarded-budget.json) · [Earlier explicit-guard sizing](../primary/cp03-budget.json)

The only fallback priced here aggregates **already public, wallet-proved CP03**.
The wallet submits full CP03 once per scheduled intake copy, averaging
1,751,265.75 B plus the 12-byte envelope. Each intake peer that evaluates every
request owes 100 million CP03 mempool checks at either inclusion rate. Each
untrusted builder needs all selected full proofs to generate the aggregate. A
co-located builder can use the intake copy; a separate remote builder needs
another transfer. The aggregate relation must execute the fixed CP03 verifier
again over each included proof and bind its exact CP03 proof digest, canonical
public prefix, identity, order, chain, branch context, version and arity. It
must accept every scheduled statement under verifier-owned parameters, using
genuine proof verification at both levels. The outer verifier checks the complete
ordered block and the capsule data. Receipt digests and dynamic anchor,
nullifier, replay, supply, fee and atomic state obligations remain independently
checked at ledger admission. The current fixed CP03 ordinary 2x2 minimum fee
is 2,112,248 atomic units, so no fee policy changes follow from this layout.
[Baseline admission](../../../source/crates/ledger-cp03/src/admission.rs)

For cost only, each capsule is a 4,952-byte CP03 reduced record (4,876-byte
prefix, 12-byte record framing and 64-byte proof digest). The proposed block
charges `240 + 5020n + aggregate proof bytes`, with 228 base bytes, 68 B per
payment for the ordered identity and length framing, and 12 B to tag and size
the outer argument. This introduces a prospective versioned block codec. A
200,000 B outer argument is a sensitivity. No complete aggregate, canonical
codec, PQ composition, extraction argument, or prover resources have been
established. A block-only validator verifies one genuine outer proof and applies
all capsule state transitions per block, independent of an intake service
verdict. An outage or withholding of CP03 from builders can delay or censor
inclusion even when existing compact blocks can be validated. Direct submission
reveals timing and connection metadata to the receiving service. Alternative
independent intake and builder routes improve reachability at extra traffic and
processing cost. The builder receives public payment bodies only and its inputs
still need availability until inclusion or expiry.

## Projected role results

| Complete body or outer proof input | Included | One canonical copy TB/year | Mempool + block peer Mb/s up | Independent block-only Mb/s up | Block-only cold replay, 1 year, link-only days while live |
|---|---:|---:|---:|---:|---:|
| Reviewed guarded WHIR, 262,850 B mean | 95% | 24.977 | 13.02 | 6.34 | 31.40 |
| Reviewed guarded WHIR, 262,850 B mean | 100% | 26.292 | 13.35 | 6.67 | 33.20 |
| Reviewed guarded WHIR, all at 272,556 B bound | 95% | 25.900 | 13.50 | 6.57 | 32.66 |
| Reviewed guarded WHIR, all at 272,556 B bound | 100% | 27.263 | 13.84 | 6.92 | 34.54 |
| Guarded WHIR 1,058,728 B | 95% | 100.586 | 52.39 | 25.52 | Live egress exceeds profile |
| Guarded WHIR 1,058,728 B | 100% | 105.880 | 53.73 | 26.86 | Live egress exceeds profile |
| WHIR 373,548 B | 95% | 35.494 | 18.49 | 9.00 | 46.29 |
| WHIR 373,548 B | 100% | 37.362 | 18.97 | 9.48 | 49.05 |
| WHIR 640,458 B | 95% | 60.850 | 31.70 | 15.44 | 87.27 |
| WHIR 640,458 B | 100% | 64.053 | 32.51 | 16.25 | Live egress exceeds profile |
| WHIR 1,594,887 B | 95% | 151.521 | 78.91 | 38.44 | Live egress exceeds profile |
| WHIR 1,594,887 B | 100% | 159.496 | 80.93 | 40.46 | Live egress exceeds profile |
| Aggregate 200,000 B per block | 95% | 0.675 | 44.61 | 0.171 | 0.78 |
| Aggregate 200,000 B per block | 100% | 0.711 | 44.62 | 0.180 | 0.82 |

Default symmetric relay application rates happen to match in both directions
because the model uses one outbound payload copy in each phase. The earlier 373,548-byte
WHIR estimate exceeds the 16 Mb/s profile for a mempool participant. Its
independent block-only case fits the steady link at both inclusion rates, but
the 100% 10x burst takes a projected 7,246 s to drain on networking alone. At
640,458 B, the 95% block-only steady share fits the link within 0.57 Mb/s of the
ceiling, and the 100% case exceeds it. A single builder or mempool participant
charging every CP03 offer still needs roughly 44.44 Mb/s just for the intake
payload stream. A 200,000-byte aggregate could substantially reduce the archival
and independent block-validation terms while leaving upstream participation
expensive. Under six full payload copies at 100%, projected send rates for the
reviewed 262,850-byte WHIR estimate and aggregate mempool peers reach about
80.04 and 267.65 Mb/s. Perfect cross-phase reuse lowers that WHIR case to 6.68 Mb/s and
still leaves the aggregate case at about 44.49 Mb/s. Both reusable-input
scenarios need a real authenticated compact-relay protocol and measured misses.

The reviewed 262,850-byte mean case fits both steady links. At 100%, the
network-only 10x burst drains in 26,592 s for a mempool peer and 3,260 s for a
block-only validator. Replacing every body with the exact 272,556-byte modeled
maximum raises the block-only drain to 3,511 s. That leaves 89 s against the
one-hour target before CPU, storage, invalid-input service and retries. The exact default 100% sizing
limits for this burst are 275,881.970 B for a block-only validator and
137,682.985 B for a peer covering both mempool and blocks. Steady-link-only
limits are 630,644.250 B and 315,064.125 B respectively. These limits depend on
the assumed link, gossip and public block layout. The guarded elementary case
exceeds the steady uplink for both validator roles at both inclusion rates.

Wallet upload across all origins is 26.286 TB/year for the reviewed mean
scenario, 105.874 TB/year for the older guarded elementary case and 175.128 TB/year
on the fallback with one upload each. The fallback means 0.876 s ideal upload transfer for one CP03 body
on the useful home uplink, before wallet proving, handshake, receipt, queue
and retransmission costs. The 262,850-byte WHIR case is 0.131 s for transfer
after an unmeasured prover. Per-wallet payment volume is user-specific.

At 100% every receiving wallet reads about 502.963 GB and uploads 0.529 GB/year
for common history with one update per block, including an explicit modeled
72-byte query and 256-byte reply for an independently sourced endpoint per
range. The implemented continuation contributes 436 B each way; the endpoint
protocol is a sized placeholder. At 95% the figures are 477.814 GB and 0.503 GB.
Unchanged heads require no continuation read. Wallets may batch common ranges
or download the same public frames via any availability service. Endpoint
validity, freshness, recipient trials, witness CPU and metadata anonymity
remain separate from frame accounting.

## CPU budget for independent block validation

At 100% inclusion, steady arrivals are `100M / (365 × 86,400)` = 3.170979
payments/s. Replaying one offline year in 90 days requires an additional
`100M / (90 × 86,400)` = 12.860082 payments/s. The resulting 16.031062
payments/s leave **0.124758 CPU s/payment** across two validation core-seconds/s
for all public verification and state handling. At steady arrivals alone that
allocation provides **0.630720 CPU s/payment**. A peer participating in the
mempool additionally pays pre-inclusion checks and has less headroom.

The public matrix, guard and first main fold component used 0.2451–0.2608
thread-CPU s on three public statements. The component alone would spend
3.930–4.180 core-seconds/s while catching up if a complete verifier uses this
source and does equivalent per-statement work on the same machine. It fits the
two-core steady budget before charging the remaining verifier and state work.
With all four physical cores dedicated solely to validation and perfectly usable,
the catch-up ceiling rises to 0.249516 CPU s/payment. The slowest component
sample alone exceeds it. The fastest leaves about 4.4 ms/payment for all
omitted verification and state work. The no-overhead, component-only catch-up
projection spans 232–257 days with two cores and 88–95 days with four.
Matrix preparation is extra at process startup. The evidence does not price a
new formulation, verified batching or a completed public verifier. Any credit for
those changes requires source-equivalent measurements.

## Retention, branch changes and recovery

The projected pruned node retains spentness and replay keys, both funded leaves
per ordinary payment, the occupied depth-40 tree, reduced public history,
ordered headers and a sized archive catalog. It keeps a 256-block anchor/undo
and complete proof window plus capacity for one staged fork, two inflight blocks,
and local transactional spool. Exact recent undo counts use the distinct nodes
touched at each level per block plus a prior 64-byte digest when that node
already existed. Each included body adds state even if payload eviction succeeds.
This is a disk planning scenario with explicit row, index and 25% page
allowances. Physical SQLite allocation at year scale, write amplification and
fragmentation still need measurement. The script prices one additional projected
DB copy if recovery builds new state alongside the old installation. The `node_undo` suffix
policy and the remote block catalog are new storage work. The current RETAIN
validator and separately provisioned archive do not supply this profile.

| Independent block-only projection, 100% inclusion | 1 year | 5 years | 10 years |
|---|---:|---:|---:|
| Reviewed guarded WHIR, 262,850 B mean and 272,556 B staging, decimal TB | 0.875 | 4.323 | 8.632 |
| Fallback at 200,000 B outer proof, decimal TB | 0.862 | 4.310 | 8.619 |

The 4 TiB profile is 4.398 decimal TB. Five-year storage leaves limited space
in the ledger plan. At ten years the public state and common history exceed
this allocation even under pruning. The source-derived selected state fields
alone are 83.200 GB in year one at 100%, and 502.242 GB/year of framed common
history dominates the planned proof-pruned node. A mempool peer adds a bounded
on-disk public transaction spool and parser/verification work. It needs a
separate RAM profile for verification, live mempool metadata and concurrent
block/capsule parsing. The 600-second pending window is a sized staging
assumption. An excess queue requires backpressure, service and explicit pending
availability. Silent expiration cannot satisfy the offered-load test. Old
nullifiers and all funded occurrences remain necessary under current semantics.

The default table has no observed annual fork count. `--extra-fork-blocks-per-year`
charges full 96-payment replacement blocks, archive copies and wallet public
replacement frames, assuming the wallet falls inside its tested eight-checkpoint
window per shallow event. `--wallet-deep-replays-at-first-year-end` adds a
complete common-history scan per deeper selection. Old or unavailable common
checkpoints require validated public replay. A validator selecting beyond its
retained 256-block state/proof window would have to recover authenticated data
and rebuild from genesis, or implement a separate snapshot/archival undo
contract. A peer's state dump adds a new trust or proof premise. A body that
returns to the mempool needs retained full proofs or a funded wallet/peer
resubmission, with `--reorg-wallet-resubmissions-per-year` charging the full
body, upload, relay and pre-inclusion checks again. CP03 documents cases where
anchor loss or expiry also requires a newly proved wallet payment. Capsule-only
retention provides neither the original proof for re-inclusion nor service
availability by itself.

Three independent archive replicas store complete canonical frames by default.
At 100%, the reviewed WHIR mean case means 26.292 TB per copy per year or
78.876 TB for three copies. It needs about 20.01 Mb/s primary archive egress for two
replication feeds and one live full-data feed. The aggregate-only fallback
needs 0.711 TB/copy/year, 2.132 TB across three, and 0.541 Mb/s of analogous
mean egress. Repairing a lost copy incurs retransmission of its full retained
volume. Complete cold validator and wallet service are additional downstream
streams. The script emits their exact receive sizes, archive RPC overhead and
residual-link transfer floors at one, five and ten years. The archive role's
copy and link checks require durable authenticated identities, fail-closed
refetch, independent failure domains and continued reachability. Acknowledging
one PUT does not implement remote pruning or permanent availability.

Fallback archival policy determines retained proof evidence. Aggregate-only
retains versioned headers, all capsule data and original outer proofs, and
allows historical aggregate verification assuming a reviewed proof of the
exact CP03-verifier relation and continued historical verifier availability.
The inner proofs cannot be independently audited or re-served from the
capsules after expiration. Keeping the included CP03 proof bytes as a separate
ordered audit stream, reusing capsule prefixes, raises the single-copy total
at 100% to 175.350 TB/year. The stream adds one 4-byte length per proof and a
12-byte frame per block. It supports reconstituting exact full CP03 bodies,
recomputing IDs and verifying the preserved inner arguments with a pinned
historical registry. At 95% this policy costs 166.582 TB/year. An independent
all-offered audit copy costs 175.838 TB/year at 100% and 175.802 TB/year at 95%,
including public complete submitted bodies with 4-byte length prefixes. It
adds long-lived transaction-timing and rejected-offer exposure if submission
metadata is also recorded. The model retains public bytes and omits private
transport metadata by assumption. Even an all-offered archive shows only the
particular intake channel's observed submissions. Mempool-wide censorship and
network anonymity require a separate model.

A backup-only wallet needs its complete retained-key inventory, verified
genesis and independently selected endpoint and common history. Current
wallet validity remains delegated to a checking endpoint. The 100% one-,
five- and ten-year scans are about 13.95, 69.76 and 139.51 h of link time alone
at 80 Mb/s. An exhaustive one-year scan upper bound is 200 million, 800
million or 6.4 billion decapsulation attempts for 1, 4 or 32 retained keys.
The one-year 48 h target requires roughly 1,157 / 4,630 / 37,037 attempts/s
with ideal overlap, or 1,632 / 6,527 / 52,213 attempts/s if trials start after
download, before state reconstruction, endpoint acquisition and recovery
spending. Real trial and witness service at this density is unmeasured. A
full-verifying wallet also downloads all proof-carrying blocks and rebuilds
public state before counting recipient recovery. It uses the validator inputs
and then pays wallet scanning and witness costs. The small executed restore
does not establish any of these year-scale recovery times.

A cold validator downloads a complete canonical branch and repeats each
required block proof/state transition from genesis while service of new
traffic continues in the sizing model. Only the live link residual is credited.
The calculator separately exposes a 40 ms serialized GET RTT sensitivity, and
optional measured CPU inputs support a best-case CPU capacity floor. The
current receipt prices a component outside that complete CPU term. Link-only success says nothing about
state IO, serialized commits, cold persistent storage, invalid inputs or
historical data availability. Cold wallet and validator projections include
one 254,584 B public genesis fetch, sized from the measured Gate2 case and
replaceable with `--cold-genesis-bytes`. Gate2's separate 168,591,428 B
laboratory funding frame remains historical evidence. Future ordinary sizing
needs its own issuance rate, verification rules and retained state cost. A working snapshot could improve recovery only
with an explicit authentication and availability boundary.
