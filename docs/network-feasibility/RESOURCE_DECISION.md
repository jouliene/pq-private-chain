# Network resource decision — retention and wallet synchronization

The declared eight-batch workload passed independent review. Root provisionally
retains CP03 with **fully retaining validators and a separately provisioned opaque
serving archive**. The full finite wallet campaign also passed independent
evidence review. This implemented model does not evict and has no
unfinished export obligation. This is a finite research allocation, not owner
acceptance of annual costs or ordinary-home-node economics.

The authenticated-continuation implementation now passes Root's genuine nine-proof
wallet scenario and exact32/128/260-block scaling experiment. Independent clean
execution also passed; publication/CI is still pending. The current measured update
path removes the repeated-prefix obligation described in the historical Gate3
section below; complete payment storage and assurance qualifications are unchanged.
See the [current acceptance record](../../experiments/incremental-sync/RESULTS.md).

## Measured service decision

Eight new96-payment batches, including an initial two-batch burst, were offered
at T=30.27456s. All768 ordinary payments were accepted by **287.618316s**, before
the fixed **363.294720s** observation end. The validator was actually stopped for
**90.824782s**, reopened its database, retried the canonical tip with zero new
proof/admission work, and completed the queue. All queues and outstanding credits
were zero at the fixed end. Credits peaked at two; source-pending peaked at four
batches; actual credit backpressure was159.457134s. Different queue maxima are
not assumed simultaneous. Six distinct ordinary-body PUT/GET overlaps were
observed. This answers Gate1's scheduling uncertainty for the finite workload;
it does not establish indefinite stable service.

All14 source/destination SQL tables matched, excluding only local catalog identity.
Isolated native validator processes checked all864 genuine proofs (96 funding,
768 ordinary) and96 source signatures. All13 role incarnations exited successfully.
Current-tip retry is not a new payment. Gate1's malformed-final-proof/atomicity,
interrupted transfer and archive crash/lost-ACK controls remain closed evidence.

See [predeclared profile](../../experiments/network-feasibility/GATE2_PROFILE.json),
[raw network evidence](../../experiments/network-feasibility/evidence/gate2-96x8-01-network/RESULT.json),
[author readback](../../experiments/network-feasibility/transport/GATE2_FULL01.json)
and [independent review](../../experiments/network-feasibility/review/PIPELINE_FULL03_ACTUAL01.json).
The historical profile declaration is deliberately not rewritten after execution.

This was paced loopback:100Mbit/s **per direction**,40ms once/RPC, onePUT/oneGET,
CPUs0/1/2 for measured roles,4GiB address space and8GiB disk per role. Shared host,
warm/uncontrolled caches and tiny state are explicit. It is not WAN, cold-disk,
arbitrary-fanout or year-long capacity evidence. The separate experimental
controller had affinity0..11 and consumed **218.785783 CPU seconds** after pin
preflight; its cumulative933504KiB RSS peak includes preflight. Preparation,
scheduling and post-observation SQL oracle costs are additional experiment costs.
No phase split was measured; do not claim the whole experiment used only3CPUs.

## Complete role costs and projections

The owner supplied100M offered payments/year, **no annual traffic limit**. Annual
values are analytical projections, not observations or universal rejection caps.
The768 ordinary bodies total1344972096B, mean1751265.75B/payment.

| Role | Actual evidence | Annual implication and unresolved cost |
|---|---|---|
| Validating node | Complete ordinary96 commands about20.62–20.85s. Across funding/ordinary/restart/retry, native SELF CPU67.819430s plus waited helpers3.604015s separately. Sampled tree peak411572KiB. FinalDB1523658752B logical, retained bodies1513556768B, pending/missing/unexported0. | **175.126575TB/year** per body copy, about44.43Mbit/s mean incoming body traffic, plus growing public state/history/undo/indexes. Full retention exists; remote-pruned participation does not. |
| Archive | Ten opaque objects1513872156B logical/1513926656B allocated, CPU11.572017s. PUT RX1513872676B and GET TX1682007932B include framing, funding and retry. No payment verification or remaining partial object. | Another175.126575TB/year per copy before replication/repair. Six full streams average about266.56Mbit/s egress before overhead. ACK is a durability assertion, not permanent availability; same-host roles are not independent failure domains. |
| Miner | No mining executed. Admission inherits genuine validation and relevant relay/history duties. | Puzzle work, issuance, competitive hardware and economic security remain unimplemented and unpriced, not zero. |
| Wallet | Historical full264-proof campaign established local witnesses and recovery. The new nine-proof scenario preserves those paths with authenticated continuation; measured260 one-block appends return1492866B and authenticate260 blocks. Clean independent execution reproduced the exact counts. | Ordinary updates now charge one common-history pass plus bounded per-request framing. Conditional96-payment batching gives about502.696GB responses +0.454GB requests/year; endpoint acquisition, transport/retry, key scanning, reorganization and cold replay remain additional. No ownership-selective fetching. |

Generation is separate:96credit+768ordinary complete proofs took6639.207363s wall,
6619.042769 CPU seconds and first-wait4 peak248668KiB. It includes private bridge,
fixture receipt/membership and local admissions. Pre-generated proofs drove the
network experiment; this is not live wallet throughput. All producer physical
copies, including Parent metadata/proofs and prepared frames, total**7744724992
allocated bytes**, below the declared8GiB allocation. Duplicates are charged.
Safe raw generation metadata is in
[evidence/gate2-96x8-01-producer/](../../experiments/network-feasibility/evidence/gate2-96x8-01-producer/).

Existing source-derived state field counting gives83.200GB/year for two-nullifier,
two-output fields and occupied tree values. Row/index/undo/header/history/catalog
overhead is excluded. This is neither measured year-sized SQL nor a protocol-wide
minimum. [RESOURCE_MODEL01.json](../../experiments/network-feasibility/evidence/RESOURCE_MODEL01.json)
and resource_model.py preserve that calculation and its historical Gate1 sample.
Using the new body mean, one year's bodies alone need about162.15days at100Mbit/s
or16.22days at1Gbit/s without contention. Validation, incoming traffic, availability
and older years are additional. Trusted database opening is not authenticated
bootstrap; no checkpoint verifier is implemented or priced as free.

## Historical integrated wallet campaign at the reviewed baseline

The predeclared full campaign used K8 owned notes, R8 retained rewind checkpoints
and A256 accepted-anchor history; these are finite research bounds. It created
264 distinct proofs and performed265 positive proof admissions, four rollbacks
and two typed Anchor rejections with all14 tables unchanged. The selected final
branch has260 blocks,261 bodies,522 leaves and516 nullifiers; total1100000000,
fees551305634, remaining note supply by conservation548694366, liabilities0.
Its457020724 retained full-body bytes have no pending/missing/export obligation.

The original isolated wallet span was2240.169956s; backup-only new-process restore
and new spending took11.983326s. Node SELF CPU51.51s/1.80s and waited descendants
1383.81s/6.34s are separately scoped. Sampled concurrent tree RSS peaked at
389376/349108KiB. Nested proof-worker wall483.392890s is already inside those
wallet spans and must not be added again. Native CLI CPU778.148485s and controller
SELF81.006325s are additional experiment costs; controller cumulative933504KiB
includes preflight. This heavily instrumented sequential branch experiment is
not live network throughput or an exhaustive memory-peak measurement.

The265 full-history reads total187364746B and26.718863s processing, versus the
last1374318B common-history response. The136.33 cumulative/final ratio includes
all wallet sessions, replays and restore; it is not a universal multiplier.
That baseline refresh authenticated the complete prefix before applying new
suffix leaves. It was functional local-witness recovery; the subsequent
continuation implementation below replaces its ordinary synchronization path. All public experiment copies cost2083110912 allocatedB at
measurement. Source/runtime stayed unchanged; no private backup/stream was
persisted or hashed. Full evidence is
[wallet-full01](../../experiments/network-feasibility/wallet-integration/evidence/wallet-full01/RESULT.json)
and the [independent readback](../../experiments/network-feasibility/review/GATE3_FULL01_ACTUAL01.json).

Independent reproduction used a clean checkout with the original project,
research tree and dependency caches hidden. The new build produced four ELFs and
passed eight provider controls. A new isolated small5 wallet cycle then passed,
including new-process backup recovery and a newly proved spend. Finally a fresh
public-only ledger verified all264 full01 proofs,265 positive admissions, four
rollbacks and two atomic Anchor rejections in341.039873s outer wall time. Final
selected head and all14 canonical tables matched; only local catalog identity is
excluded. This fresh-CLI replay cost is not persistent-validator throughput.
No old database, private wallet or Parent verdict seeded its acceptance. The scope
combines independently reviewed full private expiry/rewind evidence with new
small5 and public replay; it does not claim a second full private264 campaign.
Safe receipts and exact commands are in
[gate5-clean](../../experiments/network-feasibility/evidence/gate5-clean/).
The independent replay directory occupies926965760allocatedB, including its copied
public inputs and fresh database. Later public export, clone-input and release
archive copies are separately counted in
[GATE5_PUBLIC_STORAGE01.json](../../experiments/network-feasibility/evidence/GATE5_PUBLIC_STORAGE01.json).
Those delivery copies are additional to the original experiment's at-measurement
disk figure; build/source/toolchain/Git storage is a separate infrastructure cost.


## Authenticated continuation: corrected wallet cost

The current source checkpoint is17dd4e73f4fbde9fee2129d0fd761b864eefe42f. In the
fixed genuine260-block dataset,260 one-block append requests total113360B; replies
total1492866B, including436B of continuation framing per reply. Wallet authentication
covers260 blocks and261 reduced payment records. The exact old repeated-prefix
response obligation for those same frames is181853424B and33930 authenticated
blocks. Smaller32/128-block cases match the same formula. Actual indexed serving
rows/blob counts, base/target/startup checks and SQL fullscan counters are recorded
in the [raw trace](../../experiments/incremental-sync/evidence/trace01/RESULT.json).
Physical disk pages, WAN behaviour and a growing production DB were not measured.

For frame lengths F_i and N updates, responses are `sum(F_i) + 436*N`; requests
are `436*N`. Ready unchanged heads require zero history requests/authentication.
The previous response cost was `sum((N-i+1)*F_i)`. A shallow reorganization charges
its replacement suffix from the wallet's retained joint checkpoint; a deeper
selection and cold recovery charge a full replay. Neither reorganization nor
recovery cost is hidden in the append claim. Actual cold restoration in the small
genuine scenario reads94218B/259blocks and then proves and admits a new spend.

For an explicit analytical scenario of all100M offered two-input ordinary payments
being included in96-payment blocks, there are1041667 blocks. Current reduced
records plus common block framing cost502241666744B. One request and one response
header per block add454166812B in each direction:502695833556B responses and
454166812B requests, or503150000368B combined. This is approximately503.150GB of
protocol range traffic, not complete annual wallet operation or an owner budget.
Endpoint acquisition, other transport framing, retries, reorganization, full cold
scans and retained-key receiving/witness CPU are additional. Different batching,
update cadence, arities or a future privacy scheme change this calculation.

The exact finite improvement does not establish a numerical PQ/privacy theorem.
Complete payment proof parameters, default private receiving, value/ownership/
membership constraints, nullifiers, source authorization and atomic admission are
unchanged. Requests reveal only common public ranges under the same synchronization
state/target; this does not hide source choice, IP address, timing or activity.

## Participation decision and next investment

The selected finite research model is implemented and services the declared
workload. **Affordability/decentralization at the annual sizing input remains
unresolved.** Validator plus archive body copies alone are350.253TB/year. Storage,
history availability, growing state and new-node bootstrap remain material
architectural problems. Faster processing does not settle them; owner acceptance
is not inferred.

Remote pruning is unimplemented: the network frame ACK is not the local catalog's
DurableBatch. A later change needs explicit remote durability policy, authenticated
object identity, restart-safe catalog/eviction and bounded verified refetch with
fail-closed availability. Forged local locators, silent policy conversion or
forgetting nullifiers/undo on anchor expiry are invalid. The earlier
[participation review](../../experiments/network-feasibility/review/GATE2_PROFILE_PARTICIPATION_REVIEW01.md)
identifies these seams. Today's selected model pays for full copies instead.

The historical network milestone's clean reproduction and automatic CI remain
closed evidence. Independent execution of the current synchronization milestone
has also passed; its own CI and publication gates remain and do not inherit the
historical PASS.
After those gates pass, stop expanding synchronization work. The next concrete
proof-size experiment is specified in
[NEXT_EXPERIMENT.md](../../experiments/incremental-sync/NEXT_EXPERIMENT.md); it is
a future bounded gate, not an experiment started by this milestone.

This removes repeated prefixes but leaves the first-copy175.126575TB/year
obligation. The subsequent global architecture priority is a materially smaller
complete payment/storage route unless a costed participation model is explicitly
adopted for a stated research scope. Full PoW/issuance integration is deferred;
standalone PoW remains the preferred direction, not an implemented consensus.
A larger test disk is a useful experiment resource, not adoption of the annual
participation model.
Formal PQ/privacy, network anonymity and production readiness remain separate in
[OBLIGATIONS.md](OBLIGATIONS.md).
