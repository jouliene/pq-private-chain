# Network resource decision — finite Gate2 passed; Gate3 authorized

The declared eight-batch workload passed independent review. Root provisionally
retains CP03 with **fully retaining validators and a separately provisioned opaque
serving archive** for Gate3. This implemented model does not evict and has no
unfinished export obligation. This is a finite research allocation, not owner
acceptance of annual costs or ordinary-home-node economics.

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
| Wallet | Genuine receiving/proving exists; Gate3 joint local witnesses, rewind and isolated recovery are pending. Ordinary reduced record4952B, common scan framing5022.417B/payment at96-body batching. | About**502.242GB/year** common scan plus requests/retries, per-key receiving and witness work. Transfer alone about11.16h at uncontended100Mbit/s. No ownership-selective remote fetching. |

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

Next execute actual Gate3 receiving/local witnesses, changing-root expiry, rewind,
backup-only fresh-process recovery and new spending. Independent clean-checkout
reproduction and reviewed publication follow. Final handoff must decide whether
a specific storage/bootstrap change precedes permissionless PoW integration;
this finite pass alone does not justify a full consensus build. Formal PQ/privacy,
network anonymity and production readiness remain separate in
[OBLIGATIONS.md](OBLIGATIONS.md).
