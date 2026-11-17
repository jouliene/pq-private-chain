# Network resource decision — Gate1 accepted, Gate2 pending

The actual 96-payment separate-process path passes its functional and finite
retention controls. Retain the unchanged CP03 backend for the declared next queue
experiment. Do not yet accept an annual participation model or begin full Gate3
integration. A concrete remote pruning mechanism and its costs are still open;
the observed scheduling gap alone does not justify changing cryptography.

## Measured result and next falsifiable question

The ordinary destination command took **20.837566 s**, including receive,
identity checks, parse/copy, real proof/state validation and durable RETAIN.
Producer upload took **13.949979 s**. Their serialized stage-cost sum is
**34.787545 s**, above the **30.27456 s** comparison interval for 96 payments at
100 million offered payments per 365-day year. It is not an observed sojourn or
steady throughput. The next declared test must actually overlap upload and
destination service, measure shared archive contention, and account for all
queues during a burst and stopped/restarted validator.

The experiment uses application-paced local loopback, independent full-duplex
100 Mbit/s directions, one archive PUT and one GET slot, and 40 ms once per RPC.
It does not reproduce WAN loss, congestion, TCP windows, cold disks or a year of
indexed state. See [the complete Gate1 cost record](../../experiments/network-feasibility/transport/GATE1_REVIEW.md),
[independent readback](../../experiments/network-feasibility/review/GATE1_96_READBACK01.json)
and [predeclared Gate2 profile](../../experiments/network-feasibility/GATE2_PROFILE.json).

## Role costs and projections

All annual figures below are analytical scenarios derived from current formats
and the actual 96-payment sample. The owner specified the offered payment count,
not an annual traffic cap, hardware budget, archive replication count or catch-up
deadline. No laboratory funding is extrapolated as permissionless issuance.

| Role | Actual evidence | Annual sizing implication and unresolved cost |
|---|---|---|
| Ordinary validating node | Ordinary 96 receive-to-commit 20.838 s, native CPU 7.348 s; retained actual 192-body database 340.255 MB including funding. Sampled campaign process-tree peak 463,940 KiB. | One incoming full-body copy averages about 44.43 Mbit/s. Current RETAIN adds about 175.160 TB/year of bodies. A pruned ordinary-node path is not yet implemented through the network archive. Public state, history, undo and indexes continue growing even after body eviction. |
| Archive | Actual final 505.183 MB contains genesis, funding, valid ordinary and a separately charged invalid-control frame. All crash/retry traffic is counted. It stores opaque bytes and performs no payment validation. | About 175.160 TB/year per full-body copy, before metadata, replication and repair. Each additional full stream repeats that egress duty; six outgoing copies average about 266.61 Mbit/s before framing/retries. An ACK is a configured server's durability assertion, not proof of permanent future availability. |
| Miner | No mining executed. A miner accepting these payments inherits genuine validation and relevant relay/history obligations. | Puzzle work, competitive hardware, reward issuance and economic security are unimplemented and unpriced. They are not zero and cannot replace the ordinary-node cost row. |
| Wallet | Existing receiving composition is genuine. The new common-history selective witness algorithm is not integrated yet. Actual ordinary reduced record is 4,952 B; framed common scan averages 5,022.417 B/payment at 96-body blocks. | About 502.242 GB/year of common scan at this batching, before request/retry overhead. At an uncontended 100 Mbit/s, one year's transfer alone takes about 11.16 hours; receipt decryption, number of receiving keys, authentication and local witness work are additional. No ownership-selective remote fetching is assumed. |

The producer created 96 credit plus 96 ordinary genuine proofs in 1,439.136 s.
That includes private bridge checks, fixture receiving/membership work, repeated
local ledger admission and safe public output. It is separate from sender/network
service and is not live wallet throughput. Gate2 uses newly generated proofs;
repeated delivery of existing payments does not count as new offered workload.

Current-schema field counting for a 100M two-input/two-output ordinary scenario
gives about **83.200 GB** for nullifier IDs, CORE IDs, funded leaf origin/commitment/
body IDs and occupied tree values alone. This excludes reduced history, headers,
row keys and overhead, indexes, undo, archive catalogs, funding and journals.
It is neither a measured large database nor a minimum required by every possible
protocol. The actual source-derived node formula reproduces the observed 799
nodes for 384 funded leaves. Do not infer constant-size state from a body-cache
quota or erase spent nullifiers when an anchor expires.

Fresh full validation currently needs genesis replay. One year's full bodies
alone take about **162.19 days at 100 Mbit/s** or **16.22 days at 1 Gbit/s** to
transfer without contention. Those are transfer-only calculations: validation,
current incoming traffic, server availability, indexes and older years are
additional. Opening an operator-trusted local database is not authenticated
bootstrap. No checkpoint verifier is implemented or priced as free.

Reproduce the byte/state calculation without new proofs or database mutations:

```sh
python3 -I experiments/network-feasibility/resource_model.py \
  --workload experiments/network-feasibility/producer/.work/gate1-96.public/workload.json \
  --approve-workload 338ddf2f36ea74d7e193dd7f14b4d779588bb0fffa5c3c36f2f820aa4bfcfc42 \
  --output /absolute/new/resource-model.json
```

[RESOURCE_MODEL01.json](../../experiments/network-feasibility/evidence/RESOURCE_MODEL01.json)
contains actual read-only SQL/page and scan lengths, formulas' outputs and their
scope. Independently regenerated workloads have their own exact manifest digest;
the historical Gate1 generator remains available at commit `2ab99fb`.

## Participation decision boundary

The proposed ordinary participant would verify every incoming complete payment,
retain a bounded recent full-body cache plus explicitly growing public state and
common history, and retrieve older full blocks from provisioned archives when
serving/replaying/deep-rewinding. Archive loss would fail closed; it must never
permit unchecked acceptance. Replicas and incentives remain separate duties.

This is presently a **specified direction, not a demonstrated implementation**.
The TCP frame archive does not produce the local catalog's `DurableBatch`.
Canonical local eviction requires matching committed archive objects. Local
archive tiering only moves bytes to another volume of the same operator; it
does not make remote pruning exist. A remote policy needs explicit durable
publication, restart-safe catalog/eviction and bounded verified retrieval, with
no forged local locators or silent policy conversion. The independent
[participation review](../../experiments/network-feasibility/review/GATE2_PROFILE_PARTICIPATION_REVIEW01.md)
identifies exact API seams and the smallest genuine failure/retrieval test.

After Gate2, decide separately whether the measured configuration services its
finite offered workload and whether a concrete participation model is supportable
enough to retain for the next research investment. A finite drain, a larger disk
quota, or an external archive in a diagram cannot decide the second question.
Owner acceptance of proposed costs remains separate. Full wallet integration,
independent clean-checkout reproduction and milestone publication are pending.
Formal PQ/privacy composition, network anonymity and production readiness remain
qualified as stated in [OBLIGATIONS.md](OBLIGATIONS.md).
