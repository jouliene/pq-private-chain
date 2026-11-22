# Two-core admission for four-group SGM1

**Advance the native verifier for isolated protocol development. Keep C on the funded PoW chain.** On two physical cores of an i7-8700K, the validator kept up with 3.169 mixed operations/s, the 100M/year scenario. It used 0.141 CPU-seconds per proof-bearing leg, including transaction-specific setup, signatures and durable state changes. On this 100-operation trace, 12 offered operations/s kept the outstanding queue bounded to five. At 16/s it reached 22. Twelve empty-database historical replays sustained 12.77 operations/s. This resolves the earlier CPU objection under the measured conditions. The proof and receipt composition still needs cryptographic assurance. [Raw admission traces](evidence/TRACES.json) · [Security review](review/SECURITY.md)

## Measured live load

Each row used the same 90 distinct payments and ten independently authorized swaps, with a swap as every tenth operation. Each group used a newly funded root and count. The public frame reader, verifier workers, signature helpers and SQLite writer shared an affinity mask with one logical CPU on each of two physical cores. The host ran Linux Mint 22.3, GCC 13.3, OpenSSL 3.0.13 for the native SHAKE implementation, Node 24.22.1 with OpenSSL 3.5.9 for SLH-DSA, and SQLite 3.45.1 on ext4/NVMe. Fixture proving and the correctness oracle were outside the timings.

| Offered rate (ops/s) | Wall to 100th commit (s) | CPU-s per leg | Mean cores used | Outstanding peak / at last offer | Drain after last offer (s) | Sampled peak RSS, process tree (MiB) |
|---:|---:|---:|---:|---:|---:|---:|
| 0.317 (10M/year) | 312.76 | 0.131 | 0.046 | 1 / 1 | 0.339 | 122.2 |
| 0.951 (30M/year) | 104.44 | 0.133 | 0.140 | 1 / 1 | 0.298 | 122.1 |
| 3.169 (100M/year) | 31.58 | 0.141 | 0.491 | 2 / 1 | 0.339 | 122.1 |
| 8 | 12.67 | 0.117 | 1.015 | 3 / 1 | 0.298 | 159.6 |
| 12 | 8.56 | 0.116 | 1.492 | 5 / 2 | 0.308 | 160.2 |
| 16 | 7.88 | 0.118 | 1.650 | 22 / 21 | 1.690 | 164.7 |
| 20 | 7.69 | 0.117 | 1.673 | 36 / 36 | 2.738 | 167.3 |

An outstanding operation has entered the reader and has yet to commit. The final arrival itself counts. At 16/s the outstanding counts at the 10th, 50th and 100th offers were 2, 12 and 21. At 20/s they were 4, 20 and 36. The maximum paced-offer lateness in any row was 3.2 ms. At the 100M rate, median and maximum ingress-to-commit latencies were 151 ms and 347 ms. The 100 final frames contained 110 proofs and used 15.51 CPU-seconds at that rate. Its 0.574 CPU-s/leg comparison is `2 × 365.25 × 86400 / 110,000,000`. The experiment does not price invalid-traffic floods, peer transport, ordinary PoW validation or many years of database growth. The largest paced trial lasted 312.76 seconds. [Method and resource definitions](README.md) · [Calendar calculations](evidence/CAPACITY.json)

The non-author's anonymous checkout also accepted 18 newly generated ordinary payments and two new swaps, including the restored wallet's onward spend. On the exact released 100-operation corpus the complete functional result matched byte-for-byte. At 100M/year this run used 0.134 CPU-s/leg and 0.467 mean cores with two outstanding at peak. At 12, 16 and 20 offers/s, respectively, the last offer found 2, 24 and 40 operations still outstanding. Its 1,200 historical admissions took 95.31 seconds including signed funding and database closure, or 12.59 operations/s. Both runs support the same operating decision. [Independent reproduction and CI](review/PUBLIC.md)

## Historical validation and body costs

Every historical pass reopened an empty database, verified the funded genesis and two issuer signatures, admitted the same 100 original frames exactly once and closed its WAL database. All twelve reached the same root. Summed funding-to-close wall time was 93.98 s for 1,200 historical admissions. Individual pass rates ranged from 12.59 to 12.97 operations/s. The total CPU including funding was 156.06 CPU-seconds. Summed process-tree RSS samples peaked between 160.4 and 218.3 MiB across the passes. The comparison uses warm filesystem data, a bounded reader queue, and new verifying processes and stores. It excludes downloading the archive from peers. Each closed 100-operation store occupied 21,430,272 bytes, including signed frames, indexes, tree nodes and rollback history. [All twelve pass records](evidence/HISTORICAL_REPLAYS.json)

A payment was 183,224 bytes, a signed leg was 213,152 bytes, and a complete ordered swap was 426,324 bytes. Each proof was 179,234 bytes at every measured count. The 100 frames totalled 20,753,400 bytes. The following projections use that actual mix. Replay time uses the first measured post-funding, through-close service rate of 12.85 operations/s. Concurrent arrival figures subtract the comparable live arrival rate from historical service. They assume the same state cost, bandwidth, cadence and hardware remain available at that scale.

| Annual included operations | One copy of payment/swap frames (TB) | Historical replay, no new work (days) | Clearing that year while current traffic continues (days) |
|---:|---:|---:|---:|
| 10M | 2.075 | 9.0 | 9.2 |
| 30M | 6.226 | 27.0 | 29.2 |
| 100M | 20.753 | 90.1 | 119.5 |

Each additional full relay copy carries the same frame payload. Block framing, indexes, replicas, forks and network protocol bytes add to the body figures. A long-offline wallet also needs authenticated receipt history and local scanning. At 100M operations the mix creates 220M encrypted output slots per year. No annual storage or traffic allowance has been accepted by the owner. [Data and projection formulas](report.py)

## What was admitted

Eleven native grants and two signed fixed issues funded the isolated genesis prefix. Two resident processes created and kept their own swap spending, receiving and final approval keys. Each checked the other leg's incoming asset, quantity, native value and its own ability to open the note before signing the common pair. Role 1 paid one native fee and role 2 paid zero. The isolated writer accrues fees and performs no mining or reward issuance. The ordinary first-time recipient recovered a note with eight native units from its original 64-byte backup and verified public history. Operation 11 paid four onward, left three in change and paid one fee. [Wallet](wallet.py) · [Two-owner protocol](swap_owner.py)

Each block changed the incremental funded tree. The ten proof anchors had counts 13, 35, 57, 79, 101, 123, 145, 167, 189 and 211. At height 100 the result had 233 output occurrences, 220 registered nullifiers and 100 accrued fees. Current spentness and anchor eligibility were rechecked under the ordered write lock, including for preverified operations after a competing commit or reorganization. When the replacement failed validation, the original state survived intact. The controls compare the full occurrence table, tree, nullifiers, block identities, canonical body digests and undo rows across restart and branch changes.

| Selected state | Height | Output count | Cumulative fee | First-swap nullifiers present (owners 1 / 2) | First-swap outputs present (legs 1 / 2) |
|---|---:|---:|---:|---:|---:|
| Rewound common prefix | 9 | 31 | 9 | 0 / 0 | 0 / 0 |
| Competing ordinary spend | 10 | 33 | 10 | 2 / 0 | 0 / 0 |
| Selected complete swap | 10 | 35 | 10 | 2 / 2 | 2 / 2 |

The reference and native implementations accepted all 110 legs on identical public data and rejected all 21 full-length differential alterations. The real conflicting payment passed on the alternate branch. The original swap survived reintroduction, and neither a detached root nor an already verified result for that root could authorize a debit. Tests distinguished a 64-block eligible base from the subsequent expired base and checked the last swap at its height-100 expiry boundary. The C++ verifier reconstructs the full monetary wiring on each call and consumes all DECS, masked Keccak GKR, selector, scalar, trace, ring, Q, Merkle and degree-completion data. The previous ordinary reference packet is included in the release. In a separate wiring test the native and Python compilers agreed on every public constant and wire address for eight registration vectors spanning counts from one through 2^40. Only the algebra and permutation tables stay warm. Loading the library cannot supply a payment verdict. [Registration](native/README.md) · [Functional and adversarial evidence](evidence/CONTROLS.json) · [Public test corpus](https://github.com/jouliene/pq-private-chain/releases/tag/sgm1-two-core-2026-11-22)

## What still determines promotion

The next decision is whether a quantum adversary accepting this exact adaptive transcript can be reduced to a funded witness with a defensible concrete loss. It requires a prefix extractor or an equivalent quantum interactive knowledge argument for the registered masked GKR plus the custom Artin–Schreier terminal, authenticated adaptive linear openings and the actual Fiat–Shamir schedule. The existing SmallWood+ result and generic multi-round transformations supply ingredients with distinct premises. A separate simulation must cover proofs together with ML-KEM-1024 receipts, retries, later spends and each observer's auxiliary information. The negotiating coordinator sees offers, descriptors and draft cores. A substituted, unauthenticated KEM descriptor can expose a proposed receipt before an honest wallet refuses final approval. The experiment demonstrates settlement with cooperative negotiation on one host. Funded migration, peer transport, archive participation, malicious-relay confidentiality and a 128-bit end-to-end quantum claim remain open. Obtain external review of these two composition statements before promoting SGM1 to a funded network. [Independent source-to-theorem map](review/SECURITY.md) · [Reproduction](README.md)


The tested code is [823cdcc43e6e47a4e58e83ba78aefef237f4f04e](https://github.com/jouliene/pq-private-chain/commit/823cdcc43e6e47a4e58e83ba78aefef237f4f04e). All three applicable GitHub Actions passed at this exact revision. [Fresh SGM1 admission](https://github.com/jouliene/pq-private-chain/actions/runs/44982950623) · [PoW devnet](https://github.com/jouliene/pq-private-chain/actions/runs/44982950539) · [Research payment smoke](https://github.com/jouliene/pq-private-chain/actions/runs/44982950545)
