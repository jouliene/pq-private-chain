# N3B1 component measurements, 21 November 2026

Measurements use this checkout's small C/Node programs, one process per run, Intel i7-8700K, Ubuntu x86-64, GCC 13.3.0 -O3, libcrypto/OpenSSL 3.0.13 for C, project Node 24.22.1/OpenSSL 3.5.9 for ML-KEM. No funded proof campaign was run. Commands are in the [operator notes](README.md#reproducible-resource-screen).

| Independent process | Three-view Keccak-f CPU ns | Opened pair check CPU ns | SHAKE256 tape B/CPU s | SHA3-512 view B/CPU s | C peak KiB |
|---|---:|---:|---:|---:|---:|
| 1 | 2,222.80 | 1,181.00 | 455,178,553 | 250,662,686 | 5,888 |
| 2 | 2,176.86 | 1,187.14 | 456,875,480 | 250,758,364 | 5,888 |
| 3 | 2,213.77 | 1,191.26 | 448,898,980 | 246,907,246 | 5,888 |

Each C sample times 1,024 actual bit-packed three-share Keccak-f calls with affine and chi rounds and precomputed deterministic public test tapes, then 1,024 two-view checks. The verifier accumulation covers every first-party AND; the timing loop varies the initial state but uses the last captured transcript, so most iterations exercise a full-length failing verification. Correct public-state recombination, a valid first-party check and a tampered-share rejection are individually asserted before timing. Each primitive throughput uses 16 × 512 KiB. Complete 2x2 proof generation/verification, system I/O, randomness setup, exact interpreter overhead and adverse scheduling have no measured end-to-end times.

| Independent process | Receipt encrypt µs CPU | Seed-restored key match µs CPU | Unrelated key miss µs CPU | Node peak KiB |
|---|---:|---:|---:|---:|
| 1 | 93.51 | 100.97 | 84.36 | 62,172 |
| 2 | 96.06 | 97.91 | 81.52 | 62,592 |
| 3 | 96.99 | 98.39 | 81.70 | 62,532 |

Each receipt operation had 32 warmups plus 512 timed trials. The benchmark regenerates the key from the fresh original 48-byte backup, opens one honest output and locally rejects an unrelated key, altered context, commitment or ciphertext. It measures the native ML-KEM, HKDF and authenticated opening path. The timing loop uses a warm key on one envelope to price the per-key operation. This does not measure fetching 20 years of history, distinct cold keys, a funded backup respend, a real proof or recipient anonymity. The JavaScript process aggregate includes initialization/JIT; its peak RSS is separate from C.

## Whole-packet costs and limits

| Per wallet-created proof / public verifier | Wallet, streaming two passes | Public node, streaming one pass |
|---|---:|---:|
| Keccak-f share simulations/checks | 110,880 | 55,440 |
| SHAKE256 mask stream | 1,611,701,280 B | 537,233,760 B |
| SHA3-512 committed view payload | 813,313,200 B | 542,208,800 B |
| Modeled CPU from those three kernels | 7.01–7.13 core-s | 3.40–3.46 core-s |
| Planned working buffers | 3,217,096 B | 2,101,192 B |

For each sample multiply its unit timings by the algorithm counts and add the two bulk stream times. Wallet pass 1 commits all three views; after computing FS the wallet regenerates three shares/tapes and writes the selected views for each repetition. The model excludes the remaining 35,777 Boolean gates per repetition, witness-share expansion, challenge, receipt work, signatures, all final serialization, transport and node state writes. It is a calibrated component subtotal, neither an observed end-to-end time nor a machine-independent lower bound. One proof author stays local. A swap uses two such authors and two verifications plus two signatures, with no shared witness. The 3.40–3.46 core-s applies to a hypothetical widened frame; current frame rejection only needs a validated length prefix.

The working buffer schedule stores the first message, 4 × 64 × 560 private seed bytes for the prover, up to three complete views and tapes per repetition, two input-share buffers and 64 KiB scratch. The verifier reuses two views/tapes, first message and the same scratch. These algorithm buffers exclude memory allocator/native runtime, path indexes, wallet databases and full packet copies. A materialized packet alone adds 542 MB per leg, and a materialized swap bundle adds 1.085 GB. Streaming avoids those copies without altering transmitted/archived bytes. The separate measured C and Node process peaks do not establish a combined wallet RSS.

At 10M/30M/100M accepted operations/year using the shared 90% transfer and 10% swap mix the packets alone cost **5.966 / 17.897 / 59.656 PB** of archive input and one relay copy per year (decimal, before framing, consensus, retries or replicas). At 100M/year the mean ingest is **15.12 Gbit/s** (365.25 days), the verifier kernel subtotal alone is 11.9–12.1 CPU cores at 100% utilization for 110M legs/year, and 20 years retains **1.193 EB**. A 100 Mbps down / 20 Mbps up household, 2 dedicated CPU cores, 16 GiB RAM and 2 TB pruned disk is the research comparison profile. A 542 MB ordinary packet takes at least 43.4 s on that downlink and 216.9 s on the uplink before contention. Full pair upload takes 433.9 s. Pruning after validation saves historic disk, with the same full-validation ingest requirement.

Each of the 220M output occurrences/year at 100M mixed operations entails one funded leaf and (for this all-real 2x2 profile) one spent NF per output in steady-state volume terms. Keeping 48-byte spent digests alone costs 10.56 GB/year raw; a separately materialized occurrence uniqueness set adds another 10.56 GB/year. Retaining every completed binary subtree digest uses <2 digests per appended leaf including the leaf, <21.12 GB/year before mappings and database overhead, with a small current branch frontier. A wallet scan projection containing kind, both NFs, two commitments and two receipts takes 3,649 B/leg, about 401.39 GB/year or 8.03 TB over 20 years in that mix, *before* authenticated page proofs, block headers, special funding and availability costs. An accepted-spend-only compact stream needs an independently authenticated completeness rule or full-block verification; it is not an executed synchronization product. The 4.4 billion envelope attempts over 20 years cost approximately 100–103 CPU hours **per retained key** at the measured warm miss rate, in addition to PoW/header, authenticated-page/path checks and local database/reorg work. Quantities scale linearly with accepted load and independently retained receiving keys. No traffic cap is attributed to the owner. [Exact packet sizes and pure-workload projections](PRICE.json)
