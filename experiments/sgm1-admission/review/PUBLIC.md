# Independent public reproduction

The non-author reviewer reproduced the fresh wallet flow, the released 100-operation branch and the two-core admission result. On the same home machine, the independent 100M/year trace consumed 0.134 CPU-seconds per leg across 110 proofs. Peak outstanding work was 2 and the last arrival drained in 0.328 s. Twelve separately initialized historical stores sustained 12.59 operations/s from funding through final database close. [Machine-readable observations](observations.json) · [Author decision](../DECISION.md)

## Provenance and functional comparison

The reviewer anonymously cloned the public HTTPS repository into an empty directory with Git system/global configuration, credential helpers and prompts disabled. The detached checkout was clean, had no object alternates and contained the launch baseline `beae20b4` as an ancestor of `823cdcc43e6e47a4e58e83ba78aefef237f4f04e`. The release tag pointed to this exact source. Node 24.22.1 matched the pinned SHA-256 before each build. The native verifier was compiled from this checkout. The three triggered source workflows all passed. [Source revision](https://github.com/jouliene/pq-private-chain/commit/823cdcc43e6e47a4e58e83ba78aefef237f4f04e) · [SGM1](https://github.com/jouliene/pq-private-chain/actions/runs/44982950623) · [Payment smoke](https://github.com/jouliene/pq-private-chain/actions/runs/44982950545) · [PoW devnet](https://github.com/jouliene/pq-private-chain/actions/runs/44982950539)

The anonymous release download contained 19,313,729 bytes, SHA-256 `eb9126b06ac3d84b628528bb622fb8b331d0f0d7a59548a2ea7473f096bbeb2b`. Inspection found 110 allowlisted public files and their manifest. Every manifest digest matched. The payment and swap frames totalled 20,753,400 bytes. SHA-256 over their 100 individual SHA-256 digests in height order was `70ef83ff5eb5bed20b35da46d8824b9c5d4714e9bf0966a007550059818327bd`. SHA-256 over the concatenated raw frames was `3f5821d9c29610b36f2c98e589333eadab488ca93d35f1f8add9c7256a6f268c`. [Release archive](https://github.com/jouliene/pq-private-chain/releases/tag/sgm1-two-core-2026-11-22)

The reviewer ran `reproduce.sh FRESH walkthrough`, then `reproduce.sh REPLAY public RELEASE/public` in separate scratch directories. The first invocation created a new funded genesis, separate resident swap owners, 18 ordinary payments and two signed pairs. A recipient using only its backup and validated public history produced onward payment 11. Both verifiers accepted all 22 proof legs and rejected the 21 differential changes. All 20 fees, 44 nullifiers and 57 leaves agreed at restart and final replay. The fresh ordered frame-digest list hashed to `c61dcd93abe8b1653643ebdf7753d6f9d04214eff6eb73c1572c08b4c2b976fa`. The release replay accepted all 110 legs, reproduced 233 leaves, 220 nullifiers and 100 fees, checked the 64/65 anchor and 100/101 expiry boundaries, and reached the same root after rollback, conflicting admission and reinstatement. The complete 100-operation controls output matched the author's published file byte for byte. The earlier 179,234-byte proof passed five times after signed funding reconstruction, with all 15 changes rejected. [Expected controls](../evidence/CONTROLS.json) · [Replay procedures](../README.md)

## Admission and repeated history

Each paced trial started with a fresh disk-backed database on ext4. One logical CPU on each of two physical cores was available to the public frame reader, native proof checks, Node signature helpers and synchronous SQLite writer. Outstanding work includes the just-arrived frame. The RSS column gives the sampled peak sum for the process tree. The observer sampled every 20 ms. Table labels 10M, 30M and 100M denote offered operations per year, and the higher rows show offered operations per second.

| Offered workload | Actual ingress (ops/s) | CPU-s/leg | Mean cores | Outstanding peak / last | Drain (s) | Tree RSS (MiB) |
|---|---:|---:|---:|---:|---:|---:|
| 10M | 0.317 | 0.131 | 0.046 | 1 / 1 | 0.335 | 122.3 |
| 30M | 0.951 | 0.133 | 0.141 | 1 / 1 | 0.335 | 122.0 |
| 100M | 3.169 | 0.134 | 0.467 | 2 / 1 | 0.328 | 122.3 |
| 8/s | 8.000 | 0.118 | 1.023 | 3 / 1 | 0.305 | 160.0 |
| 12/s | 12.000 | 0.120 | 1.541 | 5 / 2 | 0.301 | 160.5 |
| 16/s | 15.996 | 0.124 | 1.656 | 25 / 24 | 2.062 | 165.4 |
| 20/s | 19.989 | 0.124 | 1.665 | 40 / 40 | 3.222 | 167.0 |

At offers 10, 50 and 100, outstanding counts at 16/s were 3, 12, 24. At 20/s they were 5, 21, 40. The independent 12/s maximum was 5. The two higher rates accumulated work during the trace. Two proofs and both signatures were checked for every swap.

Twelve new stores each validated the same starting branch. Including funding and final close, 1,200 admissions took 95.31 s and 161.19 CPU-seconds. Individual pass rates ranged from 12.12 to 13.15 operations/s. The highest sampled process-tree RSS was 162.2 MiB. The closed 100-operation SQLite store occupied 21,430,272 bytes. These are short, same-host trials with warm filesystem data and separate processes and stores. P2P transport, PoW, wallet proving, invalid submissions, extended database growth and cryptographic reductions remain outside the service estimate. [Full author traces](../evidence/TRACES.json) · [Cryptographic review](SECURITY.md)
