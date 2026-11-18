# Wallet proof and participant costs at 100M offers per year

The three complete WHIR payments averaged **263,292 B per submitted payment** and **0.09838 CPU s per warm public verification plus ordered durable application**. At 100% inclusion that corresponds to **26.336 TB for a year of framed blocks and 1.58 dedicated cores for a 90-day replay while following live payments**. The archived bodies and received ciphertexts are needed even when a node discards its own copy. The two archive budgets refer to decimal TB in a single canonical copy. They are service comparisons. The only owner sizing input is 100M offered payments per 365-day year. [Source results](wallet/evidence/RESULT.json) · [durable measurements](wallet/evidence/DURABLE.json) · [calculator](roles.py)

## Wallet-created WHIR

| Projected role metric | 95M included | 100M included |
| --- | ---: | ---: |
| Wallets' total submission payload, TB/year for all 100M offers | 26.3292 | 26.3292 |
| Complete canonical archive, one copy / three independent copies, TB/year | 25.019 / 75.058 | 26.336 / 79.009 |
| Retention of 1 / 5 TB in one copy, days | 14.6 / 72.9 | 13.9 / 69.3 |
| Primary archive egress for two replicas plus one full live stream, Mb/s | 19.04 | 20.04 |
| One requesting peer, pool / block-only / both-phase upload, Mb/s | 6.69 / 6.35 / 13.04 | 6.69 / 6.68 / 13.37 |
| Six requesting peers, both phases / ideal one-peer cross-phase reuse, Mb/s | 78.17 / 6.69 | 80.18 / 6.69 |
| 10× demand for 600 s, block-only / both-phase drain, seconds | 2,950 / 23,164 | 3,271 / 26,870 |
| 100 offers/s for 600 s, block-only drain, seconds | 11,442 | 12,530 |
| Required validation cores for 90-day replay while live, warm public plan | 1.50 | 1.58 |
| One-year catch-up while live at 80 Mb/s, link-only lower bound, days | 31.5 | 33.3 |
| One-year catch-up while live on 2 cores, warm CPU-only lower bound, days | 63.5 | 67.5 |
| One-year catch-up on 2 cores, plan rebuilt each 96 / each 3, days | 72.7 / 950 | 77.4 / 1,158 |
| Required inbound for 90-day archive plus live block peer, Mb/s | 32.09 | 33.78 |
| Projected block-only pruned node after one / five years, decimal TB | 0.832 / 4.107 | 0.875 / 4.323 |
| Live receiving wallet common history, GB down/year | 477.8 | 503.0 |
| Cold receiving wallet one-year history, GB down / link-only hours | 477.1 / 13.25 | 502.2 / 13.95 |

A wallet sends its full proof plus both ciphertexts for each offer; the pool cannot pull those bytes out of a header. Add 12 B per offer for the model's wallet frame. The peer inventory model charges six inventory messages, upstream request/body and one requesting downstream peer per object. A block-only participant obtains complete uncached bodies from upstream. A participant in both pool and block dissemination forwards the accepted bodies again unless a separately implemented availability/compact-relay protocol reuses them. The table prices one full requesting peer and an alternative six. An archive holding two replicas in other locations transfers 12.69/13.36 Mb/s of pure replica payload in the two inclusion scenarios; a further full live stream and RPC framing take the primary beyond the 16 Mb/s home egress profile. Blocks are modeled at 96 payments, 68 B per entry and 228 B per block. Each wallet pays for its own proving and upload. The relaying peer pays for retransmission; archive operators pay for durable copies, reading and egress. The fixed research fee of 2,112,248 atomic units per WHIR payment has no measured fiat purchasing power or archive reimbursement schedule. The two-phase node passes the mean 16 Mb/s uplink but misses the one-hour drain criterion in both scenarios. Excluded offers still impose upload and validation costs. [Inherited role model and explicit assumptions](../node-validation/roles/README.md)

The three local proving jobs took 27.37–27.71 s and up to 2,339,664 KiB per worker. Counting all offers distributes about 87 core-seconds per second across originating wallets. Their private witnesses never become a builder input. Fresh public-only *per-payment process* checks average 1.267 CPU s for the cryptographic process because each constructs its own public plan. Mean enclosing cold admission wall time is 1.362 s. At 100% those fresh checks require at least 4.02 cores for live traffic alone. A separate verifier process prepared the plan once for three sequentially checked payments in 1.144 CPU s. Their checks cost 85.69, 81.27 and 79.21 ms each after preparation. Ordered ledger work took 48.96 ms CPU and 58.83 ms wall per three payments, including SQLite FULL-sync commits, public receipt checks, spent/nullifier reads, tree/fee updates and full-body retention. The measured three-payment cold group took 1.589 s wall end to end. SQLite used 815,104 B for 789,876 B of bodies plus small-state tables. These sizes do not establish an annual database amplification ratio.

The 98.38 ms value adds the real warm proof checks to the ledger CPU. The ledger's children are measured in 10 ms ticks per group, or 3.33 ms per body of one-tick resolution. The enclosing process, binary startup, installation checks, OS scheduling, pool retries, cold storage stalls and large-state index costs are additional. Reusing a public matrix retains no verdict. The 96-payment setup amortization is calculated, while the observed group had three actual statements. With fresh preparation per individual payment the live demand already exceeds two cores. With the long-lived plan, the corresponding 95%/100% CPU allowances for complete catch-up are 131.32/124.76 ms per included payment. Network and CPU bounds can overlap; disk service, concrete concurrency and growing-state performance still need measurement.

The three dependent payments exercised the adapter's **current-root/count** checks at successive tips. On that literal dependent path a subsequent wallet waits for a changed anchor and constructs another proof; summing mean prove time and cold admission gives about 28.9 seconds per step. A 96-payment framing assumption does not establish support for 96 contemporaneous payments sharing one authorized anchor. Network capacity projections require acceptance of explicitly eligible historical anchors plus current spentness/conflict checks or another tested admission policy permitting concurrent origins. CP03's earlier anchor window is not automatically active in the WHIR adapter. No sustained WAN, adversarial or 100M load was executed here.

The pruned estimates inherit the explicit SQL allowance, 256-block history window, one fork, in-flight staging and no mempool for a block-only node. The observed WHIR SQLite reference retains its tested bodies; rotating a real pruned store and retrieving historical evidence were not part of the three-payment loop. A fully validating wallet must fetch the same complete historical blocks as a validator, then scan for its receipts. A wallet delegating validity to a selected authenticated endpoint can instead download common receipt/witness history. At 100% this takes up to 200M recipient trials per retained key or 6.4B for 32 keys over one year. The link floor omits decryption, catch-up for live receipts, witness reconstruction and endpoint trust. The existing CP03 incremental frames and recovery method provide the exact byte-accounting premise; this milestone tested three local WHIR receipts and respend, without exercising a year or a WHIR-specific remote restore. [Measured and projected wallet path boundaries](../node-validation/roles/README.md)

## Direct default Qnero comparison

The standalone private extrinsic was 154,508 B for one ordinary active payment. Its specialist's independent calculation gives 14.678/15.451 TB of extrinsics for 95M/100M inclusions and 44.035/46.352 TB for three copies. One 5 TB archive covers 124.3/118.1 days of that demanded traffic. The public 120 s target and normal byte allowance imply at most 6.57M such extrinsics per year even without competing normal traffic. The pool and dispatched state still obtain bodies. Its own storage, RPC wire, public spend checks, wallet scan, default occupancy and rejected-call measurements are maintained together. No stock-runtime throughput or batch occupancy is imported into the native pair comparison. [Qnero role model](qnero/ROLES.md)

## Native pair of independent wallet proofs

Two separately running wallets uploaded **147,324 B each**. An isolated builder used both hiding wallet proofs plus their public ciphertexts to produce a **157,220 B** committed pair. The pair held one 150,044 B proof, four 1,792 B ciphertexts and its 8 B header. That saves 137,428 B against retaining both original packets, or 46.64%. The committed per-payment share at demonstrated occupancy two is 78,610 B. Builder intake and user-origin work persist regardless of this saving. In the follow-up spend a singleton again occupied 147,324 B. Wider occupancy and cross-phase cache hits receive no credit. [Native receipt](native/evidence/RESULT.json) · [wire and verifier rules](native/README.md)

| Native role projection from these packets | 95M included | 100M included |
| --- | ---: | ---: |
| Wallet-to-builder payload for 100M offers, TB | 14.732 | 14.732 |
| Committed pairs, millions/year | 47.5 | 50 |
| Pair-only archive, one copy / three copies, TB/year | 7.468 / 22.404 | 7.861 / 23.583 |
| Retention of a 1 / 5 TB archive, days | 48.9 / 244.4 | 46.4 / 232.2 |
| Two replica streams from primary, payload Mb/s | 3.79 | 3.99 |
| Pool / included-pair / both-stage one-peer egress, Mb/s | 3.75 / 1.90 / 5.65 | 3.75 / 2.00 / 5.75 |
| Network-only 10×600 s drain, pair-only / both stages, seconds | 128 / 2,348 | 172 / 2,430 |
| Link-only one-year catch-up while serving live, days | 8.85 | 9.33 |
| Required binary download for 90 days including live pair relay, Mb/s | 9.58 | 10.09 |
| Builder core-seconds/s at the required included rate | 25.33 | 26.66 |
| New current-tip pair required every, seconds | 0.664 | 0.631 |
| Unauthenticated compact receipt-history payload, GB/year | 346.56 | 364.80 |

Actual committed bytes include the native packet's header and all four ciphertexts. If each native transition is enclosed in its own **additional** CP03-style transport header (228 B plus a 68 B entry), 100% demand would need 7.8758 TB/year. If 48 already-computed sequential transitions share one such transport header, it would need 7.8646 TB. Neither transport encoding ran; sharing a transfer frame would not authorize same-anchor execution. The annual wire table above uses one inventory object per native pair, one upstream and one requesting downstream, without either extra CP03 frame. Pair and wallet objects have different bodies; reuse cannot eliminate transmission of the new outer proof. Preserving both source submissions for every included pair as well as its outer packet adds another 13.996/14.732 TB per archive annually. The builder sees which two incoming proofs, public effects and ciphertexts correspond to each outer packet.

The two wallets took 4.52 and 4.81 s to create their proofs. The measured builder performed its two-input proving step in 8.64 s elapsed and 16.82 CPU s, after 6.09 s of setup. The node consumed 10.85 ms CPU to apply the valid pair to the in-memory small state after 6.17 s setup. Its accepted singleton used 24.03 ms CPU. There is no measured durable native database commit. The strict current-tip construction makes every new height depend on the preceding accepted root/parent. Even allowing both wallets to prove concurrently, the measured longest wallet step plus builder and application is 13.46 s per pair before propagation or rejections. A literal, nonspeculative sequence at those timings gives roughly 4.68M payments per year. Its live/burst queue already grows at either demand. The attractive network-only drain and 10.85 ms sample do not demonstrate live capacity. Loosening the anchor rule changes state-consistency, expiry and replay obligations.

There is a second size-dependent constraint on independent replay. The current `header()` recomputes the tree and hashes the entire ordered sequence of commitments before every transition. From four genesis leaves and four additional leaves per pair, the ordered-hash input alone is `64 × P × (P+1)` bytes over P successive pairs. At 95%/100% this is 144.4/160.0 **PB** before tree reconstruction, stored indices or other checks. In a 90-day replay of the 100% historical year that single hash-input stream must process 20.58 GB/s before new live traffic. Therefore the fixed-state proof CPU extrapolation in the JSON is only a component sensitivity. The current state representation also retains two 32-byte nullifiers and two 32-byte commitments per payment, a raw 12.16/12.80 GB one-year identifier floor before indices and persistence. An actual pruned durable node, historical checkpoint protocol and non-rebuilding accumulator remain necessary to price full native state replay. [Native header and ledger](native/native_pair.rs)

Compact post-validation history was 7,296 B per pair (four commitments and four ciphertexts). The wallets found their real receipts, recovered their notes in the live session and the next spend passed. Delivering a year of that unframed history would take at least 9.63/10.13 hours at 80 Mb/s and up to 190M/200M trials per retained key before endpoint authentication, completeness, wallet membership witnesses or processing time. No authenticated remote light-wallet stream, independent backup-only restore or pruned server was run for the native pair. A fully verifying native wallet needs all accepted pair packets and the state work described above. The complete body history, compact recipient view, and wallet-to-builder proof packets have distinct retention policies and payers.

## Recalculate

```sh
python3 -I -B experiments/wallet-created/roles.py | diff -u experiments/wallet-created/ROLES.json -
```

The calculator hashes its source receipts, checks the three wallet proofs against their complete bodies, verifies the three-record durable CPU sum, and checks native two-wallet occupancy and sidecar sizes. The stock metrics refer to the original Qnero role evidence. No annual-scale chain, consensus/DA network, storage market or token price was simulated. [Machine-readable results](ROLES.json)
