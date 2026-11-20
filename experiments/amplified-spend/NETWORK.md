# Wire, archive and home-node costs

Use one included transfer or one complete two-wallet swap as one operation. A transfer occupies one of four block slots, a swap occupies two adjacent slots. The measured released swap body contains two 160,446-byte frames and a 13-byte submission envelope. The actual mined swap-only block occupies 321,122 bytes. Each block contributes 222 fixed bytes plus four length bytes per occupied slot. A 143,233-byte ordinary transfer gives a 143,459-byte block when mined alone. The calculator reads the independent public capture, validates its checksum and compares the mined block's exact slot bytes to the submitted frames. [Byte inputs and calculation](traffic.py) · [Published funded capture](https://github.com/jouliene/pq-private-chain/releases/tag/funded-whir-2026-11-20)

The comparison uses decimal TB, 365-day years and 90% ordinary transfers / 10% swaps. Packed years fill all four slots, with no forks, orphan traffic, rejection, retry, compression or empty blocks. Each hypothetical profile uses the same non-proof framing as funded WHIR. Its unregistered blocks cannot enter the current network. Only the two reference encodings have measured packets. The amplified mean comes from expected counts of distinct leaves and siblings at each level for independent uniform queries, rounded down by less than one byte per proof. The KKW floor counts mandatory bits for two explicit nonsquare products per seventh power. Additional KKW witness and proof data would increase the totals. [Exact byte counts for all scenarios](TRAFFIC.json)

| Profile and evidence | Final transfer / signed swap submission B | Archive at 10M, TB | 30M, TB | 100M, TB |
|---|---:|---:|---:|---:|
| Live MNG1/SLG1, captured | 143,233 / 320,905 | 1.611 | 4.832 | 16.106 |
| Prior funded WHIR, captured packets | 239,233 / 514,005 | 2.668 | 8.003 | 26.677 |
| Amplified CFW, modeled mean | 1,129,218 / 2,292,887 | 12.456 | 37.369 | 124.565 |
| Amplified CFW, full geometric maximum | 1,175,929 / 2,386,309 | 12.970 | 38.911 | 129.703 |
| KKW, compiler-specific lower bound | ≥1,314,656,001 / ≥2,695,079,061 | ≥14,526.98 | ≥43,580.95 | ≥145,269.83 |

For 100M solely ordinary transfers the live projected archive is **14.329 TB**. For 100M solely swaps it is **32.101 TB**. In the mixed case, including one operation per block raises 16.106 to **16.123 TB**. Any additional empty block adds 222 B. The 1 and 5 TB comparison scenarios would allow 10,000 and 50,000 B per included operation at 100M/year. The owner has set no annual traffic ceiling.

## What a participant must move or retain

| Live 90/10 mix, decimal TB | 10M | 30M | 100M |
|---|---:|---:|---:|
| One final submission per operation, including submit RPC framing | 1.610 | 4.831 | 16.102 |
| One copy of pending bodies and one of the packed chain, inbound | 3.221 | 9.662 | 32.206 |
| Both of those bodies to each of two downstream peers, outbound | 6.441 | 19.324 | 64.413 |
| One uncompressed canonical archive copy | 1.611 | 4.832 | 16.106 |

Relay columns specify copies and directions. Submission counts cover the final sender-to-node request. Negotiating wallets additionally exchange offers, signatures, addresses and terms. A previous native-for-token walkthrough measured 324,039 bytes for one copy of the private agreement, two offers and two signatures before final submission. Relay projections omit RPC/TCP/TLS overhead on peer links, inventory, duplicates, quotes and rejected branches. An initial node downloading the canonical validation history pays for at least one complete chain copy in this full-body model. Additional indexed state, retained forks and backups occupy more space. [Measured swap negotiation and block](../atomic-swap/NATIVE_CURRENCY.md)

As a researcher-selected home-node example, consider four available CPU cores, 16 GiB RAM, a 2 TB data disk, 100 Mbit/s downstream and 20 Mbit/s upstream. At 100M mixed operations, the two-peer outgoing example averages **16.34 Mbit/s** before bursts and protocol overhead. The first-copy archive exceeds the sample disk in about 45 days. The four-slot block limit would require at least 27.5M blocks per year, an average interval of **1.147 s or less** at full occupancy. At 10M and 30M the corresponding largest intervals are 11.468 and 3.823 s. This calculation makes no assumption that PoW propagation or miners can sustain these intervals. Prior spending measurements and fresh proof-verifier checks establish neither sustained multi-peer capacity nor an economical archival service.

On the host used for the replay (Intel i7-8700K, Linux x86-64), warm CPU medians were 0.00628 s per transfer and 0.02419 s per signed pair. Under the same 90/10 workload that projects to approximately 0.026 CPU cores on average at 100M/year for one public proof/authorization pass per included operation. A node may verify again at block admission and needs additional CPU for state, PoW, gossip and bursts. Wallet proving in the earlier funded run took about 4.7–4.8 s elapsed per released proof. No prover resource figure was measured for either excluded design. Materializing all of the CFW codeword payloads would represent 1,814,036,480 bytes before salts, paths and scratch buffers; actual peak memory depends on scheduling and streaming. [Current public verifier samples](LIVE_VERIFY.json) · [Earlier wallet measurements](../funded-whir/review/REVIEW.md) · [Committed-oracle counts](primary/MODEL.json)

A pruned node would still need branch-validating state, the spent set, tree frontier and retained history. Its disk use and archival data availability have no new measurements here. Cold wallet recovery still requires the public history service to supply the common recovery data used to locate and decrypt receipts and reconstruct branch witnesses. An owner who has already synced can use retained joint checkpoints where compatible. This milestone changes neither what the chain commits nor what the node or wallet can safely discard. [Wallet history contract](../../devnet/WALLET_PROTOCOL.md) · [Funded recovery procedure](../funded-whir/wallet/README.md)
