# Funded profile-C partial fills

**Decision.** Use an online maker's durable off-chain order book for partial fills on the local devnet. Each confirmed fill remains one ordinary two-owner atomic swap. Two buyers can trade against one order without sharing keys or registering the order on chain. This gives independent settlement for each buyer at the full cost of one swap per fill.

## Selected-chain outcome

The three validating processes replayed the public funded chain through height 33, issued two fresh assets and funded five independent trading wallets by height 46. Both buyers discovered the same order and each paid 5 B and 3 native units for 50 A. After the first inclusion the seller had 50 A available and 5 B received. After both purchases the seller held 10 B, the two buyers each held 50 A and the order had zero remaining. The comparison wallets traded 100 A for 10 B once with the same price and fee policy. Both sellers started with one 90 A and one 10 A note.

| Observed on the selected chain | Two 50 A purchases | One 100 A purchase |
|---|---:|---:|
| Signed SWB3 packets | 800,330 B | 400,165 B |
| Ordered, length-prefixed block slot vectors, including counts | 800,322 B | 400,161 B |
| Entire mined blocks, one swap per block | 800,764 B | 400,382 B |
| Native fees credited to selected miners | 6 | 3 |
| Successful local submissions, one per swap, including RPC framing | 800,376 B | 400,188 B |

Each packet carries two 182,881 B proof-and-receipt legs, two owner signatures and their binding fields. Its two physical frames are each 200,076 B. The submission row counts one request per included swap; each reply was another 120 B. Duplicate submissions, branch propagation, discovery and private negotiations are separate traffic. These are measured local costs at the demonstrated occupancy. [Run data](evidence.json)

In the operator run, reserving and completing the first fill used three authenticated connections: 275,963 B toward the seller and 290,727 B back. The full-size comparison used 275,964 B and 290,722 B. The second fill used 275,939 B toward the seller. Of the 290,727 B sent back, the fault-injection link withheld 22,968 B of encrypted reply and delivered 267,759 B. Directory discovery and inspection are itemized separately in the run data. TLS totals vary with message encoding. They count application traffic over the links, excluding IP and TCP overhead. The operator deliberately triggered retries and a fork; these are additional costs outside the selected-chain comparison.

## Controls

- With a 90 A reservation outstanding, two buyers requested the last 10 A. Exactly one succeeded. The losing wallet requested it again after the reservation committed and received an explicit capacity refusal. Cancelling both unsigned reservations made all 100 A available.
- Both sides prepared funded legs for an alternate 20 A / 2 B fill. Withdrawing it before signing charged zero fees. A request for 15 A and a changed instruction for 30 A were rejected.
- The second buyer released its authorization. The link forwarded it but withheld the complete final reply. The maker restarted, refused to release the signed capacity on cancellation, closed the offer to new business, and recovered and resubmitted the exact pair. The buyer recovered that same packet from its own node while the maker was offline.
- On the winning branch at height 49 the second fill and its fee had rolled back. The seller showed 50 A confirmed, 50 A still committed by its released signature, and zero available for another buyer. The same signed pair was included at height 50. Resubmitting a confirmed pair left the tip, spent set, fees and empty mempool unchanged. The third swap completed the full-size comparison at height 51.

## Operating boundary

The guarantee depends on one honest maker preserving its local authorization journals. A closed order can still settle an already signed fill, even after a reorg. An abandoned signature can keep liquidity unavailable indefinitely. The wallet seed alone cannot recover off-chain agreements. Settlement inherits profile C's monetary and privacy assumptions. Directory operators can connect to the maker as ordinary clients and inspect its terms and available quantity. Terms are shared with counterparties. The chain exposes the swap format, fee and byte-identical retries. There is no public order identifier. This milestone used scheduled CPU mining and colocated independent processes. Network anonymity and mainnet cryptographic assurance remain open. EAR1 and EC01 stay parked. [Protocol and visibility](PROTOCOL.md) · [CLI and reproduction](README.md)

## Independent reproduction

A non-implementing reviewer repeated the entire CLI scenario from the [public executable revision](https://github.com/jouliene/pq-private-chain/commit/23903f335d9d832c226e36084f81984245da722e), using fresh keys, assets and PoW blocks. All six signed legs matched their funding wallets. The second seller leg spent the first seller leg’s 40 A change plus its original 10 A. Both runs agreed on selected packet and block sizes, fees, the last-lot race outcome and all six compared order snapshots. The independent walkthrough took 419.32 seconds. [Reproduction](review/PUBLIC.md) · [Independent observations](review/observations.json)
