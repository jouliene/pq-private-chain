# Independent reproduction of two purchases from one maker

Two buyers each received 50 A from the same off-chain order, paying 5 B and 3 native units apiece. All three validators selected the same final PoW chain. The separate full-size buyer received 100 A for 10 B and paid one fee of 3. The maker's order and wallet balances agreed with the actual signed packets and their selected blocks. [Independent observations](observations.json)

## Source and funding

I cloned the public repository over HTTPS into an empty directory with `--no-local`, an empty environment, system/global Git configuration disabled, no credential helper or prompt, and HTTPS as the only Git transport. The clone had no object alternates. Its remote-tracking main and my detached checkout both identified `23903f335d9d832c226e36084f81984245da722e`, a descendant of `e1dc16d2a617143442c738d10f559d6b49d2e795`. [Tested source](https://github.com/jouliene/pq-private-chain/tree/23903f335d9d832c226e36084f81984245da722e/experiments/partial-fills)

I ran `./pqd market --home NEW_DIRECTORY partial-walkthrough` using the default three public downloads. All passed their pinned SHA-256 checks. The nodes replayed the common H33 branch, then funded five fresh wallets by H46. Both freshly issued asset IDs, all three settled bundle hashes, the H46 funding tip and the final H51 tip differed from the author's run. The complete walkthrough took 419.32 seconds. The checkout remained clean. [Public input digests and fresh tips](observations.json)

## What settled

The read-only checker decoded the selected and detached blocks, PoW IDs, fee deltas, rewards, SWF3 frame lengths, reciprocal SLG3 leg hashes and SWB3 envelopes. On each selected pair it matched both physical legs and signatures to the respective wallets' native signing journals and checked which private funding records those exact frames spent. The three nodes independently verified the registered C proofs and signatures during admission. [Standalone checker](verify.py)

| Selected purchase | Seller inputs | Buyer input | SWB3 bytes | Native fee |
|---|---|---|---:|---:|
| First 50 A at H47 | 90 A | 5 B and 3 native | 400,165 | 3 |
| Second 50 A at H50 | 40 A change created by the exact H47 seller frame, plus the original 10 A | 5 B and 3 native | 400,165 | 3 |
| Full 100 A at H51 | Original 90 A and 10 A | 10 B and 3 native | 400,165 | 3 |

The two partial purchases therefore used 800,330 envelope bytes and 6 native units in fees. The complete block vectors occupied 800,322 bytes across two blocks, against 400,161 in the full comparator's block. Each of the three selected swap blocks credited the miner 103 units. The two sellers started with the same note denominations. The first seller retained 50 A after H47 and zero after the second selected fill. [Block, fee and funding readback](observations.json)

## Reservation, recovery and visibility

- Two buyers raced for the remaining 10 A lot while 90 A was reserved. Exactly one got a funded reservation. Cancelling both unsigned reservations restored 100 A. Both sides prepared a 20 A for 2 B fill and cancelled it before signing with zero fees. The wallets rejected a 15 A instruction and a change from 20 A to 30 A.
- The link withheld 22,968 bytes from the second buyer's final reply. The seller restarted, retained 50 A of signed exposure, closed the offer, and recovered the original signed packet. The buyer recovered its countersignature from its own validating node while the maker was offline.
- A heavier branch detached the H48 second fill and reversed its fee. At H49 the order showed 50 A confirmed, 50 A exposed and zero available. The very same packet was re-included at H50. A repeated submission after confirmation left the tip, cumulative fees, spent-set digest and empty mempool unchanged. [Fresh branch and fault observations](observations.json)

As a narrow encoding check I searched for both test order handles and the five complete receiving descriptors, in binary and hexadecimal form, in the six post-funding block bodies retained by the mining node, including the detached block, and in the observed broad directory adverts. There were zero literal matches. Any client that connects to the online maker can inspect its price and available quantity. The public can link the two frames of each swap, observe its fee and recognize an identical retry. Counterparties and network operators also have timing and endpoint information. Joint privacy and resistance to traffic analysis remain open. [Protocol and observer model](../PROTOCOL.md)

This run exercised independent processes and newly funded owners on one host with scheduled mining. Production capacity remains unmeasured. Recovery of an outstanding off-chain authorization depends on retaining the corresponding private journals. A disconnected peer or an uncertain authorization can keep capacity encumbered. [Operator instructions](../README.md)
