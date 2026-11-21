# Use a scheduled compatible verifier upgrade for existing funds

**Adopt the direct-spend upgrade mechanism for the local PoW devnet. Retain FRI-32 as a migration test profile.** A wallet funded under A paid directly under B from its original backup. The chain required no claim transaction, second note, exchange service, balance translation or new genesis. The price of this particular parameter change is roughly twice the wallet proving time and memory. There is no quantified system-wide security improvement to justify deploying it to production. [Protocol and trust boundary](PROTOCOL.md) · [Run the experiment](README.md)

## What happened to the money

Three peer processes started with the A deployment. Two miners earned native subsidies with real PoW and the wallets issued 80 fixed tokens and registered 100 managed tokens. Six A transactions were confirmed by height 12. The peer processes stopped, upgraded and restarted on the same databases, network and genesis. The offline recipient had exported its public address and saved its original 32-byte backup before receiving anything. The recovery destination had no previous state. It scanned 15 blocks through the wallet's validating node and processed 31,079 bytes of public wallet history. Its only positive incoming note held 20 native and 12 managed units.

| Selected block | Authorized action | Result |
|---|---|---|
| 16 | Restored recipient spends its A-funded note under B | Pays 12 native and 8 managed, pays fee 3 and retains 5 native and 4 managed |
| 17 | Second wallet spends that B-created output under B | Pays 5 native and 6 managed, pays fee 3 and retains 4 native and 2 managed |
| 18 | Two independently funded owners jointly sign a B swap | Alice pays 7 fixed for 9 managed and pays the single fee of 3. Alice and Bob each verify their incoming note before authorization. |

The independent holder-side check reopens the offline recipient's original backup with both registered wallet roles. Each derives the same real nullifier for the one positive incoming A note. The check also matches the second wallet's actual B input to the first wallet's B output. The public graph alone establishes valid debits and credits, supplies and fees. The private asset amounts attributed to named participants require the fixture disclosures and owner-side checks. [Public PoW reconstruction](PUBLIC.json) · [Disclosed fork balances and wallet measurements](RUN.json) · [Independent recipient check](review/recovery.py)

At height 13 two different miners included distinct A and B payments consuming the same funded note. Both proofs used an eligible common anchor. Each peer rejected the rival from its mempool and then from the already-spent branch at the next candidate height, while both versions still qualified. The observer first selected the A payment of 8 native to one address and then the heavier B fork paying 9 to a different one. A later reorganization removed both owner debits, the two swap frames, the fees of all three B-only operations and the offline recipient's onward spending. Fees fell from 30 to 21 and the spent set from 22 to 14. Returning to the heavier B history restored the exact original transfers and signatures. The former A and B attempts were publicly linkable through their shared nullifier. The two recipient output commitments themselves did not disclose which opening was consumed.

Two additional controls isolate the activation boundary. A separate funded wallet prepared a B payment at anchor 11. The node rejected it when the next block would be 12. After the original block 12, the identical complete packet entered a mined block at 13 and paid exactly three native units. On a different fork, a genuine A ordinary spend still had an unspent input and eligible anchor at height 15. Released A accepted that mined block; upgraded consensus rejected the same block and refused to trust the legacy database containing it. A genuine issuer-authorized registration from anchor 7 could still be included for the first time at height 15, issuing 100 managed units and paying one fee on its separate branch. [Measured boundary outcomes](BOUNDARY.json) · [Early funding and receipt](EARLY.json)

A new node with an empty database connected to a peer and replayed the selected 20-block history in 7.57 s on the author machine. It agreed on the tip, selected branch data and economics. The author archive includes 27 distinct mined blocks spanning both branches. The independent public reader rechecked 12 funded proofs and three issuer/swap signatures across this graph. On the selected history 2,000 newly mined native units plus 30 recycled fees produced gross miner credits of 2,030. The sum of controlled holdings was 2,000 native, 80 fixed and 100 managed; both registered IDs, the issuer and the amounts outstanding survived the upgrade. One two-leg swap occupied two physical slots and paid exactly one fee. [Verifier and independent accounting](review/public.py) · [Account-level economic reconstruction](review/fixture_amounts.py)

## What changed in the verifier, wallet and network costs

Both registered roles changed from 26 to 32 FRI queries with blinded traces of 4,096 and 8,192 rows respectively. The A and B public statements still have 31 words per transfer or 34 per swap leg. The following totals include the public input vector, all proof data, both original encrypted receipts per leg, the outer framing and both final signatures where applicable. An ordinary transaction or signed leg fits its existing 262,144-byte physical slot.

| Author measurement | A | B |
|---|---:|---:|
| Full ordinary submission | 143,233 B | 182,855 B |
| One signed swap frame | 160,446 B | 200,068 B |
| Complete signed swap submission | 320,905 B | 400,149 B |
| Wallet proving the competing spend of the same funded note, wall / CPU | 5.07 s / 9.83 core-s | 9.82 s / 19.03 core-s |
| Peak RSS of that wallet's native proving process | 451,928 KiB | 886,776 KiB |
| Cold verifier launch through first ordinary acceptance | 1.36 s | 2.76 s |
| Warm ordinary crypto check, median wall / native CPU | 7.14 / 6.97 ms | 8.92 / 8.59 ms |
| Warm complete signed pair crypto check, median wall / native CPU | 24.26 / 23.66 ms | 28.64 / 28.17 ms |
| Native verifier peak RSS, ordinary | 201,100 KiB | 351,284 KiB |

The restored wallet took 10.10 s to prove its A-funded spend under B and the next wallet took 9.91 s to spend onward. B swap wallets each took about 10.1 s to prepare a leg. Negotiation sent 403,280 bytes for one copy of each terms, offer and signature file, with a further 400,149-byte submission. Warm verifier trials verify the complete proof(s), ciphertext binding and swap signatures through the pinned native roles. They exclude PoW, disk commit and relay. A's comparison swap comes from a checksum-pinned historical release; the two ordinary proofs spent the same note in this experiment. The corrected proof-only size excluding the vector length and public words is 139,378 B under A and 179,000 B under B for either relation. [Raw native counters and safeguards](COSTS.json) · [Exact serialization calculation](PROFILE.json)

Direct migration pays a single ordinary fee of 3. The parameter change costs 39,622 extra bytes for each ordinary transfer and 79,244 for each signed pair. At 100M included ordinary transfers that is 3.9622 TB/year of additional first-copy transaction data. Block framing, forks and replication are separate. The test supplies no archive-retention policy or owner traffic cap.

## Assurance and deployment limits

Both eras use the same funded note commitment and spending secret, nullifier derivation, asset identity, receipt keys and backup. N7P2's different funded domains and receiving format would require a separate supply-preserving bridge, which its isolated demonstration does not supply. B still relies on A correctly admitting historical money. A remains prospectively authoritative for genuinely authorized supply changes, including their native funding and change. An old zero-delta transfer cannot claim the supply exception. Any party that still runs A-only software can extend a fork the new software rejects. The activation schedule needs prior operator coordination. [Version rules](upgrade_rules.py) · [Compatibility and privacy review](review/DESIGN.md)

The protocol does not establish that an adversary needs 128 bits of quantum work to spend another holder's note. The prover reveals more query openings, the live membership relation retains its count/depth assumptions, and recorded receipts remain subject to the old receiving-key and joint-privacy assumptions. A different issuer key, new archival model or retroactive repair of unsound A funds requires a separate protocol decision.
