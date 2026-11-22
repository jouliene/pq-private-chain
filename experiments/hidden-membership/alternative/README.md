# Private lookup in a verifier-owned funded table

**Hold the split-ANF compiler before payment integration.** One fresh authorization component proved knowledge of a funded opening and its nullifier against 53 eligible rows. At 220 million occupied rows the complete, two-input EM-256s byte schedule already calls for 6,403,188 bytes per ordinary payment. The compiler also emits an expected 68.72 billion coefficient XORs **per private input** at that occupancy under the ideal-digest model. The pinned library addresses wires with a 32-bit ID. A wider wire ID alone leaves the evaluation and bandwidth costs.

## Funded data and private selection

A node replays the selected branch to derive its ordered table of 64-byte FS01 funded leaf hashes, each SHAKE256 commitment to a distinct funding occurrence O and note commitment CM. The anchor names the eligible branch state. Spent rows remain in the anonymity set. Admission must consult current nullifiers separately. A registered deterministic compiler takes the authenticated public table, tags, chain, anchor and count. A transaction carries the public nullifier and proof. The prover never supplies the verifier with a replacement circuit, table, index or coefficient digest. All funded positions at that ancestor are possible, subject to the remaining transaction information.

For an occupied count n, pad to the next power of two with zero leaves and constrain the private index below n. Write its low and high bits as x and y. Taking the binary Möbius transform of all public rows produces the 512-bit algebraic normal form (ANF) coefficients c[l,h]. For each output bit the circuit computes

```
selected[b] = XOR_h y^h * (XOR_l c[l,h,b] * x^l).
```

Here x^l is the AND of the input bits selected by mask l. The empty product is one. Share each monomial across all output bits. The split avoids an AND for every bit of every row. Public coefficients decide where XOR gates occur. For L low bits and H high bits, one lookup costs exactly (2^L−1−L) + (2^H−1−H) + 512(2^H−1) ANDs in this compiler, before the range check. Pricing chooses the integer split with the fewest ANDs, retaining at least two bits in each group for d ≥ 4. A direct circuit can also share linear combinations, and proof protocols with preprocessing can use a different lookup argument. These measurements apply to the stated compiler. For the general split-variable upper bound see Boyar and Find, theorem 7. [Primary paper](https://arxiv.org/pdf/1407.6169)

The 6-bit executable uses a 4+2 split. Private data are ASK64, native:u64, asset64, qty:u64, salt64, O64 and index:u6. The circuit computes the FS01 owner from ASK, the 208-byte note commitment under the validator's chain, H(leaf,O,CM) compared with the selected public row, and H(nf,ASK,O) compared with the public NF. These four SHAKE256 outputs take six Keccak-f permutations in total. Identical CM paid twice at different occurrences uses different O and hence different NF under the assumed hash binding. Relocating the same O to another position retains its NF. The component covers one active input opening. The complete price preserves both active/dummy slots and all the FS01 monetary gates. Payment-level typed positive amounts, range and balance, intent/receipts, transaction replay and atomic spentness are outside this executable. [Underlying monetary semantics](../../fresh-spend/binding/RELATION.md)

## Executed checks

The fixture independently derives fresh ASK, salt, O, CM, leaf and NF using Python's SHAKE256 and writes the public table before invoking the prover. Private fields travel over a pipe. A separate verifier process receives the node's table file and NF64 || public proof. Its transcript context hashes a fixed compiler/profile version, chain, anchor, count and all occupied leaves. A production validator would derive these rows from independent consensus replay. This experiment starts at that boundary with a synthetic funded table. Its small table format is HLT1 || chain64 || anchor64 || count:u8 || ordered leaves.

| EM-256f, one active input | Measured |
|---|---:|
| Occupied rows / capacity / public table bytes | 53 / 64 / 3,525 |
| AND gates / private bits | 231,954 / 2,182 |
| Proof / public NF plus proof | 949,316 / 949,380 B |
| Prove wall / peak RSS | 0.52 s / 94,132 KiB |
| Fresh public verify wall / peak RSS | 0.47 s / 76,624 KiB |

This trial used Linux x86-64, an i7-8700K, GCC 13.3.0 and OpenSSL 3.0.13. Its public table induced 1,182,861 total circuit wires. The count varies with the table's public coefficients. The process times include construction of the circuit. Non-author review can run the same script with fresh private randomness. [Recorded trial](COMPONENT.json)

Six public checks rejected a changed table order, an unrelated changed row, a changed anchor, a changed NF, a changed proof and a truncated packet. Separate prover-side checks detected a wrong ASK, native amount, asset, quantity, salt, O, occupied index, padded index and expected NF. A clear evaluator independently checked every index and a one-bit wrong digest at each index for counts 1, 53 and 64. Incremental coefficient tests checked 130 appends, 100 removals and a new 100-row fork against full recomputation after each operation. [Public proof fixture](exercise.py) · [Branch update test](updates.py)

## Complete path pricing

The comparison retains the 40-bit index record, 41-bit count checks, inactive-slot equality, distinct real indices, both nullifiers, four note commitments, receipt and intent binding, integer balances, swap extension and both independent signatures. Known-zero high index bits at smaller occupancies can be enforced by direct equality. Relative to the previous Boolean schedule the two lookups replace 80 parent permutations, their 40,960 mux gates and 40,960 sibling witness bits. The other 742,032 ANDs and 8,273 private bits remain. Prices agree with the pinned proof-size API. These are analytical whole-payment projections using the FS01 framing widths. A real deployment needs its own registered suite and independently reconstructed context binding the full statement and ancestor. [Exact calculator, both 256s and 256f](PRICES.json)

| Occupied leaves | Split L+H | Lookup AND/input | EM-256s ordinary | Signed leg | Two-owner swap |
|---:|---:|---:|---:|---:|---:|
| 53 | 4+2 | 1,548 | 2,086,502 B | 2,116,430 B | 4,232,880 B |
| 220 million | 19+9 | 786,402 | 6,403,188 B | 6,433,116 B | 12,866,252 B |
| 2.2 billion | 21+11 | 3,147,230 | 19,387,742 B | 19,417,670 B | 38,835,360 B |
| 2^40 | 25+15 | 50,363,862 | 279,079,218 B | 279,109,146 B | 558,218,312 B |

Each input has its own private index. Public coefficients may be shared between slots and payers at a common anchor. Proving two private selections still requires both index-dependent computations. A lone sender can act without peers, a pooled witness or trusted setup, provided it possesses the authenticated table. Two swap owners use their own backups, private openings and proof randomness, each producing a self-contained leg for the same terms. Transaction-wide admission checks current nullifiers and both signatures before one atomic debit/credit. Those payment/settlement roles are carried over in the design and sizes. At the 2^40 geometry, a sender uploading one ordinary transaction over an analyst-selected 20 Mbps uplink needs at least 111.63 s. Uploading a complete pair takes 223.29 s. Wallet proving, inclusion and retransmission add delay. A branch actually filled to 2^40 cannot append another output.

Each coefficient symbol includes row 0, hence its bits are marginally unbiased if the occupied digests are ideal independent uniform values. The expected emitted coefficient XORs per input are 256 × 2^d, plus 512 × 2^H group-combining XORs. At d=40 the coefficient term is 281,474,976,710,656 XORs per input. XORs are relatively cheap in proof bytes but require wire storage and evaluation here. Linear-circuit optimizations could lower that cost. The codec counts at large occupancies are counterfactual byte geometry; real large executions, wall times and RSS have not been measured. [C compiler](lookup.c) · [Price calculation](price.py)

## Wallet, archive and node service

Every independently proving wallet needs all occupied 64-byte leaves or the equivalent coefficient data for its anchor. Download the same authenticated public range as another wallet at the same cursor. Targeted queries for the selected row or a high-index group would expose its owner’s interests. Public append/reorg deltas permit reusing the table. Updating row j XORs its delta into coefficients whose masks contain j. When the table doubles, copy the old coefficient block into its new high half before inserting the next row. Validators can cache branch-derived coefficients keyed to a verified state. Caching saves preprocessing across proofs at a common state, while each private input still needs proof verification against that state. The capped executable rebuilds the circuit on each command.

At 100M included operations/year with an analyst-selected 90% ordinary/10% pair mix, 220M new occurrences add 14.08 GB/year of raw digest storage. A node can derive these digests from existing body history. The indexed padded coefficient array at the end of year one consumes 17.18 GB; at capacity it consumes 70.37 TB. A wallet restoring from a backup needs authenticated creation data, complete receipt history for each retained key and the public branch projection before spending. Receipt ciphertexts alone add 394.24 GB/year at this mix, plus other fields, anchors and fork/availability overhead. A compact projection must authenticate both order and completeness; a node serving one table without a validated chain does not confer either. The ciphertext and digest costs are different layers and a wallet deriving one from full validated history can avoid retransmitting it as a separate stream. Pruning, service interruption or total archive loss still affects recovery. IP/timing linkage and observations of the original payer are outside this lookup's protection.

Using the end-of-first-year geometry for an entire subsequent year of unchanged sizes gives 704.95 TB of bodies at 100% inclusion, or 178.71 Mbps for one copy. Ten times that offered rate over a short burst needs around 1.79 Gbps of body intake at those sizes. For a growing *first* year starting with two rows and repeating nine ordinary payments then one swap with an immediately prior anchor, the projection is 566.67 TB. The respective 95%-inclusion figures are 669.70 TB (steady snapshot) and 531.42 TB (growing). Full-node upload, housing multiple copies, transport, forks and incomplete submissions add traffic. No annual traffic cap or prescribed role bandwidth follows from the owner's offered count. [Occupancy and traffic scenarios](PRICES.json)

## Assurance and next test

The table circuit deterministically looks up the leaf bound to the same secret that derives the NF. Hiding of the index and of related transactions still rests on this exact proof and its composition with receipts, retries and wallet access. An isolated verifier and fresh private coins demonstrate data separation. The FAEST signature QROM results do not grant this adaptive, same-witness monetary relation an extractor or a concrete multi-user error bound. The 512-bit funded digest needs binding in the relevant chosen-opening and fixed-target games. Adversarial funding can also reduce the effective anonymity set. Changing the funded commitment, public projection or proof requires a new registered monetary suite and coordinated spending/recovery rules. [Existing source-to-theorem analysis](../../fresh-spend/proof/README.md)

To reopen this global lookup, demonstrate a hiding, quantum-plausible preprocessed lookup against an authenticated, incrementally updatable ledger table. Measure its lookup proof and link to this same owner/occurrence/NF assignment from independent wallet and node states, with preprocessing/update/recovery costs included.

## Reproduce

Use the common runner's pinned VOLE source/build directory, including its size API binary. To build that dependency standalone from the repository root, run the first command in a new scratch location. The second command creates a fresh capped proof and reruns the pricing and branch checks. Only public files are written.

```sh
bash experiments/fresh-spend/proof/reproduce.sh /tmp/new-vole-build
bash experiments/hidden-membership/alternative/reproduce.sh /tmp/new-lookup-run /tmp/new-vole-build
```

The source pins are libtalos_voleith 255f1a995b8542de453efef57db7aa47a09f3a03 and libtalos_ichor 1e49bd0e6395523b3499d2deedae3f957e41d5c1. The runner links their pinned source builds under the upstream licenses and reuses the project's Keccak circuit. [Upstream archive checksums](../../fresh-spend/proof/SOURCES.sha256)
