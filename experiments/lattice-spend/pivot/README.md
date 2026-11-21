# Fixed-arity four-child Poseidon2 parent

Replacing the two path gadgets' variable-length parent with a fixed-length parent reduces the first fitting degree-seven signed-leg tree from 2²⁰ TCitH parties to **2¹⁸**. There are still 20 quaternary levels, two input slots, all original money/authorization gates, two receipts and a separate owner signature per leg. The best screened signed frame at that height is **261,068 B**, with **1,076 B** to spare. Its wallet processes 1,117,782,016 field bytes in leaf commitments. This is a component workload, not network traffic or an end-to-end timing. [Priced full relations](PRICE.json) · [Checked public and synthetic cases](CHECKS.json)

## Hash and state rule

The old parent absorbs 16 limbs of sorted child digests, appends a delimiter and pads to three blocks of eight. The candidate starts the same width-12 Goldilocks Poseidon2 permutation from an all-zero state except capacity word 8, set to the little-endian integer represented by the seven ASCII bytes `PQ4N/v1`. It absorbs exactly two successive eight-word blocks into the rate by field addition. Permute after each block, return rate words 0–3, serialize as four canonical u64s. The fixed arity is part of the domain: the function takes only four ordered 32-byte digests. The wallet and node sort each four-child group by its serialized bytes, including zero padding. The circuit, as previously, proves secret insertion at one of four slots along the accepted ordered tree; the branch root authenticates that order. Dynamic active levels support the original capacity 4²⁰=2⁴⁰ without silently shortening a proof.

The old header, old header hash and leaf CM stay intact. The statement appends four public words containing the selected branch's new auxiliary root. The circuit authenticates the legacy header/height to the original anchor, derives the real input's CM as previously and matches its new path root to the appended words. A node must obtain or compare these four words from its own branch replay keyed by that authenticated anchor and height. Otherwise a privately fabricated root could satisfy the arithmetic. A test exercises a different internally valid path against the original branch map and requires rejection. Derived state can be kept in a branch index; a versioned block-header extension carrying the auxiliary root would add 32 B per block, and requires replay verification and distinct block versioning. Two independent signed frames pay 64 B of extra root words in total. The same nullifier derivation and one spent set across versions are required for a migration. No consensus change is activated.

Only the parent changes. The fixed-length initial capacity domain, unchanged 256-bit hash outputs, original note and nullifier sponges, receipt hashes and owner authorization retain separate security obligations. A fresh derivation of collision/second-preimage and multi-domain security for this exact compression, with the intended quantum attacker, is required. A shorter sponge transcript does not supply the missing noninteractive quantum extraction or joint receipt-privacy theorem.

## Recompiled rows, widths and cost

The isolated backend executes the existing funded frontend, selects the new parent only in the path, and redirects the terminal real-input assertion from the legacy root inside the header to the four appended public words. The helper checks that the original source contains exactly one redirectable assertion. Both sparse quadratic and direct seventh-power encodings are emitted from that same builder. The 20 gated levels stay in both inputs even for a dummy. The original shared-depth, direction, dummy flag/ranges, policy/key, receipt digest, branch and monetary checks remain in their respective layers. Exact circuits and public hashes are in the generated census. [Builder](pivot.py) · [Pricing](price.py)

| Profile | Public words | Old → new total permutations | New direct rows | New private columns | Direct packed group lengths |
|---|---:|---:|---:|---:|---|
| MNG1 | 35 | 160 → 120 | 16,093 | 16,082 | 16,082; 3×1,842; 2×14,160 |
| SLG1 | 38 | 164 → 124 | 16,833 | 16,818 | 16,818; 3×2,099; 2×14,632 |

The 40 removed permutations account for 4,720 seventh powers per relation. The public matrix checks all extra zero lanes after each group's independent packing. For pricing, the predecessor's same field, commitment salts, reachable maximal binary frontier, SHA3-512, three transcript commitments, batching, degree masks and separate 256-bit screens are retained. Its actual cost, search and integer certificate functions receive the new emitted matrix census; no proof transcript is simulated to stand in for verification. [Predecessor model](../../packed-tcith/model/README.md)

| TCitH parties | SLG1 direct proof | Signed frame incl. +32 B | MNG1 direct proof at its local best | MSP1 transfer incl. +32 B |
|---:|---:|---:|---:|---:|
| 65,536 | 289,128 | 310,220 | 283,504 | 287,383 |
| 131,072 | 260,440 | 281,532 | 255,112 | 258,991 |
| 262,144 | 239,976 | 261,068 | 234,856 | 238,735 |
| 524,288 | 223,904 | 244,996 | 218,752 | 222,631 |
| 1,048,576 | 210,704 | 231,796 | 206,368 | 210,247 |

The signed allowance becomes 241,052 B of proof bytes, after the 32 extra public bytes. The ordinary totals charge its actual six-byte outer MSP1 envelope on top of the historical 3,841-byte inner wrapper and 32 new bytes. The quadratic alternative at 2¹⁸ still requires **447,152 B** for an SLG1 proof or 468,244 B framed. At this height both direct profiles share s=117, ℓ=32, τ=1, ρ=5, η=33. A simultaneous verifier would check two full SLG1 proofs and two independent signatures on the joint body.

The independent integer lower-bound routine enumerates all widths and opening counts that could attain 241,052 B up through height 17; 43 tuples survived its cheap bound and none qualify. Height 18 is therefore the **first admissible binary party count** for this pricing. Among its screened profiles the 239,976 B example includes 115,200 witness, 12,800 hints, 8,448 mask, 30,888 degree tail, 35,520 nonlinear tail, 9,280 linear tail, 192 Fiat–Shamir, 1,024 salt and 26,624 Merkle siblings. The paper screens are interactive/heuristic parameters; they do not instantiate a QROM extractor. At the first fit, leaf-hash input drops by 82.09% from the predecessor's 6,241,124,352 B. The new signed frame is still 100,622 B larger than a live frame with its 139,386 B proof and 21,060 B of original fixed fields. The lower-work geometry retains the predecessor's open quantum-extraction assumptions. The deployed verifier retains its smaller observed wire size.

## What was exercised

The published fixture contains 12 independently mined positive-reward blocks and 22 funded occurrences. Replay verifies the PoW and ancestry from genesis, original note-root field at every block and all transaction receipt digests encountered. It independently computes the auxiliary roots of the same ordered funded occurrences. For two distinct randomly selected mined rewards, it exercises the legacy compact membership circuit plus both new quadratic/direct circuits, and rejects the previous block's auxiliary root. Output reports aggregate results and public roots only. Historical encrypted outputs do not expose their private spend credentials. This is real funded membership validation and contains no newly signed historical spend.

Separately, the synthetic ordinary fixture has two real inputs; the swap fixture has a real input and a dummy. Both execute all twenty active levels. They independently recompute effects, run the legacy full relation, both new full relations and the packed verifier over their emitted bytes. Tests reject changes to the header, last-level sibling/position, auxiliary root, nullifier, fee, key/supply descriptor, overspending, token quantity and receipt order, plus an unknown branch or different internally valid branch root. These tests evaluate authentic registered arithmetic locally; they do not run a funded end-to-end TCitH noninteractive prover or change block admission. [Controls](check.py)

The final one-seed campaign also ran the complete pivot relation on fresh funded MNG1 transfer and restored-onward assignments and both independent SLG1 leg assignments. Each worker obtained the selected real occurrence from its own opening and reconstructed both full branch paths. Its old public effects, new commitments, nullifiers and receipt words remained byte-identical. The restored role spent the original counterparty output at slot zero. For those very same identities, a local admission-rule test accepted the first registration and atomically refused the second in either order. The actual proof-verification service used the released MNG1/SLG1 registration. The new profile was evaluated as a complete arithmetic circuit. [Four public role verdicts](../funded/ROLES.json) · [Branch and identity checks](funded_check.py)

Run with Python 3, NumPy and SciPy, using the same checksum-verified public Poseidon constants and released `public/` directory as the [previous reproduction](../../packed-tcith/reproduce.sh):

```bash
OPENBLAS_NUM_THREADS=1 python3 -IB experiments/lattice-spend/pivot/price.py "$constants" | cmp - experiments/lattice-spend/pivot/PRICE.json
python3 -IB experiments/lattice-spend/pivot/check.py "$constants" "$events" | cmp - experiments/lattice-spend/pivot/CHECKS.json
```
