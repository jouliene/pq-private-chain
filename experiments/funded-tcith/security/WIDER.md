# A wider auxiliary tree for retained note commitments

Use a separate registered auxiliary tree with the same 20 quaternary levels and original 32-byte funded note commitments. The tested arithmetic changes only branch membership and authenticates the actual active depth. For a comparison, this proposal spends seven Goldilocks capacity words on the parent instead of four. In the ideal-permutation model the previous generic intermediate-capacity matching calculation now has a quantum exponent near (7 log₂ p)/3 = **149.33**. Seven output words give the same generic quantum collision exponent. Those are resources of generic methods, not a lower bound for this concrete Poseidon2 variant, the full ledger, or the inherited note relations.

## Rules priced in the prototype

* A bottom parent consumes four ordered four-word legacy commitments. All higher parents consume four ordered seven-word digests. Missing siblings at each layer are all-zero values of the appropriate width. The node groups the same original occurrence sequence and sorts each four-child group by its canonical concatenated u64LE bytes at that layer.
* For level j from 1 to 20 use the existing width-12 Goldilocks permutation. Initialize a zero state with capacity word 5 set to the u64LE integer of `PQ4N/v2` and word 6 set to j. Absorb the exact fixed-size input at rate five by field addition, zero-filling the last partial block. No other arity or length is valid in that level domain. After the last absorption permutation take five rate words, permute once more without absorption, then take two more rate words. Keep all seven as the ordered digest, totaling 56 bytes. The first level needs four absorption permutations and one squeeze. Each of the other 19 needs six absorption permutations and one squeeze. The two complete paths use 276 permutations across all active-level gates.
* Append seven root words and one depth word to the original public statement, producing 39 ordinary or 42 signed-leg words. The node recomputes that versioned root and depth from its own selected branch, with depth the count of nonempty grouping levels (at least one for a spendable root). The circuit constrains the number of active prefix bits to this public depth and validates each real input's terminal seven limbs. The circuit consumes four-word bottom siblings; it never treats an old leaf as an already-seven-word internal opening. The level field also distinguishes traversal length. Dummy, money, key, output commitments, receipts, fees and nullifiers retain their original constraints. Keep a single branch-local spent set across live and prospective proof types. Reorganization must restore the root/depth mapping and spent set together. Seed-only recovery still needs scanning the same receipts plus computing the wider paths; per active level after the first, three 56-byte siblings replace three 32-byte siblings. A full private path therefore grows by **1,368 bytes** (19 × 3 × 24).
* Root/depth can be derived using replay and a local index. The per-proof price pays 64 extra public bytes relative to the live registration, compared with 32 for the previous auxiliary tree. If a new block version also carries this root and depth, budget another 64 bytes per block. This price table assumes the index-only branch rule and counts complete payment packet bytes.

[Recompilation, fixed-arity rules and exact pricing](wider.py) · [Pinned Poseidon2 constants](https://docs.rs/qp-poseidon-core/3.1.0/src/qp_poseidon_core/poseidon2.rs.html)

## Complete projections

| Signed-leg geometry (N,s,ℓ) | Ordinary packet | Signed leg | Two-leg submission | Leaf field bytes per signed leg |
|---|---:|---:|---:|---:|
| 2^18, 117, 32 | 395,439 | 417,772 | 835,557 | 2,401,239,040 |
| 2^18, 172, 34 | 372,311 | 393,060 | 786,133 | 1,711,276,032 |
| 2^20, 139, 26 | 328,031 | 348,780 | 697,573 | 8,279,556,096 |
| 2^28, 107, 14 | 241,567 | 261,468 | 522,949 | 2,695,091,978,240 |

The old geometry yields 396,648 proof bytes plus 21,124 signed overhead bytes. Ordinary and signed frames include all public fields, both receipts and the applicable original wrappers and signature. At the first fitting grid point the signed packet has 676 bytes of headroom but its wallet would hash approximately 2.695 TB of field shares, before salts and all other work. That is about 2,411 times the field payload for the original 2¹⁸ candidate. No time or RAM figure can be inferred directly. The proposed SHA3-512 proof transcript still has the original multi-round quantum-extraction gap.

The search reused the packed TCitH estimator at T=256 and scanned heights 6–63, s=1…260, ℓ=1…80 for SLG1, repricing the best eight estimates per height with integers. It selected the first fitting **screened** height; this is not an all-geometries exclusion. The comparison uses the same geometry for MNG1 and separately prices its actual private packed width. Both proofs retain the same six separately rounded groups, batch masks, salts, worst-case frontier, canonical fields and three digests. [Exact widths, full statement counts and price components](WIDER.json)

The local driver compiled the original monetary constraints for both suites with the new path. A depth-20 artificial ordinary assignment with two real inputs and signed-leg assignment with one real input and one dummy passed the emitted matrices. Both rejected a changed root and a changed depth with the same private assignment. SLG1 has 40,544 rows, 40,522 private wires and 37,760 seventh-power constraints. MNG1 has 39,804 rows, 39,786 private wires and 37,288 seventh-power constraints. Numeric and emitted checks share the registered permutation coefficients. The fixture is a synthetic arithmetic test with opaque legacy header fields. It does not exercise branch replay, fresh funded receipt/recovery, a wider proof or independent cryptanalysis. No node accepts this registration. The old note, ownership and nullifier digests remain four words. A new spending front end cannot improve the security of an independently accepted old spending path. The extra capacity rules out the *old parameter count* for the matching method. Adopting this particular expensive lowering would need a wider proof review, a cheaper lowering and a separate coexistence/migration policy.

Reproduce using the exact checksum-pinned `qp-poseidon-core-3.1.0/src/poseidon2.rs` located by the lattice experiment:

```sh
OPENBLAS_NUM_THREADS=1 python3 -IB experiments/funded-tcith/security/wider.py "$constants" | cmp - experiments/funded-tcith/security/WIDER.json
```
