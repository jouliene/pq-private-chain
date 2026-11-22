# Complete FS01 monetary wiring

The compiled ordinary payment has 99 Keccak permutations, 80 private sibling selections and one packed proof. At three committed round groups per permutation, the exact proof extent is **175,442 bytes** with the 4,096-leaf ring suite. The original FS01 codecs then give 179,432 ordinary bytes, 209,360 bytes for a signed leg and 418,740 bytes for a complete two-leg bundle. The pricing test calls the actual encoders with an opaque proof-sized marker and signature-sized buffers. It measures frame geometry. Genuine proofs, receipt sealing, signature verification and any state transition require their separate role measurements. [Compiler](monetary.py) · [Inventory and clear checks](inventory.json) · [Original FS01 packet format](../../fresh-spend/binding/RELATION.md)

## Compiled equations

The verifier constructs the circuit from a canonical 526-byte statement and flattening choice. The private codec accepts exactly the original 6,155-byte witness. Constants zero and one are pinned. All private wires inhabit the one ring commitment, including the active bit, the shape-independent Keccak boundaries, the arithmetic intermediates and the little-endian amount bits.

- The owner, both input note commitments, both occurrence leaves and both nullifiers use the same field IDs as their consumers. At all 80 levels the index bit selects child ordering, the level fixes the parent prefix, and each result feeds the next parent. Both final digests are pinned to the trusted public root. Both indices must be below count. Both records must contain a positive native amount or quantity.
- The index XOR is nonzero exactly when the second slot is active. The inactive bit times every discrepancy in the two 277-byte scalar records must be zero. Both paths remain checked. Slot zero uses tag 8. Bit zero of the second slot's hash tag is the inactive bit and the remaining tag bits encode 8. This computes tag 8 or 9 without changing proof shape. Both nullifier digests must equal the public values, and the public parser rejects equal nullifiers.
- Each of four independently computed quantity indicators gates every bit of the common asset ID. The resulting vector must equal that note's asset. The common ID is nonzero exactly when at least one quantity is nonzero.
- Both forms of value satisfy independent 66-bit conservation equations. The inactive slot contributes zero to each sum. The native output sum additionally includes all 64 public fee bits. A ripple-carry computes every intermediate over 66 positions with an explicit terminal no-overflow constraint. Two u64 inputs and three u64 terms on the right fit this width.
- Both output note preimages produce the public output commitments. The same first slot ASK and the public intent produce the pinned authorization. Deriving that intent from the actual core, receipt tails, role and eligible branch is the caller's job. The circuit directly consumes every bit of the resulting intent.

Input count, fee, expected output digests and intent are public parameters. The compiler builds the same geometry for active and inactive payments at any fixed count and flattening. It also accepts a one-entry anchor for a true inactive duplicate. The role-specific enclosing registry supplies the complete statement to the compiler and binds its encoding in its registered transcript domain. No source in this directory changes the live consensus registry.

## Counts and comparison

At count 2 and flattening 3, there are 625,404 committed binary wires, 758 K trace elements, 6,065 scalar product rows and 61,937 linear rows. The selector uses its separate packed selection argument. The ring opens 569 rows. The core packet price adds the 758 × 32-byte earlier trace messages to all ring and LCS messages.

| Committed round groups per permutation | 1 | 2 | 3 | 4 | 6 | 8 | 12 | 24 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Proof bytes at count 2 | 215,618 | 178,946 | 175,442 | 179,234 | 196,850 | 218,090 | 265,922 | 417,722 |

For non-full anchors the index comparator runs 40 stages per slot with one extra bit wire for each set bit of the public count. Its maximum is count 2^40−1. At count 2^40 it can skip the comparator; the committed index already has exactly 40 binary coordinates. The recorded full-count and maximum-comparator shapes bound all valid counts. The row rounding gives the same 175,442-byte K=3 packet across this interval. The counts price the current construction and provide no lower bound on other proof systems.

The clear tests generate fresh secrets in memory, derive their roots, commitments and headers via Python hashlib, parse both codecs, execute the compiled Boolean/Keccak assignment, and check every affine, scalar-product and selector row. The independent clear monetary evaluator must return the same accept/reject value. Three valid cases include the inactive one-entry anchor and true sums above 2^64. Twelve invalid cases include direct monetary and authorization failures and both 2^64 wrap cases. They do not run the noninteractive proof engine. The public JSON contains aggregate geometry and dispositions only.

From the worktree root, in the mixed backend's Python/NumPy/CLMUL environment:

```bash
run_dir=$(mktemp -d)
experiments/hidden-membership/smallwood/build-wide.sh "$run_dir/native"
PYTHONPATH="$run_dir/native" python3 experiments/structured-keccak/payment/check.py > "$run_dir/inventory.json"
cmp experiments/structured-keccak/payment/inventory.json "$run_dir/inventory.json"
```
