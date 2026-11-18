# Transparent aggregation of wallet-generated CP03 proofs

This fallback would let independently operated wallets prove their ordinary payments once with CP03. They send their complete public CP03 bodies to an intake peer or builder. The builder needs each proof, public statement and ciphertext. It needs no spending key, note opening, wallet backup or private membership path. Peers may relay and precheck those bodies. A block-only validator would receive ordered public payment records and one transparent validity argument. Separating these roles can reduce block traffic and cold validation work. It moves substantial computation to block producers and keeps a distinct pre-inclusion availability obligation.

## What an eligible block receipt must prove

The verifier chooses the historical guest program and profile and compares its journal with the expected chain/genesis, parent block and parent state, branch policy, ordered payment/capsule commitment, count and resulting state. The fixed guest must parse canonical CP03 bodies, compute their exact proof digests and ordered identifiers, authenticate registry/preprocessing and run the full inner verifier against the same public statements. Both slot-specific ciphertexts, chain, fees, root/count eligibility, current nullifiers and source/value/supply state determine admission. Check conflicts within the proposed order as well as against the parent. Validators must also receive the complete ordered public effects and ciphertexts, bind the available data to the same journal, and apply or rollback atomically. Whole-state checks can instead remain in each validator if the specified guest and published capsule leave **every** required input independently available and authenticated. Neither deployment boundary is implemented here.

An independent verifier must enforce the fixed guest image, the successful halt and expected journal, the transparent receipt type, the approved control root and an empty/discharged assumption set. Every accelerated Keccak claim must bind its inputs and outputs to the guest execution via resolved receipts. Public input components include the authenticated opening tree reconstruction, transcript, EF5 arithmetic, byte/frame checks and branch state. A digest of a host verifier's verdict is insufficient. Outer proof knowledge/extractability or a construction-specific composition theorem must link an accepting builder to an acceptable inner payment argument. Both layers' Fiat–Shamir/QROM, hash and adaptive assumptions matter. The outer prover receives only public CP03 material, so a correctly implemented wrapper introduces no wallet witness disclosure through its input. Submission still exposes network metadata to its intake peers.

## Executed discriminator

We pinned RISC Zero v3.0.6 at `1cc70cf05033a79ebc90f07c679cb4bd1cd301b9`. Its transparent Keccak circuit is a real candidate for the expensive SHA3-512 portion of the CP03 verifier. The test extracts an actual 584-field main opening and its salt from the published CP03 payer body. It preserves the leaf domain, little-endian payload length and SHA3-512 padding. A 4,764-byte framed preimage needs 67 Keccak-f[1600] permutations. Independent SHA3-512 checks agree on the final leaf digest. The runner supplies these 67 actual sponge states to the pinned CPU prover and verifies the resulting cryptographic seal in another process. Its public verifier checks the expected input/output transcript digest and the selected power-14 circuit size. A changed public leaf and a corrupted seal both reject; the latter reaches upstream cryptographic verification.

| One real accelerator seal on the i7-8700K, two Rayon workers | Measured result |
|---|---:|
| Seal | 400,392 B |
| Prove | 15.24 s elapsed, 30.54 CPU s, 462,464 KiB peak RSS |
| Fresh verify | 0.02 s elapsed, 0.02 CPU s, 8,192 KiB peak RSS |

The seal proves a batch of permutations. A host in this experiment derives the states, checks the leaf and compares the circuit transcript. The missing full guest would have to constrain this derivation, the whole CP03 verifier and all journal/state bindings. These are neither complete payment nor final block-proof timings or sizes. In particular, the role model's 200,000-byte **hypothetical final aggregate** is a separate sensitivity. [Seal](leaf.seal), [measurements](RESULT.json), [build and source identities](BUILD.json).

On the already-released public trace we parsed 96 distinct, previously validated CP03 payments in history order. They occupy 168,075,264 bytes. Their nonfixed opening-tree reconstruction alone needs at least 3,600,891 permutations, ranging from 36,306 to 38,637 per body. Counts exclude the reusable public fixed tree, transcript, field arithmetic, binding and state work. These are 96 successive historical payments, not a newly admitted 96-payment aggregate. The independent counter parses real salts, frontiers and wire shapes rather than multiplying one sample by 96. A fixed public table could remove repeated verification of the fixed tree, but its own preparation and authentication must still be charged. [Per-body counts](WORK.json) and [independent counter](../review/merkle_work.py).

The pinned circuit schedules at most floor(2^po2/200) permutations per seal; 81 at power 14 and 1,310 at the largest approved power, 18. Even if every batch crosses payment boundaries and fills perfectly, this trace needs at least 44,456 or 2,749 accelerator seals, respectively, before resolving them and proving guest execution. With the observed small geometry alone, 44,456 times the measured 15.24 s is about 7.84 days on that two-worker instance, versus a 30.27 s interval for 96 payments at 100M/year. This last arithmetic illustrates the magnitude of the measured configuration. Higher powers, more hardware, optimized trace layout or different component costs require new measurements. The number of internal subproofs is not the number of proofs a block-only validator downloads. [Upstream accelerator capacities](https://github.com/risc0/risc0/blob/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9/risc0/circuit/keccak/src/lib.rs) and [assumption binding](https://github.com/risc0/risc0/blob/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9/risc0/zkvm/src/host/server/session.rs).

The upstream proof library uses 50 queries and inverse rate four; its optimistic query term alone is 2^−100. The upstream calculator describes 97 conjectured bits for its stated geometry, with lower figures for larger segments. This supplies no non-weakening argument for the study's 128-bit interactive-component screen and no concrete QROM authorization guarantee. An approved stronger profile would need newly derived verifier parameters and revalidated control IDs across guest execution, accelerator, recursion and assumption resolution. CP03 itself has no established whole-protocol quantum security level. [Pinned proof parameters](https://github.com/risc0/risc0/blob/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9/risc0/zkp/src/lib.rs) and [upstream soundness calculator](https://github.com/risc0/risc0/blob/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9/risc0/zkp/src/prove/soundness.rs).

## Reproduce

Use Linux x86-64 and the project's Rust 1.99.1 compiler, GNU time, C/C++ build tools, pkg-config and the locked upstream CPU prover. The build uses Cargo registry dependencies and the upstream checksum-verified recursion artifact. It ran with normal consumer Rust warning behavior; upstream C FFI declarations generated two warnings on this compiler. The source and proof verifier are unmodified. Each new output path is create-only. No remote proving service or wallet is involved. From the project root:

```sh
tmpdir=$(mktemp -d)
git clone --depth 1 --branch v3.0.6 https://github.com/risc0/risc0.git "$tmpdir/risc0"
git -C "$tmpdir/risc0" rev-parse HEAD
python3 -I -B experiments/node-validation/aggregate/run.py "$tmpdir/risc0" "$tmpdir/target" "$tmpdir/run"
"$tmpdir/run/accelerator" verify "$tmpdir/run/public.leaf" "$tmpdir/run/leaf.sha3" experiments/node-validation/aggregate/leaf.seal
```

To independently price all 96 proofs, supply the public tar whose retrieval command and immutable SHA-256 are in [the original public replay instructions](../../network-feasibility/wallet-integration/README.md). This pass reads the published file without extraction or a new proving campaign.

```sh
python3 -I -B experiments/node-validation/aggregate/trace_work.py .work/full01-input/full01-public-closure.tar | diff -u experiments/node-validation/aggregate/WORK.json -
```
