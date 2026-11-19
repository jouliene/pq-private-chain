# TKQ1 direct-proof comparison

**A genuine two-input, two-output TKQ1 payment verified and both wallets recovered their expected holdings.** TKQ1 moves the argument’s Merkle commitments and Fiat–Shamir challenge generation from original Poseidon to full-output Keccak-256 and increases the FRI query count from 26 to 64. TKN1's note-opening and monetary constraints, 26 public fields, and two encrypted receipts remain the same. The measured packet grows from 143,187 to 383,033 bytes. It exceeds this devnet’s 262,144-byte packet bound by 120,889 bytes. The result supports further comparison of argument hashes and improved FRI parameters outside the live protocol. [Preregistration](REGISTER.md) · [Exact configuration](config.rs) · [Native measurements](evidence/PROBE01.json)

| Single complete direct payment | TKN1 | TKQ1 |
|---|---:|---:|
| Gates before blinding / padded rows | 468 / 4,096 | 468 / 16,384 |
| Enlarged domain / query draws | 131,072 / 26 | 524,288 / 64 |
| Reductions by four / final coefficients | 5 / 4 | 6 / 4 |
| Full proof / encrypted receipts / frame, bytes | 139,594 / 3,584 / 9 | 379,440 / 3,584 / 9 |
| Per-packet archive at 100M inclusions, decimal TB | 14.319 | 38.303 |
| Prove CPU / wall, seconds | 7.478 / 3.825 | 8.495 / 4.501 |
| Wallet setup CPU / wall, seconds | 2.680 / 1.444 | 3.255 / 2.019 |
| Peak wallet RSS, KiB | 452,044 | 1,765,260 |
| Fresh verifier setup CPU / wall, seconds | 2.373 / 1.279 | 3.461 / 2.196 |
| In-process whole-packet verification, ms CPU | 6.300 | 5.824 |
| Peak verifier RSS, KiB | 201,212 | 668,440 |

Proving baseline values are means over the previous four TKN1 positives. The independently launched public TKN1 verifier here checked one archived genuine TKN1 packet; the TKQ1 public verifier checked one new TKQ1 packet. Setup includes deriving fixed keys from source and matching serialized bytes. The isolated wallet roles used two Rayon worker threads. One sample cannot establish a sustained service rate. Only proofs, receipts and framing are in the archive comparison; offered upload, rebroadcasts, spent state, ordinary block/core overhead, bootstrap and replicas add costs. The new wallet’s first proof call including setup took 6.520 seconds. The larger query budget also increased blinding allocations and crossed two power-of-two trace boundaries. [TKN1 reference](../../token-profile/RESOURCES.json) · [Actual registered TKQ1 geometry](evidence/REGISTER.json) · [Raw process meters](evidence/PROBE01.json)

The released 1,489-byte TKQ1 verifier has SHA-256 `74fa3fb56350de946797b7b68e925ae2193efe6b0257ad62e474225d650cd68c` and was registered before generating the specimen. The independent receiver opened `(12 native,17 token)` and the payer recovered `(75,103)` from two original notes totalling `(90,120)`, with a fee of three native units. Private actors used temporary seed files on tmpfs. A fresh public process, without any wallet mount, verified the full packet and recovered both ordered ciphertexts. Both public verifier programs also rejected the other's genuine proof given their own expected framing. The two proof shapes and query counts differ, so this cross-profile result does not isolate a wrong-key rejection on an otherwise identically parsed argument. This comparison exercised a funded tree, real witness, recipient scan, fee and change. It exercised no TKQ1 mining, fork, node admission, typed historical certificate or wallet respend. [Entire public payment](evidence/payment.bin) · [Experiment](probe.py) · [Build receipt](evidence/BUILD.json)

## What strengthened, and what still needs a proof

The existing argument uses original Poseidon over Goldilocks for its commitments and challenges. Its upstream authors cite a roughly 95-bit algebraic estimate for that configuration. TKQ1 removes that assumption from two roles involving adversary-generated commitments and challenges. The pinned library's `KeccakGoldilocksConfig` truncates Merkle digests to 25 bytes, so TKQ1 defines its own `GenericConfig`, with full 32-byte legacy Keccak-256 digests. In an ideal generic model, 200-bit digests have arbitrary collision scales about 2^100 classically / 2^66.7 in quantum queries; for 256 bits the scales are about 2^128 / 2^85.3. Fixed-target preimage costs differ. These scales characterize digest lengths and primitives; they give no end-to-end payment security figure. The 26-field statement still goes through the original algebraic Poseidon public-input digest. Note commitments, receipt digest, key derivation and the two-lane opening still rely on existing primitives and hiding assumptions. [Upstream Poseidon assessment](https://github.com/0xPolygonZero/plonky2#security) · [Pinned Keccak code](https://github.com/Quantus-Network/qp-plonky2/blob/632f23ca07712bfa5bc8ed082bc05c41c5929dfb/plonky2/src/hash/keccak.rs) · [Native transcript call site](https://github.com/Quantus-Network/qp-plonky2/blob/632f23ca07712bfa5bc8ed082bc05c41c5929dfb/verifier/src/plonk/get_challenges.rs)

The challenger uses an implementation-specific 12-field state. It serializes the state, applies legacy Keccak-256, repeatedly hashes each previous digest, and rejection-samples canonical u64 field elements until the state is full. The call site absorbs public inputs via `InnerHasher`, then switches to `Hasher` for the challenge engine and Merkle caps. This is a custom Fiat–Shamir construction. FIPS 202 SHA3-256 has a different suffix; SHA-3 standardization does not establish this transcript's QROM theorem. Recursing via the previous algebraic `verify_proof` gadget also needs additional non-algebraic hash support and a newly registered wrapper. There is no TKQ1 D8 verifier. [Keccak team’s padding conventions](https://keccak.team/keccak_specs_summary.html) · [Reference recursive assumptions](../../delayed-eight/assurance/ASSURANCE.md)

**A finite Reed–Solomon discriminator.** Let `N` be the evaluation domain, `k` the polynomial dimension, `t` an agreement-set size and `d=k−1`. For any fixed received word, each pair of distinct degree-`<k` polynomials agrees together on at most `d` points. Given `m` candidates with at least `t` matching indices each, truncate every match set to `t`. Let `h_i` count matches at index `i`. Cauchy–Schwarz gives `(mt)²/N ≤ Σh_i² ≤ mt + m(m−1)d`. Consequently `m ≤ floor[N(t−d)/(t²−Nd)]` when the denominator is positive. At `t=N/4` this is at most six polynomials for **both actual domains**. This deterministic fact applies to one received RS word and states nothing about which adaptive transcript an adversary can produce.

For a challenge drawn uniformly from `p=2^64−2^32+1` field elements and mapped modulo `N`, a fixed set of `t` positions has worst-case mass `s=(floor(p/N)t+min(t,p mod N))/p`, where `p mod N=1`. For `q` independent draws with replacement, the conditional probability they all land in that fixed set is at most `s^q`. At one-quarter agreement the exponents are approximately 52 and 128 bits, respectively. If there are at most six prelisted bad sets each of that size, union bounding reduces those to 49.415 and 125.415. The RS list lemma bounds the number of highly agreeing polynomials; it does **not** bound the size of their agreement sets from above or force the verifier’s acceptance into those prelisted sets. Those are separate assumptions. At one-half agreement the single-set exponents are 26 and 64 bits. [Exact probabilities and finite list bound](evidence/BOUNDS.json) · [Calculator using the real keys](bounds.py)

Actual FRI needs bounds across its committed and folded words, correlations between rounds, field and degree errors in batched openings, Fiat–Shamir adaptivity, and knowledge extraction. Growing the trace from 4,096 to 16,384 also changes degree-dependent algebraic error terms. The published noninteractive FRI analysis illustrates the gap between conjectured and proved figures for its own settings. Neither increasing queries nor changing the hash proves whole-transcript zero knowledge, multi-user receipt privacy or a 128-bit PQ security level. [Block and Tiwari, *On the Concrete Security of Non-interactive FRI*](https://eprint.iacr.org/2024/1161) · [TKN1 assurance](../../token-profile/ASSURANCE.md)

## Reproduction

Use the same Linux prerequisites, pinned Qnero checkout, Rust 1.93.0 and genuine registered TKN1 reference runtime described by the prior release. `baseline` below is the *typed* native installation containing `native`, `BUILD.json` and `registered/token.vk`. Verification starts with operator-approved local source/runtime inputs. The build overlay uses a temporary upstream copy. All emitted evidence files are public. Host testing initially selected a Rust home lacking 1.93.0; selecting the existing pinned toolchain completed the unchanged build. [Reference setup](../../token-profile/README.md)

```sh
cmpdir=experiments/token-devnet/comparison
python3 -IB "$cmpdir/build.py" "$lab/tkq" "$upstream" "$lab/target"
RAYON_NUM_THREADS=2 "$lab/tkq/native" register "$lab/tkq/registered" > "$lab/tkq/REGISTER.json"
cmp "$lab/tkq/registered/token.vk" "$cmpdir/evidence/tkq1.vk"
python3 -IB "$cmpdir/probe.py" "$lab/tkq" "$baseline" "$cmpdir/evidence" --replay
python3 -IB "$cmpdir/probe.py" "$lab/tkq" "$baseline" "$lab/fresh-public"
python3 -IB "$cmpdir/bounds.py" | cmp - "$cmpdir/evidence/BOUNDS.json"
```
