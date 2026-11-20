# Picnic3-style Boolean proof of a funded spend

**Reject this lowering for the existing 262,144-byte frame.** The L5 online broadcasts for four funded Poseidon2 seventh powers alone require at least **278,528 bytes**. Across the fixed ordinary relation this partial count reaches **1,314,652,160 bytes**, and for one swap leg **1,347,518,464 bytes**. These are bounds for the explicit Boolean circuit below. The 49,024-byte stock Picnic3-L5 specimen proves knowledge of a LowMC key for a much smaller circuit. The experiment verified the stock signatures and evaluated a real modular arithmetic component. No complete funded proof was generated. [Component counts](GATES.json) · [Verified signature measurements](KAT.json)

## What each opening sends

The source pin is Microsoft Picnic v6.0, commit `c56abd3baf6629c1f1c122929ebbaac8a9baec15`. KKW uses MPC with preprocessing. Picnic3 derives private tapes from seed trees and commits to the simulated views with a Merkle tree. A common transcript hash commits to preprocessing hashes, the views root, salt, LowMC public key/plaintext and message. Its deterministic expansion chooses a subset of distinct executions and one hidden party for each selected execution. The `T-u` other executions expose preprocessing seeds through a shared tree cover. In the `u` selected executions the verifier gets the seeds for the other 15 parties in compressed form. Four 32-byte seeds cover those 15 leaves at L5. This pricing includes Picnic3's compressed preprocessing and uses its online-opening count of 68. The older Picnic-FS three-party protocol has a different repetition schedule and wire format. [KKW paper, corrected January 2021](https://eprint.iacr.org/2018/475) · [Picnic3 paper](https://eprint.iacr.org/2020/427) · [Pinned challenge and hashing](https://github.com/microsoft/Picnic/blob/c56abd3baf6629c1f1c122929ebbaac8a9baec15/picnic3_impl.c#L456-L543) · [Reference parameters](https://github.com/microsoft/Picnic/blob/c56abd3baf6629c1f1c122929ebbaac8a9baec15/picnic.c#L87-L194)

An AND appends a single bit to each simulated party's broadcast. Only the hidden party's broadcast is transmitted in its online proof. The final preprocessing party supplies one correction bit per gate, and its correction string is present when the hidden party differs from that final party. The masked private input is always transmitted for each online opening. With `G` AND gates, `u` openings, `k` transmitted correction strings, private input width `w` bytes, digest width `h`, seed width `s`, and `N=16`, the exact serialized byte count is

```text
h + 32 + initial_seed_cover_B + view_merkle_cover_B
+ u*(4*s + w + h) + (u+k)*ceil(G/8)
```

The two covers and `k` depend on the challenges. The mandatory online term is always `u*ceil(G/8)`. The C probe runs the original verifier, deserializes and reserializes each published count-zero vector, compares every signature byte and reconciles all component sizes. For the L5 vector, 64 auxiliary strings were sent. Its 49,024 bytes comprise 96 for challenge and salt, 5,600 for initial seeds, 11,200 for the views-tree opening, 8,704 for party seeds, 8,192 for correction bits, 2,176 for masked inputs, 8,704 for hidden-party broadcasts and 4,352 for commitments. The known-answer signed-message container has a separate length and message prefix. [Reference AND and broadcast](https://github.com/microsoft/Picnic/blob/c56abd3baf6629c1f1c122929ebbaac8a9baec15/picnic3_impl.c#L257-L281) · [Masked key and proof assembly](https://github.com/microsoft/Picnic/blob/c56abd3baf6629c1f1c122929ebbaac8a9baec15/picnic3_impl.c#L785-L858) · [Reference serializer](https://github.com/microsoft/Picnic/blob/c56abd3baf6629c1f1c122929ebbaac8a9baec15/picnic3_impl.c#L996-L1060)

| Stock KAT | Parties | Executions | Online openings | LowMC ANDs | Actual signature bytes |
|---|---:|---:|---:|---:|---:|
| Picnic3-L1 | 16 | 250 | 36 | 516 | 12,200 |
| Picnic3-L3 | 16 | 419 | 52 | 768 | 27,080 |
| Picnic3-L5 | 16 | 601 | 68 | 1,020 | 49,024 |

## Funded circuit and compiler dependence

The registered funded expressions perform 160 permutations in the 31-word MNG1 ordinary transfer and 164 in the 34-word SLG1 leg. Each width-12 permutation has 8 full and 22 partial rounds, hence 118 seventh powers. Both inputs use the fixed maximum depth, including inactive levels. The Boolean candidate evaluates the same field functions directly, with no constant propagation or cross-S-box common-subexpression elimination. This is a gate-level compiler choice. The underlying field, fixed-width membership profile and receipt binding stay the same. [Registered funded shapes](../../funded-whir/relation/README.md) · [Funded seventh-power expression](../../funded-whir/relation/frontend.py) · [Permutation schedule](../../spend-proof-decision/whir_port.py)

The complete test gadget uses 64-bit Goldilocks `p=2^64−2^32+1`. It multiplies two words using 4,096 partial-product ANDs and 4,096 one-AND full adders. It reduces the 128-bit product with 128 fixed steps. Each step subtracts the constant modulus using 65 carry ANDs and selects 64 low result bits using 64 ANDs. The result uses exactly 24,704 ANDs per field multiplication in this compiler. The fixed carry is `a XOR ((a XOR b) AND (a XOR carry))`. Its truth table, modular products and seventh powers were checked against integer arithmetic on zero, boundary and deterministic random operands. The complete `x², x⁴, x⁶, x⁷` chain uses 98,816 ANDs. [Executable Boolean network](gate_count.py)

For the conservative comparison, count only the 4,096 original-bit partial products in each of the final two nonsquare products, `x⁴·x²` and `x⁶·x`. Omit both full squarings, all carries, all reductions, every correction, masked inputs and all other constraints and serialization. This leaves `160×118×8192` and `164×118×8192` AND bits per online opening. Multiplying by 68 and dividing by eight gives the opening sizes in the first paragraph. Even the cheaper L1 schedule gives 147,456 online bytes for four S-boxes and 4,349,952 bytes for one full permutation using this partial count. Optimized squarers alone cannot remove the two nonsquare products. An arithmetic MPC protocol, a different multiplier or a circuit that exploits witness structure needs its own inventory. [Gate counts and schedule](GATES.json)

A separate size check is independent of the multiplier. Explicitly passing both depth-20 paths with three siblings of four 64-bit limbs per level costs `2×20×3×4×8=3,840` masked-input bytes per selected execution. The L5 openings alone transmit 261,120 bytes. Adding the two 1,792-byte funded receipts brings this to 264,704 bytes before any AND, signature, header, other witness fields or tree cover. A path-compression or witness-generation circuit would change this particular argument. [Input copy in reference code](https://github.com/microsoft/Picnic/blob/c56abd3baf6629c1f1c122929ebbaac8a9baec15/picnic3_impl.c#L1033-L1056) · [Funded path and external receipt verification](../../funded-whir/relation/README.md)

The amplified RS primary candidate's registered schedule has 1,172,088 modeled maximum proof bytes, including 9,903 Merkle siblings. This alternative removes RS codeword queries but pays for gate broadcasts. Its conservative compulsory online bytes alone exceed the physical frame by thousands of times. The RS number describes a modeled maximum for that profile. The Boolean numbers above are all-challenge lower bounds for this compiler. [Primary calculation](../primary/MODEL.json)

## Security scope

The three stock signatures are real LowMC proof instances. They establish source and wire correspondence for this price calculation. Adapting KKW to funded notes requires specifying the relation and canonical field encodings, range and balance checks, real/dummy handling, authenticated membership, nullifiers, output currency and commitments, authorized key, fee, and the complete public statement in the challenge. The actual Picnic3 optimization for LowMC propagates the input mask using the circuit's structure. A generic MPC preprocessing implementation must account for its own masks and corrections. This estimate describes a candidate retaining the measured masked-input and online-broadcast format. The independently decisive online floor uses zero auxiliary bytes. [Picnic3 implementation paper](https://eprint.iacr.org/2020/427) · [Reference specification v3.0](https://github.com/microsoft/Picnic/blob/c56abd3baf6629c1f1c122929ebbaac8a9baec15/spec/spec-v3.0.pdf)

Don, Fehr, Majenz and Schaffner explicitly discuss Picnic3 under their Merkle commit-and-open extraction result. Theorem 5.1 assumes the required special soundness and models both the commitment hash and the Fiat–Shamir oracle as quantum-accessible random oracles. Its bound contains an additive `(22ℓ log₂ℓ+60)q³2^-n` commitment term and a `20q² p_triv` challenge term. Applying it to a funded predicate would require the extractor for that relation and the mapping of the deployed transcript, seed expansion and challenge distribution to the theorem. The stock L5 label and our finite arithmetic tests do not establish a concrete 128-bit quantum funded-spend bound. [Theorem 5.1 and discussion section 5.3](https://arxiv.org/html/2202.13730v1#S5)

Zero-knowledge is a separate simulation claim. A generic port must justify its preprocessing, witness masking and fresh randomness for the joint view of repeated payments, two swap participants and their encrypted receipts. Each funded wallet still has to decrypt the receipt, authenticate its amount, asset and local spend ownership, then recover the same spend identity. The public verifier must rehash both ciphertexts in order and check the proven digest; the node must still check anchors, spentness and atomic settlement. No funded packet, new signature, restored payment, or privacy theorem was produced by this size probe. [KKW proof model](https://eprint.iacr.org/2018/475) · [Funded wallet and restore checks](../../funded-whir/wallet/README.md)

## Reproduce

From the repository root, the gate check runs with Python 3.10 or newer. To also recount both complete funded frontend shapes, add `--constants PATH_TO_qp-poseidon-core-3.1.0/src/poseidon2.rs`; the frontend enforces the original source digest. The KAT probe uses Clang, make and the published reference archive. Run in a new temporary directory. An upstream compile with GCC 13's default `-Werror` stopped at an array-parameter diagnostic in the older three-party code. The commands below use the unmodified upstream source and its normal warning flags with Clang.

~~~sh
set -eu
d="$PWD/experiments/amplified-spend/kkw"
python3 -IB "$d/gate_count.py" | cmp - "$d/GATES.json"
tmp=$(mktemp -d)
rev=c56abd3baf6629c1f1c122929ebbaac8a9baec15
curl -fLsS "https://codeload.github.com/microsoft/Picnic/tar.gz/$rev" -o "$tmp/ref.tgz"
echo "f2b3611ce215a4903091836f60df2b3ddf10a7b1bcd3e3433b72d4a258d0c2e8  $tmp/ref.tgz" | sha256sum -c -
tar -xzf "$tmp/ref.tgz" -C "$tmp"
p="$tmp/Picnic-$rev"
make -s -C "$p" CC=clang libshake.a libpicnic.a
clang -Wall -Wextra -Werror -std=c11 -I"$p" "$d/kat.c" "$p/libpicnic.a" "$p/sha3/libshake.a" -o "$tmp/kat"
python3 -IB "$d/check_kat.py" "$p" "$tmp/kat" | cmp - "$d/KAT.json"
~~~

Pinned document SHA-256 values are `34b0f7524a790ba9c5f139df30126f1ecbacfa4a01f217cc38258268bf0b7636` for the reference specification and `d4aa39f05e1f37105fc6a8fb2125af15cd10faf8c24d3654b4c056f1866db235` for the bundled Picnic3 paper. [Reference revision and specification directory](https://github.com/microsoft/Picnic/tree/c56abd3baf6629c1f1c122929ebbaac8a9baec15/spec)
