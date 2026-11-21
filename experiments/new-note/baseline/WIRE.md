# Funded proof byte errata

The archived 259,212-byte signed FTL1 leg and the 261,068-byte extremal frame both fit. The published comparison calls the 139,658-byte SLG1 payload a “bare” proof. Its encoder serializes a proof body, a u64-LE public-input count, then all 34 public field words. FTL1 serializes a proof body alone in its proof-length field and places 38 words in a separate fixed-length statement. Subtracting only the words, as in the historical 139,386-byte baseline, still charges eight vector-framing bytes to the proof. A like-for-like comparison uses **139,378** cryptographic body bytes for SLG1. The historical 21,060-byte overhead is valid for a hypothetical fixed-width 34-word replacement. The physical released overhead on a pure body is **21,068**. The pivot's “26,624 Merkle siblings” is a byte count for **416** sibling digests. None of these corrections changes a published signed total or the closed registration decision. [Historical decision](../../funded-tcith/DECISION.md#measured-funded-costs) · [Historical pivot](../../lattice-spend/pivot/README.md) · [Pinned Rust read/write methods](https://github.com/Quantus-Network/qp-plonky2/blob/632f23ca07712bfa5bc8ed082bc05c41c5929dfb/verifier/src/util/serialization/mod.rs#L1219)

| Physical field (bytes) | Live ordinary MNG1 | Live signed SLG1 | Funded FTL1, first / second |
|---|---:|---:|---:|
| Outer header, including applicable owner signature | 6 | 107 + 17,088 | 107 + 17,088 |
| Inner versioned ID + proof-length u32 | 9 | 9 | 9 |
| Two ordered receipts | 3,584 | 3,584 | 3,584 |
| Public vector prefix and statement | 8 + 248 | 8 + 272 | 0 + 304 |
| Pure proof body | 139,378 | 139,378 | 238,120 / 237,800 |
| Physical proof-length field's value | 139,634 | 139,658 | 238,120 / 237,800 |
| Complete signed leg or ordinary packet | 143,233 | 160,446 | 259,212 / 258,892 |

Both funded histories contained ordinary zero-delta MSP1 transfers, allowing both live envelopes to be read from physical bytes. Issuer-signed MSP1 registration/mint has a different outer layout. At equivalent boundaries, the first candidate adds 98,742 body bytes and 24 bytes of statement/framing to the live signed leg. The second adds 98,422 and 24. The mixed pairs measure 419,671 and 419,351 bytes, against 320,905 for a released pair. Each pair costs another 13 bytes above its two frames. An FTL1 verifier's 32-byte derived context and its local 3,717,289-byte registered program are outside the frame. [Packet parser](../../funded-tcith/wallet/ftl_wire.py) · [Ordinary envelope](../../managed-assets/managed_ops.py) · [Released signed envelope](../../atomic-swap/swap_wire.py)

## FTL1 extrema and tail

Three 64-byte transcript digests cost 192 bytes. The 32 open rows cost 1,024 salt bytes plus 32 × 533 × 8 = 136,448 field bytes. Degree tails cost 117 × 33 × 8 = 30,888. Each of five monetary batches sends 1,037 − 32 − 117 = 888 additional polynomial evaluations, 116 explicitly sent secret linear values, and 265 − 32 − 117 = 116 other linear evaluations. Together these cost 35,520 + 4,640 + 4,640 = 44,800 bytes. There are **9,461 terminal field words**. Exactly one secret linear value per batch is recovered from its sum. Thus the fixed proof part is **213,352 bytes**. [Prover and verifier loops](../../funded-tcith/proof/engine.cpp) · [Opening serialization](../../funded-tcith/proof/commitment.hpp)

With 32 distinct openings at height 18, if a level has A active children and B active parents, it emits 2B − A sibling hashes. Summed over levels, the count equals 2 − 32 plus the sum of the numbers of occupied nodes at internal depths 1 through 17. Aligned consecutive leaves minimize this sum. One leaf per depth-five subtree maximizes it. The two frontiers therefore have 13 and 416 siblings, giving 214,184–239,976 bare bytes and 235,276–261,068 signed bytes. The maximum has 1,076 bytes of headroom. The two Fiat–Shamir-derived funded frontiers had 387 and 382 siblings. Actual headroom was 2,932 and 3,252. These extrema are over valid subsets, independent of how often such subsets arise in a proof. [Source parameters](../../funded-tcith/proof/field.hpp) · [Authenticated public reader](../../funded-tcith/review/readback.py)

## Projected alternatives

A fixed-length TCitH statement uses no serialized public-vector count. With the old four-word auxiliary root the modeled MSP1 transfer wrapper is 6 + 9 + 3,584 + 35 × 8 = 3,879 bytes. The signed wrapper is 107 + 17,088 + 9 + 3,584 + 38 × 8 = 21,092. With seven root words and a depth word these become 3,911 and 21,124. Applying the eight-byte correction to these fixed-width proposals would introduce a field absent from the proposed codec. The four-word MNG1 result is a projection. Only the four-word signed FTL1 was implemented.

At the seven-word branch's original geometry the ordinary/signed projections reprice to 395,439/417,772 bytes. At its first fitting screened geometry the pair is 241,567/261,468. The separately projected one-challenge codec gives 1,145,544,999/1,189,845,092. The calculator also cross-checks both intermediate seven-word geometries with attained frontiers and recomputes each fixed-length three-party view sum. None of these alternate figures is an observed funded proof. [Seven-word model](../../funded-tcith/security/WIDER.md) · [Single-challenge view encoding](../../funded-tcith/security/ONE_CHALLENGE.md)

## Reproduce

From the repository root and two empty output directories, use the release files and their existing checksum manifests. The calculation uses Python's standard library and reads only the public fixtures.

~~~sh
lab=$(mktemp -d)
repo=$PWD
mkdir "$lab/first" "$lab/second"
assets=https://github.com/jouliene/pq-private-chain/releases/download/funded-tcith-2026-11-21
curl -fsSL "$assets/funding.tar.gz" -o "$lab/first/funding.tar.gz"
curl -fsSL "$assets/independent-funding.tar.gz" -o "$lab/second/independent-funding.tar.gz"
(cd "$lab/first" && sed -n '/  funding.tar.gz$/p' "$repo/experiments/funded-tcith/RELEASE.sha256" | sha256sum -c - && tar -xzf funding.tar.gz)
(cd "$lab/second" && sha256sum -c "$repo/experiments/funded-tcith/review/INDEPENDENT.sha256" && tar -xzf independent-funding.tar.gz)
python3 -IB experiments/new-note/baseline/wire.py "$lab/first/public" "$lab/second/public" | cmp - experiments/new-note/baseline/WIRE.json
~~~

The independent size calculation verifies both archives' physical boundaries. It reuses the original reviewer’s public Merkle reader for transcript-dependent authentication. The original funded experiment supplies the proof-verification and ledger results. [Calculated output](WIRE.json) · [Calculator](wire.py)
