# Funded C proof transcript and assurance boundary

## Result

The registered MNG3 and SLG3 verifiers authenticate genuine arithmetic proofs
for the funded C relations. Their exact noninteractive transcript and proof
geometry are reproducible from the committed verifier keys under the documented
`qp-plonky2` 1.5.5 behavior. The calculator checks the keys and selected project
sources; it does not independently authenticate the crate bodies or VCS
metadata. This establishes what the committed keys encode and gives exact
wire/resource counts under that source interpretation. It does **not**
establish 128-bit post-quantum knowledge, monetary soundness, or witness
privacy.

The strongest concrete numerical statement presently available for C is a set
of conditional terms. For an accepted index set fixed before 32 independent
uniform Goldilocks draws, the exact modulo-biased probabilities have negative
binary logarithms 160, 64, and 32 at accepted fractions 1/32, 1/4, and 1/2.
These are not FRI soundness bounds: no result yet proves that a dishonest C
proof induces any one of those fixed agreement fractions. An illustrative
substitution into the algebraic terms of OPlonky Lemma 4.9 gives individual
exponents 86.66, 113.70, and 111.83. The source-to-protocol correspondence
needed to invoke that lemma is itself unproved, and the FRI and Fiat--Shamir
losses would still follow.

The calculated proof-only S64 profile keeps the MNG3/SLG3 relations but raises
PLONK repetitions from two to three and FRI queries from 32 to 64. It is
strictly stronger under the named conditional screens. Its illustrative
OPlonky terms are 126.98, 170.26, and 110.83 bits, so this unproved mapping does
not certify the 128-bit research target. The 110.83-bit diagnostic is not an
upper bound on actual S64 security and does not prove that S64 has less than
128-bit security. Separately, S64 forces the ZK trace from 8,192 to 16,384 rows
and makes one ordinary frame 391,551 bytes. It is an exclusion under the current
physical-frame discriminator and a resource warning, not a cryptographic
exclusion or a proposed registration.

## Pinned implementation and statement

The registered keys are:

| Suite | Verifier SHA-256 | Public words | Circuit digest (Goldilocks words) |
|---|---|---:|---|
| MNG3 | `6cb89745c94ec7b2ff97173ec0819b8567ae5672991b2fdbbe3cbe5810ebadf2` | 32 | `12506747794040179225, 15517120205601633546, 16461419357440957906, 5462923815520472060` |
| SLG3 | `7acd892eb041260a90efe30fc19771922da2be083707dec4116f8b3af9765c4a` | 35 | `17477970102056484515, 12739924158267392744, 7996841224285012482, 2274105909567426162` |

Project build records attribute both keys to Qnero revision
`f04c91307837c0231668383bec76ba98d89d2652` plus the funded C patch, and to
`qp-plonky2` 1.5.5 at VCS revision
`632f23ca07712bfa5bc8ed082bc05c41c5929dfb`. This artifact records those pins
but does not independently check the qp-plonky2 crate bodies or their
`.cargo_vcs_info.json` metadata. The verifier-key hashes and selected local
project source/patch hashes that the calculator actually checks are recorded in
`PARAMETERS.json`.

The common public-input prefix is:

| Indices | Meaning |
|---:|---|
| 0--3 | selected anchor root |
| 4 | public height |
| 5--12 | two public nullifiers |
| 13--20 | two public output commitments |
| 21 | native fee |
| 22--25 | digest of the two ordered receipt ciphertexts |

MNG3 then publishes the four-word effective asset ID at 26--29, the tagged
mint/burn delta at 30, and the funded tree depth at 31. SLG3 publishes eight
bounded 32-bit one-time authorization-key limbs at 26--33 and the funded tree
depth at 34. Admission must derive this last word from the selected eligible
ancestor; it is not a prover-selected current-head hint.

The witness relation is inherited from MNG1/SLG1 and hardened for C. Every real
input uses the same hidden `ask`, `nk`, note opening, native/token values and
authentication path in:

```text
pk    = H(PK, H(AK, ask), nk)
inner = H(NOTE, pk, rho, r)
cm    = H(CM, inner, native_value)
nf    = H(NF, nk, rho, r)
```

The domain-tagged note hashes are the Qnero Poseidon2 sponge, not the original
Poseidon used by the proof transcript. MNG3 enforces the typed asset opening,
62/63-bit value bounds, native conservation and fee, and token transfer or
authorized public delta. SLG3 enforces the same base ownership and membership,
private token conservation, fee in `{0,3}`, a real first input, and output
openings bound to the published one-time authorization key. The receipt digest
is constrained as a public field value; the relation does not prove correct
encryption or receiver decryptability.

C additionally makes the depth a public input, forbids public depth zero,
requires a nonzero selected digest at every active level for a real input, and
requires the resulting real root to be nonzero. These checks preserve the
sorted quaternary set-membership semantics. They do not turn it into positional
membership and do not prove collision/preimage security of the note/tree hash.

## Exact registered C transcript

### Fields, polynomials, and commitments

The base field is Goldilocks
`p = 2^64 - 2^32 + 1`; challenges and opened values use the quadratic
extension `K = Fp^2`. The trace has `n = 8192` rows and the rate-1/32 LDE has
`N = 262144` positions. There are 135 witness columns, 60 routed columns, four
fixed selector/constant columns, 60 fixed permutation-sigma columns, two
permutation repetitions, seven partial-product polynomials per repetition, and
eight quotient chunks per repetition. The gate list is `Noop`, `Constant(2)`,
`PublicInput`, `BaseSum2(59)`, `Arithmetic(15)`, `Poseidon2`, and `Poseidon`.
Selector filtering makes nine the relevant declared gate-degree bound. The key
field 123 is the maximum constraint-vector length, not a row count.

The proof commits to four initial polynomial batches:

| Oracle | Leaf before hashing | Hiding |
|---|---:|---|
| constants and sigmas | 64 base words | verifier-owned, no leaf salt |
| witness wires | 135 polynomial words + 4 salt words | random rows and fresh leaf salt |
| two Zs and 14 partial products | 16 polynomial words + 4 salt words | correlated random Z rows and fresh leaf salt |
| 16 quotient chunks | 16 polynomial words + 4 salt words | derived from prior randomized data and fresh leaf salt |

Each cap has 16 four-word digests. Original Goldilocks Poseidon is used for
these Merkle commitments: a leaf initializes capacity word 8 with
`leaf_length + 1`, while an internal node hashes the eight ordered child words
from zero capacity. The resulting digest space has `p^4` elements. Treating it
as an ideal 256-bit hash would give generic benchmarks near 128 classical or
85.3 quantum queries for a freely chosen collision, and near 128 quantum
queries for one fixed-target preimage. Those are different games and are not
security lower bounds for the instantiated Poseidon or for a funded spend.

The transcript challenger is the original width-12 Goldilocks Poseidon with
rate eight and capacity four. Its duplex operation overwrites pending rate
lanes, permutes, discards buffered outputs when new input arrives, and returns
squeezed words in reverse buffer order. There is no external ASCII suite label
inside this challenger. Parameter serialization and the circuit digest separate
the registered MNG3 and SLG3 circuits; the wrapper's `MNG3`/`SLG3` bytes are
not an additional Fiat--Shamir absorption.

### Fiat--Shamir schedule

For either C key the verifier performs the following schedule. Reordering any
item changes the challenges.

1. Absorb the field sequence
   `[5,4,0,1,2,3,32,1,13,2,2,2,2,2]`, the four-word circuit digest, and
   `Poseidon::hash_no_pad(public_inputs)`. Absorb the 16-digest wire cap. Draw
   two base-field betas, then two base-field gammas.
2. Absorb the 16-digest Z/partial-product cap. Draw two base-field alphas.
   Absorb the 16-digest quotient cap and draw one quadratic-extension point
   `zeta`. No lookup challenges exist.
3. Absorb extension evaluations at `zeta` in this order: four constants, 60
   sigmas, 135 wires, two Zs, 14 partial products, and 16 quotient chunks (231
   extension values). Then absorb the two Z evaluations at `g*zeta`. The proof
   byte encoding places the next-point Zs earlier than this challenge order.
   Draw one extension-field FRI batching alpha.
4. Five times, absorb a 16-digest FRI cap and draw one extension-field folding
   beta. The LDE domains are
   `262144 -> 65536 -> 16384 -> 4096 -> 1024 -> 256`; every fold has arity
   four. Absorb all eight final extension coefficients and one base-field PoW
   witness. With zero grinding bits, draw the response and then 32 base-field
   words. Reduce each word modulo 262144, with replacement, to obtain query
   positions. Because `p mod 262144 = 1`, residue zero has one extra preimage.

At each query the proof opens all four initial leaves with depth-14 binary
paths. It then discloses four extension evaluations at each FRI round with path
depths 12, 10, 8, 6, and 4. It exposes 3,072 sibling hashes and 640 folded
extension values in total. The final degree bound is less than eight, and all
eight extension coefficients are public.

### Blinding and the missing privacy theorem

The builder solves a fixed point because more openings require more blinding
rows and a larger trace changes the terminal FRI polynomial. For either C key,
32 queries require 1,504 FRI opening masks per polynomial. The builder adds:

- 1,506 all-wire random no-op rows;
- 1,508 pairs of no-op rows, with the same random value copied across each
  routed wire in a pair; and
- random values in otherwise unused public-input-gate wires.

Thus 4,522 rows are designated for row blinding. MNG3 has 5,070 rows and SLG3
5,080 rows before padding to 8,192. Initial witness, Z/partial, and quotient
leaves each also carry four independently sampled base-field salt words.

These are implementation facts, not an HVZK proof. Queried salts are revealed.
Folded FRI leaves are unsalted. The extension evaluations, all FRI caps and
openings, and the terminal polynomial are public and correlated with the same
witness and transcript challenges. An applicable simulator must reproduce the
joint distribution of row-blinded wires, permutation products, quotient
openings, salted commitments, unsalted folds, terminal coefficients, adaptive
query locations, multiple proofs, and public commitments/nullifiers. No such
simulator has been established for these keys.

## Primary theorem map and missing hypotheses

| Required claim | Potential primary result | Premises not yet established for C |
|---|---|---|
| Interactive trace knowledge | OPlonky Lemma 4.9 and Theorems 1.8/1.10 give round-by-round soundness/knowledge for their indexed polynomial protocol and its correlated-agreement compiler. | Exact translation of the seven gate evaluators, selector grouping, permutation copy index, public-input compression, two repetitions, quotient chunks, point domains, and the fork's batched two-point opening protocol. |
| Low-degree/oracle extraction | OPlonky Lemmas 4.7--4.8 and Theorem 4.10, plus a compatible FRI list/proximity theorem. | A proved agreement/list regime for rate 1/32 over these exact domains; shared queries across batches; salts; power batching; arity-four folds; final degree eight; and all correlated-agreement losses. |
| Concrete noninteractive FRI | Block--Tiwari, Lemma 1 and Theorem 1, analyze classical-ROM Fiat--Shamir security of FRI under round-by-round and commitment hypotheses and quantify conjectured versus proved regimes. | Their result is not a lookup table keyed only by rate and query count. C needs a parameter-level mapping, commitment binding, actual list sizes/agreements, field sampling, all commit-phase errors, and the complete PLONK opening composition. |
| Quantum noninteractive knowledge and ZK | Chiesa--Manohar--Spooner (CMS), especially Definitions 8.3--8.5 and Theorem 8.6, transfers round-by-round knowledge and HVZK for its salted BCS construction in the QROM. | An RBR extractor and state function for C; an HVZK simulator; the CMS hash chain and salted Merkle compiler; programmable/collapsing ideal-oracle conditions; a mapping from the overwrite-mode Poseidon sponge; query surcharge and constants; adaptive statements, many proofs/users, forks, retries, and auxiliary receipt information. |
| Alternative multi-round QROM soundness | Don--Fehr--Majenz measure-and-reprogram results apply to eligible public-coin multi-round protocols with explicit query/round loss. | Identification of the actual challenge stages and ranges, an underlying quantum interactive property, and a faithful chained-random-oracle transcript. Treating the complete PLONK/FRI schedule as a three-move Sigma protocol is invalid. |
| Commitment/hash binding | Generic random-oracle or collapsing-commitment premises used by the compilers. | No reduction instantiates those premises with the fixed Goldilocks Poseidon leaf/node hash and overwrite challenger. A four-word ideal collision benchmark is not a funded-note opening theorem. |

Primary sources:

- Block, Garreta, Katz, Thaler, Tiwari, and Zajac,
  [*Fiat--Shamir Security of FRI and Related SNARKs*](https://eprint.iacr.org/2023/1071).
- Block and Tiwari,
  [*On the Concrete Security of Non-interactive FRI*](https://eprint.iacr.org/2024/1161).
- Chiesa, Manohar, and Spooner,
  [*Succinct Arguments in the Quantum Random Oracle Model*](https://eprint.iacr.org/2019/834).
- Don, Fehr, and Majenz,
  [*The Measure-and-Reprogram Technique 2.0*](https://arxiv.org/abs/2003.05207).

CMS's ideal bound contains terms of order `t^2 * epsilon` and `t^3 / 2^lambda`
for `t` quantum oracle queries, in addition to verifier queries and hidden
constants. Even granting a complete interactive error of `2^-130` and a
256-bit ideal oracle, the first term becomes order one around `2^65` queries
and the second around `2^85.33`. This is a limitation of that sufficient
reduction, not an attack cost. The concrete Poseidon transcript has not been
shown equivalent to that ideal compiler.

## Reproducible numerical bounds

For a set of `a` accepted indices fixed before sampling and an LDE of size `N`,
one uniform canonical field word lands in the heaviest such set with probability

```text
(floor(p/N) * a + min(p mod N, a)) / p.
```

Raising this value to the number of queries gives the exact conditional terms
reported by `calculate.py`. Independence, prior fixation, and the assumed set
size are essential. A dishonest noninteractive proof chooses commitments and a
statement before some challenges but after others; a FRI theorem must justify
the reduction to an appropriate fixed set.

The OPlonky figures in `PARAMETERS.json` substitute C values into the three
individual terms stated for Lemma 4.9:

```text
(3*n*(r' + u)/p)^t
((k + (s + 2)*t - 1)/p)^t
max(d, u + 1)*n / |K \ D|
```

with `n=8192`, `r'=60`, `u=s=8`, `k=123`, `d=9`, `t=2`, and
`K=Fp^2`. This yields 86.655, 113.701, and 111.830 negative log2 values.
They identify blockers and do not certify that qp-plonky2 implements the exact
OPlonky protocol assumed by the lemma.

## Same-relation S64 comparison

S64 changes only proof parameters in the model:

| Parameter | Registered C | S64 calculation |
|---|---:|---:|
| PLONK repetitions | 2 | 3 |
| FRI queries | 32 | 64 |
| trace rows | 8,192 | 16,384 |
| LDE positions | 262,144 | 524,288 |
| folds | five by four | six by four |
| final extension coefficients | 8 | 4 |
| MNG3 proof | 179,264 B | 387,952 B |
| MNG3 ordinary frame | 182,863 B | 391,551 B |
| SLG3 leg proof | 179,288 B | 387,976 B |
| complete two-leg swap | 400,165 B | 817,541 B |
| conditional fixed-quarter term | 64 bits | 128 bits |
| illustrative OPlonky minimum individual term (not an actual-security upper bound) | 86.66 bits | 110.83 bits |

The trace jump is not optional under this fork's current ZK construction. At
64 queries the builder needs 2,882 regular random rows and 2,884 copied Z-row
pairs, or 8,650 blinding rows. Together with the relation this no longer fits
8,192 rows, so the next fixed point is 16,384.

The existing C run measured six matching ordinary proofs on an Intel i7-8700K:
median 9.852 seconds wall, 19.09 CPU seconds, and 887,112 KiB peak prover RSS.
Three warm ordinary-verification groups had medians 8.13 ms native CPU and
8.78 ms wall. S64 was not built or benchmarked. Its exact structural workload,
relative to C, is 2.18 times as many initially committed base-word cells, 2.31
times the polynomial-count/domain/log-domain FFT scale, 2.25 times as many
Merkle sibling hashes, and 2.4 times as many disclosed FRI fold values. These
ratios are resource projections, not runtime or memory measurements.

S64 fails the 262,144-byte physical-frame discriminator by 129,407 bytes for an
ordinary payment. This is a byte/resource result, separate from cryptographic
qualification. Increasing queries and PLONK repetitions does not change the
quadratic-extension size used by the single `zeta` identity check. Under the
unproved OPlonky substitution, the third diagnostic term remains about 110.83
bits after the trace doubles, so that route fails to certify 128 bits. It does
not bound actual S64 security above by 110.83 bits. The unchanged four-word
Poseidon commitment and unmatched QROM/HVZK hypotheses also remain open.

## Decision

No query-count-only or repetition-only edit to the current D=2 backend
currently supplies a theorem establishing 128-bit post-quantum spend knowledge.
The diagnostic calculations show failure of the examined certification route;
they do not prove that every such profile has less than 128-bit actual security
or that another analysis is impossible. A same-relation route can remain a
legitimate research direction, but the presently identified qualification path
needs a proof-backend and transcript redesign: at minimum a larger extension
field, enough independent algebraic repetitions, retuned FRI/list parameters,
and a wider explicitly framed commitment/Fiat--Shamir construction for which
the required classical RBR knowledge, HVZK, and quantum compiler premises can
be mapped. That route must then regenerate registrations, measure real proofs,
and compose extraction with the legacy note commitment, funded tree,
nullifier, receipts, adaptive many-proof ledger game, and atomic state rules.
It is not a current 128-bit claim and does not require changing the monetary
relation merely to continue the experiment.
