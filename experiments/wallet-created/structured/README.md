# Structured 2×2 wallet proof

Three fresh ordinary 2×2 statements have genuine masked outer sumchecks, three constrained-code switches and publicly verified terminal openings in the selected full-size geometry. The wallet experiment creates the payments, encrypted receipts and subsequent spends. The verifier accepts only the registered circuit and canonical 528-byte statement. Each wallet handles its own assignment and randomness. The verifier reads public statement and proof files, has no wallet input and rechecks every proof in `verify-many`.

| Fresh payment | Proof B | Complete body B | Prover wall s / peak KiB | Structured matrix CPU s on actual transcript |
| --- | ---: | ---: | ---: | ---: |
| 1 | 259,232 | 264,108 | 27.368 / 2,339,664 | 0.0654 |
| 2 | 258,208 | 263,084 | 27.712 / 2,339,552 | 0.0687 |
| 3 | 257,808 | 262,684 | 27.590 / 2,339,596 | 0.0680 |

The last column is one measured component within an actual complete proof check. The frozen-oracle pass in the same process cost 0.2531–0.2582 CPU s, including its additional output checksum. After subtracting both measured matrix intervals in those same runs, the remaining public parsing and cryptographic verification took 0.0106–0.0112 CPU s per payment. The audit compared every coordinate and verified each proof to EOF. Cold verifier processes construct the plan themselves. A long-lived validator can reuse its public plan. Its measured preparation and actual per-payment cryptographic, parsing and admission costs are distinguished in the [wallet experiment](../wallet/). The operating system was Linux on an Intel i7-8700K. The three proof values imply 26.3292 decimal TB per 100M complete bodies at their sample mean, before blocks, history indices and redundancy. Neither the 1 nor the 5 decimal TB archive comparison is achieved at that occupancy. [Individual timed audit](evidence/REAL_AUDIT.json) · [normal build identity](evidence/BUILD.json) · [audit build identity](evidence/AUDIT_BUILD.json)

## Matrix equality

Let `e(a,r)` be the Boolean multilinear equality basis, with bit zero first. Write constraint row `r=256h+l`. Each absolute private column after the 50-element public prefix has index `65536q+c`. Its weight after the four first-stage row-index folds is `e(gamma,q)`. In one pass over a verifier-generated sparse matrix, collect every triple `(l,j,M_j[r,col])` for a fixed row block and absolute column, where `j=0,1,2` selects A, B or C. Equal ordered lists share a dictionary entry. At proof time that entry evaluates to

```text
D = sum over triples of e(alpha[0:8],l) · rho^j · M_j[256h+l,col].
```

For each occurrence add `D · e(alpha[8:21],h) · e(gamma,q)` to private output c. Public occurrences add `D · e(alpha[8:21],h)` to their original public column. Expanding the two equality factors gives every original nonzero once. The four binary row folds use the same little-endian high-row layout as the oracle, by multilinearity of `a+g(b−a)`. No row-number periodicity or coefficient sparsity heuristic enters the identity. The 33,678 dictionary entries have 1,994,680 terms. The plan executes 1,013,985 tile-pattern products and 1,017,368 destination additions. Truth of a statement never enters preparation. [Compiler and evaluator](plan.rs)

For guard base b, the first 296,448 private words receive coefficient `rho^(4+j) b^(i+1)`. With `W=65,536`, this length comprises four whole rows and a 34,304-word prefix. For each c, weight the four full rows and, if c is in the prefix, row four by `e(gamma,q) (b^W)^q`. Multiply by `rho^(4+j) b^(c+1)`. This derivation also covers b equal to zero or one. It does not require division. The separately folded auxiliary blind coefficient is `rho^(4+j)`. The remaining witness padding has zero guard coefficient.

The original three published statement-seeded tapes produced the published all-form checksums. Their paired structured and generic guarded first folds matched on the 50 public and 65,536 private coefficients by digest. CPU measurements were 0.0761–0.0903 s structured and 0.2835–0.3453 s generic. The executable then moved to independently generated Fiat–Shamir coins on each real private payment. An audit-only build instruments the actual verifier. It reproduces the published sparse coefficient loop, guard loop and four materialized row folds with substituted real coins and compares the two coefficient arrays directly, element by element. All three matched. The reproducible diagnostic SHAKE digests are output after the comparisons. [Published-tape pairs and RSS](evidence/MATRIX.json) · [audit instrumentation](audit.py) · [actual-tape comparisons](evidence/REAL_AUDIT.json)

## Complete proof and verification

For each stage the RS row coefficients are ordered seeds, mask pair (nonterminal only), main, auxiliary. The seed block has q+1 independently sampled EF5 words. The selected domain is the natural order of the positive powers starting with 1 of the pinned Goldilocks two-adic generator. The terminal code and fresh blind use independent Merkle trees. All salts and nodes are 64 bytes. The distinct queried leaves and the canonical missing siblings are serialized in their verifier-derived order. Canonical 40-byte EF5 parsing, exact section sizes and EOF are mandatory. Authentication data is excluded from future challenge derivation: roots, direct fields and prior logical coin packets define the interactive coins. [Code](oracle.rs) · [framing](tape.rs)

| Stage | Domain | Main / aux per row | Rows | q | Polynomial coefficient count per row |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 2,097,152 | 65,536 / 8 | 16 | 53 | 65,600 |
| 2 | 524,288 | 4,096 / 5 | 16 | 38 | 4,142 |
| 3 | 131,072 | 256 / 3 | 16 | 30 | 292 |
| Terminal / fresh | 131,072 | 256 / 37 | 1 each | 31 | 325 |

The payer constructs its sparse R1CS assignment from the registered payment trace. The initial oracle packs the padded 2²⁰-word witness with three EF5 terminal masks, 110 outer-mask coordinates, four base blinds and public zeros. The wallet sends the initial root and outer mask sum, and answers the four post-commitment guards. A single logical XOF packet supplies the guard vector. The 21 round polynomials each have six coefficients. Three masked terminal values and the derived joint claim bind public statements, all original witnesses, masks and blinds in one opening. [Outer prover/verifier](outer.rs)

Each of three stages runs four quadratic masked sumcheck rounds, fixes the corresponding vectors, commits the next private randomized encoding and sends one padded OOD answer. Actual authenticated old rows, their folded seeds and mask coefficients enter the batching equation. To avoid materializing every RS generator coefficient on the verifier, a geometric main vector `s x^j` is retained as the pair (s,x). Fixing a row bit with stride W multiplies its scale by `1+g(x^W−1)`; double W for each succeeding bit. OOD and generator tail coefficients are explicitly computed, including fresh pad zeros in the generator rows. All pending vectors are expanded at the 256-word terminal. The verifier checks the full 293-coordinate final linear form and evaluates all 325 blinded coefficients at every terminal query. The fresh and previous terminal leaves must match the declared combination. The first inner consistency check depends on the public prefix; a verifier defers that single scalar equality until it has computed the prefix at the first four challenges. The earlier sumcheck polynomial is already bound when the gamma coins are sampled. [Complete PCS](pcs.rs)

The real arithmetic includes amount-range, ownership, occurrence, nullifier and integer balance constraints, including both inputs. Five singly invalid assignments on the established synthetic fixture were rejected by the actual wallet's nonzero-R1CS-residual gate before any oracle was generated. These covered a wrong key with the matching changed nullifier, a different second authentication sibling, a second index equal to the public count, a wrong public nullifier, and extra output value with its matching new commitment. Separately, a changed statement nonce, modified last frontier node, truncated proof, extra byte and noncanonical EF5 encoding were supplied to the actual public verifier. All were rejected. The nonce changes a canonical part of the expected statement outside the 49 AIR-projected words, testing full-statement absorption. [Negative results](evidence/CONTROLS.json) · [negative runner](controls.py)

## Reproduce

Use a checked CP03 installation from the repository build workflow and its approved installation digest. The recorded main installation SHA-256 is `4dbabf63c36a7e26136d43490ef1d032cd4e46958bd2027f0f439fd46d2ade3d`. The experiment uses its existing compiler, Plonky3 field/FFT libraries, Rust payment AIR and vendored Keccak. Each build receipt lists the linked library hashes. Builds write a new executable only. Local temporary source paths can change exact Rust binary/debug/panic identifiers. Use the reproduced build's actual digest in the wallet controller.

```sh
d=experiments/wallet-created/structured
inst=.work/sync01/fresh/installation.json
approve=4dbabf63c36a7e26136d43490ef1d032cd4e46958bd2027f0f439fd46d2ade3d
out=$(mktemp -d)
python3 -I -B "$d/build.py" --installation "$inst" --approve-installation "$approve" --output "$out/cfw"
python3 -I -B "$d/build.py" --audit --installation "$inst" --approve-installation "$approve" --output "$out/audit"
taskset -c 4 python3 -I -B "$d/run.py" --installation "$inst" --approve-installation "$approve" --repeat 1
taskset -c 4 python3 -I -B "$d/fixture.py" --installation "$inst" --approve-installation "$approve" --binary "$out/cfw" --output "$out/fixture"
"$out/audit" verify "$out/fixture/public.statement" "$out/fixture/public.proof"
```

The public fixture driver uses the pinned, explicitly synthetic witness via stdin only. The accepted wallet integration uses fresh authorized notes and a private input channel. For a generated payment directory set `pay` to that directory and run:

```sh
"$out/cfw" verify-many "$pay/payment1.statement" "$pay/payment1.proof" "$pay/payment2.statement" "$pay/payment2.proof" "$pay/payment3.statement" "$pay/payment3.proof"
"$out/audit" verify-many "$pay/payment1.statement" "$pay/payment1.proof" "$pay/payment2.statement" "$pay/payment2.proof" "$pay/payment3.statement" "$pay/payment3.proof"
python3 -I -B "$d/controls.py" --installation "$inst" --approve-installation "$approve" --binary "$out/cfw" --public-payments "$pay"
```

A development full-size fixture was proved and verified before pinning the source/preprocessing transcript domain. It used a different proof format identity and overlapped an independent CPU reference control. Only its timing record is retained; the three real payments and their clean reproductions use the final domain. Two pre-execution Rust compile diagnostics (ambiguous field basis and an OsString path accessor) and a bit-reversed FFT view type error were corrected before execution. The natural-order transform, actual proofs and independent verifier exercise the corrected path. [Development timing](evidence/DEVELOPMENT_FIXTURE.json)

For assurance assumptions and the concrete difference between an interactive error estimate and QROM work, see [transcript analysis](ASSURANCE.md).
