# Complete 2x2 relation and matrix cost

The compiler calls the registered PaymentAir for Arity::Two and captures all 966 symbolic assertions. It traverses the resulting DAG at every one of the 512 rows. Fixed table and first/last/transition selectors become constants. Current and next trace variables refer to shared witness columns, including cyclic next-row semantics. The 49 public field elements project from the canonical 528-byte public instance. Linear operations remain sparse affine forms. Each product of two nonconstant forms gets one multiplication row and one private output. Each remaining zero assertion becomes a linear-times-one row. Wire 0 denotes one. This specific translation shares subexpressions in a row, keeps the full free trace, and does not optimize away inactive intermediate products. Wire numbering is deterministic. [Actual lowering](lower.rs).

The generated forms evaluated on the pinned intentionally public witness produce zero residuals. Changing its first trace word produces 33 nonzero residuals. These are relation controls. They do not generate a proof. MATRIX and FFT below operate without a witness. Full canonical parsing and context absorption, verification of both receipt commitments from the ciphertext envelopes, minimum fee, eligible anchor and prior spentness remain required at their existing CP03 boundaries. Replacing the AIR proof changes none of those obligations.

| Metric | Goldilocks R1CS | Direct EF5 lift with base-field constraints |
|---|---:|---:|
| Nonpadding constraints | 614,387 | 19,587,059 |
| Private variables | 612,532 | 19,288,756 |
| Public variables, excluding one | 49 | 49 |
| Matrix A/B/C nonzeros | 2,658,143 / 3,073,703 / 316,084 | 21,630,815 / 22,046,375 / 19,288,756 |

Each of 296,448 original private trace entries can be restricted to Goldilocks in EF5 by requiring its 64th successive square to equal its 32nd. For a nonzero element the difference of exponents equals p−1. Zero also satisfies the equality. The last square writes into the existing 32nd square wire. This adds exactly 64 rows and 63 auxiliary variables per original trace word. All arithmetic intermediates of the base relation are then determined. The four-challenge probabilistic batch check in the primary experiment is an explicitly different constraint mechanism with a separate soundness/hiding account.

## Public verifier work

The matrix probe prepares the verifier's own sparse matrices once using the program and public preprocessing. It builds the row equality basis, contracts A/B/C with their three EF5 weights, adds the four masked subfield-equation coefficients on original trace wires, and performs the first four binary folds of the private main linear form. The base ring and quintic binomial extension come from the pinned CP03 dependency build. The source matrix has 6,047,930 nonzero entries. In memory, 104,139,524 bytes store used terms and row endpoints, while Vec capacities allocate 146,800,640 bytes, before temporary arrays and process overhead. The two halves of the theorem's square matrix have length 2^20 each. The omitted public padding and all-zero constraint rows have zero contributions.

The input is three distinct previously published ordinary statements, never witness files. These seed reproducible public challenge values **for component timing**. The samples do not purport to be full Fiat–Shamir transcripts. The timing charges statement-specific work. Static matrix preparation, output checksum, remaining mask columns and later PCS stages are outside the CPU interval. The three measurements were made on one thread of an Intel i7-8700K with clock_gettime(CLOCK_THREAD_CPUTIME_ID). The statement-specific kernel took 0.245–0.261 CPU seconds. Actual sparse multiplication and acquisition of the row basis alone took 0.186–0.196 CPU seconds. This describes the tested generic verifier, not a lower bound on structured evaluation. [Per-statement measurements](MATRIX.json).

## Reproduction

Use the standard approved CP03 installation in BUILD.md. Pass its reviewed installation digest and use the CP03 locked compiler and artifacts. The public fixture digest is checked before lowering. The measurement scripts do not install packages.

```sh
installation=.work/smoke01/fresh/installation.json
approval=REVIEWED_INSTALLATION_SHA256
python3 -I -B experiments/node-validation/dimensions/run.py --installation "$installation" --approve-installation "$approval"
python3 -I -B experiments/node-validation/dimensions/run.py --installation "$installation" --approve-installation "$approval" --measure-matrix
python3 -I -B experiments/node-validation/dimensions/run.py --installation "$installation" --approve-installation "$approval" --first-row
```

Compare dimensions to RESULT.json and the per-instance combined-form digests to MATRIX.json. Timings vary. The optional FFT test computes two independent first-stage rows from the reviewer's salted nonuniform schedule at 2^21 points and 65,600 live coefficients over EF5, using the public power-of-two base subgroup. Its reusable radix-2 transform skips zero coefficient layers. Eight Horner point checks independently verify ordering and field limbs. These are public coefficient controls, not a wallet proof. The experiment leaves all 16 first-stage rows, tree hashing, disk, remaining oracles, masks and proof creation outside the row timings.

Two executed 83,886,080-byte row transforms took 0.3304 and 0.3348 thread CPU seconds. All eight independent Horner spot checks matched. A simple 16-row serial multiplication would charge about 5.3 CPU seconds to the initial transforms alone. This extrapolation excludes commitments, proof generation and interaction with full memory pressure. [Row measurements](FFT.json).
