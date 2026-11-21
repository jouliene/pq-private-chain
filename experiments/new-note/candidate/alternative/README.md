# Fixed public rows for a reusable N7 verification key

The N7P1 verifier spends most of its time rebuilding constants and their Merkle cap for each public statement. A proposed replacement would route the 49 canonical statement words directly to wire 0 on 49 predetermined trace rows. The verifier would use a single statically registered circuit. Only the public-row evaluator below has executed.

## Proposed protocol

Reserve rows I = {0,…,48} at the beginning of the trace. Copy the actual root words, count, fee, context limbs, ordered nullifiers and ordered outputs to their respective wire-0 cells. The copy permutation must connect each row to the value actually used in the relation. Keep the existing count/position constraints, note hashes, asset checks and conservation, while removing the statement-sponge/specialized-constant comparison and transaction-dependent circuit digest. The registered gate types, row numbers, routing, wire count, degree and transcript version are consensus inputs.

Let H be the order-n trace subgroup, h_i its i-th point, and L_i its Lagrange basis. Define q_I(X) as the sum of the 49 selected L_i(X), and PI_s(X) as their sum weighted by the 49 public statement words. On every row in H impose q_I(X)w_0(X) − PI_s(X) = 0. On a selected row this checks that cell against its public word. On all other rows both terms vanish. This numerator has degree at most 2n−2 when the ordinary wire has degree at most n−1. A blinded wire in the existing trace representation still has degree below its padded trace size. Append this term at a reserved exponent in each existing random-alpha quotient accumulator. The prover uses the same constraint in evaluation over the quotient coset. The public verifier checks the matching term at the ordinary opening point using the already opened wire.

Use a new suite/version and absorb the complete length-framed public statement as 49 canonical words into the native challenger after the registered circuit identity and before any challenge is sampled. Decode the effects from the packet independently on the public side. An opening point in H requires an explicit protocol rule. This proposal rejects the transcript, with fresh prover randomness required on a retry. A uniformly random quartic point hits H with probability n/p^4, approximately 2^-242 for n = 16,384. Both roles must use the same rule.

The target retains the already fixed proof circuit throughout the chain's lifetime. Each node obtains or locally constructs the one authorized verification key, checks its identity, and counts its initialization cost separately. Receipt contexts, state eligibility, fees paid by each leg, signatures and the existing public-input canonicality rules remain at the same boundaries as N7P1.

## Evaluator and oracle

For z outside H, L_i(z) = (z^n − 1)·h_i / [n·(z − h_i)]. The code uses Goldilocks and its quartic extension modulo u^4−7, with the exact power-of-two generator from qp-plonky2-field 1.5.5. A single batched inversion evaluates all 49 reciprocal denominators. The production verifier already forms z^n−1. Since h_i/n is a static scalar, a static verifier can precompute it for each selected row.

The check also reconstructs the coefficients of q_I and PI_s independently by an inverse discrete Fourier transform of the sparse trace vector. It evaluates the resulting polynomials with Horner's rule. Three points outside the 64-row test domain and all 64 trace rows agreed. An additional quartic opening agreed with an independent coefficient reconstruction over all 16,384 rows. A subgroup opening was rejected on both domain sizes, and 49 separate single-word changes each changed the quartic numerator at the selected opening. The Python reference took about 2.36 ms median for one numerator over 11 samples. Its simple quartic exponentiation, tuple operations and Python overhead make this a component measurement. It omits all other proof verification and admission.

```sh
python3 experiments/new-note/candidate/alternative/public_rows.py
```

[Implementation](public_rows.py) · [Recorded values and samples](RESULT.json)

## Cost conditional on preserving the N7P1 trace geometry

| Role | Added work or bytes |
| --- | --- |
| Verifier field work | 49 extension denominators, 144 quartic multiplications and one quartic inversion for the batch, 98 quartic-by-base scales for increments to the two sums, then two quartic multiplications for the final numerator. Two known alpha weights fold the shared numerator into the existing two accumulators. Reuse z^n−1 and 49 static h_i/n scalars. |
| Prover quotient work | Static q_I on the 8n coset takes 1 MiB at n=16,384. For each statement a straightforward inverse n-point FFT and an 8n-point coset FFT take up to 1,228,800 radix-two butterflies in total, plus scaling/normalization and approximately one MiB of field-value workspace for PI_s. With both alpha weights precomputed, the 131,072 coset points each need three base multiplications and three additions/subtractions for the numerator and two folds. |
| Prover constraints | Add 49 fixed rows and copy links, remove the 11 statement-sponge permutations, their input arithmetic and seven specialized digest constants. Whether the resulting actual builder stays at degree 2^14 needs measurement. |
| Wire and archive | No additional field commitment, evaluation claim, FRI oracle, proof word, or copy of the 49 public words is geometrically required. Use wire 0's existing opening, evaluator-computed q_I and PI_s, and the already present statement. At equal counts of selectors/quotient pieces, trace degree, query and fold settings, the conditional raw proof length is still 267,504 bytes, and the compact-shape maximum is 246,120 bytes. A new suite identifier and deployment registry still require accounting. |
| Startup and admission | A reusable verification key removes the measured approximately 1.8 s per-statement regeneration step by construction. Unknowns include startup from a pinned serialized key, complete verifier CPU/RSS, proof building time, end-to-end packet size and full-node capacity for the changed protocol. |

## Statement visibility, masks and degree

The 49 row values and the entire PI_s polynomial are public functions of the existing transaction. A fixed verifier key and a static q_I polynomial can be shared by independent senders. Reserve the public cells among ordinary constraint rows before adding the backend's random blinding rows. Replacing random masking cells with public inputs would reduce their entropy. Newly routed copy constraints and the associated permutation-Z evaluations must also be included when reviewing the hiding argument. Across proofs all wallet randomness and hiding-leaf salts still need fresh sampling. The verifier derives the additional numerator at z from the already-opened w_0(z) and public data. This adds no separate witness evaluation at z. Adaptively selected statements, the receipt correlation, PLONK quotient openings, and FRI combination of blinded columns still require a joint simulation or comparable privacy argument for the modified protocol.

At n=2^14 the current backend implements row blinding within n, so deg(w_0) ≤ n−1, deg(q_I) ≤ n−1 and deg(PI_s) ≤ n−1. The new numerator has degree at most 2n−2. It vanishes on H for a valid witness and its quotient by X^n−1 has degree at most n−2. A future explicit mask w'_0 = w_0 + (X^n−1)r with deg(r) ≤ b−1 would instead allow deg(w'_0) ≤ n+b−1 and a new quotient term of degree at most n+b−2. Such a profile must propagate its new bounds through the quotients, opening commitments and low-degree test. It cannot reuse the conditional size numbers without checking those parameters.

The current row-blinded quotient degree bound is below the existing eightfold quotient-coset budget. Permissionless verification still depends on binding the public transcript and checking a vanishing-polynomial identity. The custom gate and transcript need a matched prover, verifier, future recursive verifier if used, and review of random-alpha soundness, copy routing, blinding and quantum/adaptive knowledge. Code that only observes the public statement without enforcing the 49 row equations would leave the funded relation unconstrained. A full proof, actual static verifier, funded spend, complete resource measurement and independent reproduction form the next experimental gate.
