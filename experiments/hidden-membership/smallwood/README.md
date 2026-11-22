# Two linked FS01 parents with SmallWood+ Compiler 1

An independently implemented SmallWood+ Compiler 1 prototype generated and verified a proof of two consecutive hidden SHAKE256 parents. The verifier owns the circuit, the starting level and the expected 64-byte result. At the wider field setting, one proof was 6,926,976 bytes, took 22.969 s to produce and 2.917 s to verify. This measures the paper's generic R1CS route. Its smaller published Keccak estimates concern a different statement and arithmetization. [Measurements](evidence/gf256.json) · [Primary source and implementation provenance](SOURCES.md)

A subsequent run kept 256-bit challenge elements and committed the binary R1CS witness over GF(2^16). The measured linked proof fell to **241,664 bytes**, with 6.517 s proving and 1.034 s verification. On the same profile, the separate full funded-path wire inventory prices 5,966,544 proof bytes. [Mixed-field implementation and results](mixed/README.md)

| Parameter or measurement | Small calibration | Wide calibration |
|---|---:|---:|
| Binary base and challenge field degree, F = K | 16 | 256 |
| Packing s / openings s′ / tree leaves N | 32 / 16 / 256 | 32 / 84 / 1,024 |
| DECS degree dP / LCS degree dQ | 47 / 79 | 115 / 147 |
| DECS linear combinations | 16 | 4 |
| Salt bytes / Merkle digest bytes | 16 / 32 | 32 / 64 |
| Transmitted proof bytes | 87,760 | 6,926,976 |
| Prove (seconds within process) | 1.189–1.274 | 22.969 |
| Verify (seconds within separate process) | 0.544–0.612 | 2.917 |
| Peak prover / verifier RSS, KiB | 91,164 / 91,168 | 360,980 / 98,344 |
| Independently generated ordinary positive cases | 4 | 1 |

The ordinary positive and deliberately disconnected samples each use two full 24-round Keccak-f[1600] evaluations. For the disconnected controls, each parent hash is calculated honestly over its own input. The prover inserts the second input at the wrong boundary and serializes the whole proof; the fresh verifier rejects the inconsistent link. Every run also rejected changed expected root, level and opening as well as trailing and truncated bytes. The generator shuffles the four direction combinations in private memory. Each small-field run uses all four. Public transport carries the level and final root only, outside the proof. The 65-byte statement is additional to the reported proof sizes. Measurements use CPython 3.12.3, NumPy 1.26.4, GCC 13.3.0, Linux x86-64 and Intel Core i7-8700K. Each role reports its own high-water RSS and monotonic duration. The JSON also includes whole child-process wall time. The wide range has one positive timing sample. [Small measurements](evidence/gf16.json) · [Wide measurements](evidence/gf256.json)

## Reproduce

Run from this directory in the checkout. The public packets use fresh cryptographic randomness on every new proof. Use a fresh output directory for each call.

```bash
python3 check.py
python3 role.py verify evidence/gf16.statement evidence/gf16.proof
run_dir=$(mktemp -d)
python3 reproduce.py "$run_dir/fresh-small"
./build-wide.sh "$run_dir/native"
PYTHONPATH="$run_dir/native" SW_FIELD=gf256 python3 check.py
PYTHONPATH="$run_dir/native" python3 reproduce.py --wide "$run_dir/fresh-wide"
PYTHONPATH="$run_dir/native" SW_FIELD=gf256 python3 role.py verify \
    "$run_dir/fresh-wide/case2.statement" "$run_dir/fresh-wide/case2.proof"
```

The wide extension requires CPython 3.12 development headers, a C compiler, PCLMULQDQ and SSE4.1. The local field implementation uses little-endian limb encoding. The reproduction driver derives its expected roots with the separate FS01 hashlib evaluator, passes ephemeral private values through stdin to its prover child, then launches independent verifier children with public input only. The diagnostic prover can emit a full invalid wire packet for the disconnect test. Verification always runs all checks. The allowlisted small sample supports a separate public replay. The checked-in wide statement and digest identify the measured wide proof; a new run emits its own statement, packet and measurements. [Source and build pins](SOURCES.md) · [Role separation](role.py)

## Relation and compiler

Each parent absorbs 131 bytes, comprising the prefix 0xf1, tag 0x07, one level byte and two 64-byte children. A one-bit private direction selects their order. The SHAKE suffix starts at byte 131, final padding bit at byte 135 and capacity bits start at byte 136. The circuit extracts 512 output bits. The binary permutation transition commits one output wire per chi result and derives theta, rho and pi as affine functions of the previous round. The next level reuses all of the first digest wires. Two selectors, the child's starting digest and both siblings are bit-constrained over the challenge field. Two dedicated witness coordinates constrained to zero and one supply constants. The complete system has 81,412 witness coordinates and 81,922 R1CS rows, padded with zero evaluations to a 17-variable cube. The standalone check verifies both field moduli, products against independent polynomial arithmetic, all four orientations and the location of all violated rows for detached assignments. [Circuit](relation.py) · [Independent differential checks](check.py)

The sum-check evaluates a cubic equality-weighted row polynomial. Each of 17 rounds transmits three masked evaluations, then commits to its next challenge via the running Fiat–Shamir transcript. Three masked linear endpoints and the two messages from linearizing the single trace product complete the trace. The 56-element trace mask is sampled and committed together with the witness before the row randomizer. Seven final linear constraints bind the constants, three matrix evaluations and two trace identities. The verifier generates their coefficient vectors independently. [Figures 5, 6 and 13 implementation](sumcheck.py) · [Engine](engine.py)

DECS uses salted Merkle commitments and verifies completion of its random linear combinations against the preliminary digest. LCS uses the full Q polynomial in evaluation form. With d = s+s′, the mask splits as Mlo + X^s Mhi with both parts of degree at most d−1. The s′ overlapping coefficients are randomized independently while preserving their sum. For any s′ distinct openings this free polynomial has an invertible Vandermonde evaluation map, so the extra mask-part openings can be sampled given the combined mask openings. The verifier uses separate points for the packed witness, random padding and Merkle evaluations. It reconstructs both Q and R at the declared degrees. Full per-leaf authentication paths include repeated siblings. The transcript binds the statement before the commitment and length-prefixes each labeled message. The verifier has its own profile identifier and fixed parser. These local serialization choices preclude interoperability claims against an unpublished author wire format. [Figures 4 and 8 implementation](commitment.py) · [Transcript](transcript.py)

The wide proof spends 6,859,776 bytes on opened columns, 53,760 on authentication paths, 2,688 on salts, 4,096 on R completion, 4,736 on Q, 128 on initial digests and 1,792 on sum-check and linearization. Each of 2,546 committed witness/trace rows contributes a whole 32-byte element to every opening. Under the measured generic R1CS arithmetization this cost dominates. A mixed base/challenge field, the structured round protocol in §6.2, flattening and zero-knowledge ring switching change this geometry; none was priced by extrapolating this proof to a full payment.

## Assurance boundary

The row-equality test has the paper's interactive bound 17/|K|, giving only 11.913 bits for the small calibration and 251.913 for the wide run before Fiat–Shamir. For wide parameters the corresponding single DECS error term is binom(1024,117)/2^1024 (503.745-bit exponent), the opening term is binom(147,84)/binom(1024,84) (273.743), and the field mixing term is 2^−256. These calculations concern individual protocol stages under the paper's assumptions. They do not establish 128-bit monetary security in the quantum random oracle model. The code has no production review and uses data-dependent table lookups, branching and Python integer operations. The component claims knowledge of a path segment to a public result. Funded ownership, a hidden in-range position at full depth, distinct real inputs, conservation, nullifiers, receipts and monetary acceptance require the encompassing proof. [Assurance analysis](../assurance/) · [FS01 relation](../../fresh-spend/binding/RELATION.md)
