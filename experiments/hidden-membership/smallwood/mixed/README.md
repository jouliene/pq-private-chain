# Mixed-field Compiler 1 measurement

The same linked FS01 statement produced a 241,664-byte proof with a GF(2^16) commitment and GF(2^256) challenges. The prover took 6.517 s and reached 102,628 KiB RSS. A new verifier process took 1.034 s and reached 97,768 KiB. Process wall times including startup were 6.711 s and 1.221 s. One positive proof and one complete detached proof were generated. Both private selectors were sampled randomly. All four private combinations had already been covered by the same public R1CS. The detached proof has two individually correct hashlib parents and a deliberately inconsistent link. The verifier rejected it and also rejected changed expected root, level, masked sum-check message, opened column, final degree-check response, truncation and trailing data. These are component results. [Raw role measurements and rejection reasons](evidence.json) · [Pinned statement](evidence.statement)

## Construction

The base field uses the binary modulus 0x1100b. The challenge field uses X^256 + X^10 + X^5 + X^2 + 1. The implementation maps the base generator to a fixed root of its degree-16 modulus in the challenge field. It expands the 256 powers constituting the extension basis as 16 base directions times the first 16 powers of the large field's polynomial generator. Binary Gaussian elimination verifies full rank and constructs the inverse conversion. The test exhausts the 65,536 base elements for multiplication by the base generator and addition by each basis vector. Both compositions of the conversion maps are checked on every binary basis vector. [Field conversion](subfield.py) · [Algebra checks](check.py)

The 81,412 R1CS witness coordinates are binary and fit in the base field. Each of the 56 masked trace coordinates occupies 16 base-field elements in the commitment. Each trace linear-functional coefficient is multiplied by the corresponding extension basis element before aggregation. The test changes each of these 16 positions in turn and checks that its contribution survives. The width on input to LCS is 82,308 base coordinates, giving 735 rows of 112 elements. The DECS random linear combinations are sampled over the base field; the sum-check, random linear constraints and Q polynomial use the challenge field. Q is evaluated at the images of the base interpolation and opening points. Each K-valued mask is split into 16 base polynomials and then into two independently overlap-randomized chunks per component. Each opened column therefore contains 735 witness/trace values, 32 mask-part values and 75 DECS mask values. [Commitment and proof](backend.py) · [Fixed public verifier](role.py)

With s=112, s′=88 and N=2,048, dP=199 and dQ=311. The 88 columns consume 148,192 bytes, the separate Merkle paths 61,952, salts 2,816, R completion 16,800, Q 9,984, the roots 128 and masked trace 1,792. The 65-byte public statement is outside these figures. The small-field degree error has exponent 256.677 and the opening subset error 256.263. The R1CS row test still has exponent 251.913. These are separate interactive terms. The project has no established concrete multi-user quantum Fiat–Shamir knowledge or joint privacy bound for this implementation. [Executable calculation](price.py) · [Numerical results](price.json)

## Cost on larger statements

Applying the unchanged wire encoder to the recorded two funded depth-40 membership paths (3,723,978 witness coordinates, 22 sum-check variables) gives **5,966,544 proof bytes**. A separate funded execution reproduced this exact byte count and checked the dual-path proof in a new public process. [Funded measurements](../../paths/MEASURED.json) The optimistic complete-payment inventory has 3,854,992 AND outputs, 49,233 private input coordinates and two constants. Assuming all linear wires remain virtual and 22 variables suffice gives 3,904,227 coordinates, 71 trace-mask elements, 34,870 packed rows and **6,249,904 proof bytes**. Under existing FS01 pricing, that corresponds to 6,253,894 ordinary wire bytes, 6,283,822 for one signed leg and 12,567,664 for a two-leg bundle. The envelope price includes receipts and the swap signature overhead where applicable. The payment R1CS, role-specific receipts and authorization acceptance were not compiled or exercised by this measurement. Extra serialization or materialized wires increase the price. [Funded circuit](../../paths/) · [FS01 envelope and receipts](../../../fresh-spend/binding/RELATION.md)

## Reproduce

From the parent smallwood directory, use a fresh output directory. Runtime and compiler pins match the wide build in the [parent guide](../README.md). The parsed statement always supplies the expected level and root independently of the proof. The producer accepts the ephemeral fixture through stdin and the verifier receives only public artifacts. The SHA-256 digest in the recorded metrics identifies this particular randomized proof.

```bash
run_dir=$(mktemp -d)
./build-wide.sh "$run_dir/native"
PYTHONPATH="$run_dir/native" python3 mixed/check.py
PYTHONPATH="$run_dir/native" python3 mixed/reproduce.py "$run_dir/mixed"
PYTHONPATH="$run_dir/native" python3 mixed/role.py verify \
    "$run_dir/mixed/mixed.statement" "$run_dir/mixed/mixed.proof"
python3 mixed/price.py
```

## Private selection for a structured Keccak prover

A clear executable mapping places a pair of 512-bit children, a private direction and the public level into the exact 1,600-bit FS01 parent state. Write A_j and S_j for each child's 32 successive little-endian 16-bit polynomial-basis elements and b for a shared direction bit. For every j compute D_j = b(A_j + S_j), L_j = A_j + D_j and R_j = S_j + D_j. Characteristic two gives L=A, R=S when b=0 and L=S, R=A when b=1. The same D_j supplies both outputs. Constraining b(b+1)=0 over the base field excludes all other field values. The needed nonlinear selection work is 32 base-field products per parent and one bitness check if b was not constrained elsewhere. Two depth-40 paths have **2,560 selection products** and up to **80 direction-bitness products**. This counts boundary selection alone. The 80 Keccak permutations and the proof's masking, commitments, evaluations, range checks and messages have separate costs. [Clear mapping and tests](packed_parent.py)

Let V[0..63] concatenate the ordered L and R elements. Number the full state's 100 packed words from zero. Rows use little-endian polynomial-basis bit coordinates, and lo/hi denote the low and high eight coefficients viewed as bytes.

| Word | 16-bit value |
|---|---|
| 0 | 0x07f1 |
| 1 | level XOR (lo(V[0]) << 8) |
| 2 through 64 | hi(V[i−2]) XOR (lo(V[i−1]) << 8) at word i |
| 65 | hi(V[63]) XOR 0x1f00 |
| 66 | 0 |
| 67 | 0x8000 |
| 68 through 99 | 0 capacity |

Word 33 crosses from the first child into the second. Each consecutive group of four words forms one Keccak lane with its lowest 16 bits first. Header and padding introduce public affine offsets. Byte projections and shifts are linear over GF(2). For example, the low-byte projection sends 1 to 1 and X^8 to zero, so it cannot be multiplication by any fixed GF(2^16) scalar. A packed-field backend must explicitly verify the linear maps in the bit basis or provide the appropriate ring-switching constraints.

Run `python3 mixed/packed_parent.py` from the parent smallwood directory. It exhausts the selector-bitness polynomial on all 65,536 base-field values. For each of two orderings, all 1,024 possible single-bit inputs match an independent literal byte layout. All 40 level offsets are checked for both directions. An independent lane permutation over the complete input row agrees with the existing FS01 hashlib-based parent in 160 evaluations, including two distinct funded paths in one sparse tree and separate tests for both orientations at every level. The tests emit aggregate counts only. [Observed results](packed-evidence.json)

A specialized GKR proof still needs to bind the packed preimages, the shared selector, the GF(2)-linear byte projections, public level, suffix and zero capacity to the **same** committed 1,600 input bits consumed by each first round. It must prove all 24 rounds and constraints across any flattened groups, transfer exactly the first 512 output bits in the same basis to the next child's selector, and bind the final 512 bits to the verifier-owned expected root. The direction at each level must coincide with the corresponding hidden index bit, with count and distinct-index checks for the funded inputs. Any packed-to-bit consistency proof, trace-hiding commitments, Fiat–Shamir statement binding and query limits need evidence for this combined circuit. No specialized proof was produced by the mapping test.
