# Private packed terminal for arbitrary binary wiring

This implementation authenticates one public affine equation on binary wires and wide trace masks with a single mixed-field linear-constraint opening. The caller constructs the statement and all coefficients from fixed verification rules, public inputs and its transcript. All fits, timing and proof sizes here belong to the component. The standalone pinned example proves equality of private vectors. Its interface lets the structured Keccak relation supply the actual wires, selectors and terminal constraints.

## Algebra

Let F = GF(2^16) and K = GF(2^256) with the mixed backend's embedding. The basis of F over GF(2) is the polynomial basis b_i=X^i. Its trace-dual basis is u_i. Every x in F encodes 16 bits by x_i = Tr(u_i x). Every K element z decomposes uniquely as the sum of beta_l z_l for the mixed extension basis beta_l. Index its 256 binary coordinates by h=(l,k), bit k of z_l. All sums use characteristic two. The terminal equation supplied by the verifier is

    sum_ib c_ib bit_b(x_i) + sum_t k_t T_t = rhs in K.

The commitment contains one native F symbol per little-endian 16-wire group x_i, 16 F coordinates per trace mask T_t, 256 independent random m_h and their squares q_h, and 16 independent random d_j and their squares e_j. The prover zero-pads its final bit group. The verifier assigns zero coefficients to the unused bits, so they are outside the relation even for a malicious prover. Layout, fields, embedding, profile and lengths enter the transcript before the commitment. Trace masks T_t and ring pads have separate allocations.

Define the F-linear forms

    L_lk = sum_i x_i sum_b bit_lk(c_ib) u_b + u_k [sum_t k_t T_t]_l.

Their absolute traces are exactly the bits of the complete terminal left side. The trace contribution includes the same precommitted T_t used to hide the caller's earlier GKR messages. The prover publishes 256 base-field elements v_h = L_h + m_h + q_h. Verification first requires Tr(v_h) = bit_h(rhs) for each h.

After receiving all v, the verifier samples 256 independent K challenges a_h. The prover sends one K element U. After U the verifier samples 258 independent K batching weights. They compress all of the following linear equations into one call to the mixed LCS. Base symbols use their fixed embedding in K.

    L_h + m_h + q_h = v_h                      for every h
    sum a_h m_h + sum beta_j d_j = U
    sum a_h² q_h + sum beta_j² e_j = U².

For the weighted bit terms, a byte-indexed binary linear map applies the 256 public weights to each wide coefficient, then the existing CLMUL backend multiplies by the embedded dual basis. The trace contribution uses the F-linearity of z -> sum_lk g_lk u_k z_l. The implementation works in bounded chunks. It does not need the 256-by-number-of-wires coefficient matrix. See [ring_switch.py](ring_switch.py).

## Correctness, soundness and privacy scope

For honest pads, Tr(m_h² + m_h)=0 and squaring the equation for U gives the last equation. For a fixed commitment and fixed v, the two U equations imply

    sum a_h² (q_h + m_h²) = sum beta_j² (e_j + d_j²).

If any q_h differs from m_h², conditioning on all other a leaves the square of one independent uniform K variable, so the equality has probability 2^-256. A false q can survive a separate random linear aggregation with probability at most 2^-256 when any equation remains false. The e_j,d_j need no separate check for extracting the original relation. Their discrepancy is a fixed offset before a. If every q is correct and all equations hold, the trace checks imply the caller's equation on the binary unpacking of the committed symbols. A union bound for these two local interactive terms is 2^-255, before the caller and LCS terms. Hash binding, DECS extraction, repeated/adaptive statements and Fiat–Shamir require additional analysis.

In the honest clear-message distribution with fixed genuine inputs and prior circuit view, m_h²+m_h is independently uniform over the 15-dimensional trace-zero subspace for each h. Every v_h is uniform on the affine coset fixed by the corresponding **public** RHS bit. Even after choosing a from these messages, adding sum beta_j d_j gives fresh uniform U over K. These masks are used once. This characterizes the two clear messages given the earlier circuit data in the ideal private-commitment argument. The real root, degree response, opened columns and Q polynomial belong to the inherited masked LCS. A proof of adaptive joint privacy, concrete QROM knowledge or payment-level anonymity does not follow from this distribution or the tests. Fresh masks and the pinned public statement/round schedule are necessary for this argument.

The construction in SmallWood+ Fig. 12 instead starts from a masked multilinear evaluation at a hiding point, sends partial evaluations, and runs a further masked sum-check with a terminal scalar. This experiment needs arbitrary linear forms after Keccak wiring and works directly with trace-dual forms. It has no hiding-point search, scalar inversion or ring retry. Distinct-index selection within the legacy LCS retains its own deterministic challenge sampling. No theorem for Fig. 12 is claimed for this alternative. [Feneuil, Provin and Rivain, §§5–6](https://eprint.iacr.org/2026/2880)

## Wire and measured reproduction

The default suite uses 4,096 leaves, packing width 91, 60 distinct openings, 75 DECS rows, 32-byte salts and 64-byte roots. The legacy 2,048-leaf profile can be selected explicitly. In the default let R = ceil((ceil(nbits/16) + 16 ntrace + 544)/91). The standalone mixed commitment/opening and ring messages cost exactly 120(R+107) column bytes, 46,080 sibling bytes, 1,920 salts, 13,650 degree-response completion, 7,744 Q, 128 digests, 512 for v and 32 for U. The caller's earlier messages and its statement are additional. At these default parameters the historical DECS bound 16·75 − log2(binomial(4096,152)) gives 267.439 bits. The distinct-opening bound log2(binomial(4096,60)/binomial(241,60)) gives 256.195 bits. Both describe local interactive checks.

The retained 514-bit, four-mask proof is 83,866 bytes. A fresh verifier accepted it using only its fixed statement and the public proof on stdin. Nine malformed or invalid inputs were rejected, including a committed pad changed by a nonzero trace-zero error. In that case the public trace projection still passes and the mixed linear check rejects. Exhaustive tests cover the absolute trace dual basis and all fibers of m -> m²+m. Randomized projection/adjoint tests cover eight widths including empty and partial groups. [Receipt](evidence/receipt.json) · [Public transcript](evidence/projection.proof)

Run from the worktree root in the mixed backend's documented Python/NumPy/CLMUL environment. Each record run takes a new directory and uses fresh private inputs in memory.

```bash
run_dir=$(mktemp -d)
experiments/hidden-membership/smallwood/build-wide.sh "$run_dir/native"
export PYTHONPATH="$run_dir/native"
python3 experiments/structured-keccak/ring/check.py algebra
python3 experiments/structured-keccak/ring/check.py verify < experiments/structured-keccak/ring/evidence/projection.proof
python3 experiments/structured-keccak/ring/check.py record "$run_dir/ring-actual"
```
