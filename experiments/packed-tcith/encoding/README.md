# Two complete encodings of the funded spend relation

The quadratic encoding reconstructs the published MNG1 and SLG1 matrices byte for byte. The direct encoding represents each seventh power as one check on linear forms, `X^7=Y`, and substitutes affine assignments into subsequent expressions. For a swap leg, this reduces the private assignment from **140,604 to 21,538 Goldilocks elements**. The complete packed relation has **66,539 scalar coordinates** before padding. It pays to tie nonlinear gate ports to the same private assignment, to fixed public words and to each other. No assumption about invisible wiring or free public binding enters this census. [Frozen counts](CENSUS.json) · [Original registered relations](../../funded-whir/relation/README.md)

| Suite and encoding | Private W | Linear rows | Quadratic rows | Seventh-power rows | Packed words before padding | Global linear rows before padding | Private matrix nonzeros before padding |
|---|---:|---:|---:|---:|---:|---:|---:|
| MNG1 registered | 136,964 | 59,613 | 77,362 | 0 | 369,050 | 291,699 | 1,247,146 |
| MNG1 direct | 20,802 | 91 | 1,842 | 18,880 | 64,088 | 43,377 | 395,354 |
| SLG1 registered | 140,604 | 61,112 | 79,507 | 0 | 379,125 | 299,633 | 1,279,174 |
| SLG1 direct | 21,538 | 102 | 2,099 | 19,352 | 66,539 | 45,103 | 406,250 |

## Reconstruction and wiring

The compiler executes the same frozen frontend with two arithmetic backends. The registered backend keeps every multiplication and matches the SHA-256 of the original serialized A/B/C matrices. For packing, a rank-one row with a structurally constant operand becomes a public linear equation. The direct backend substitutes structurally constant multiplications into public linear forms. It creates a single result wire and a seventh-power check for the original chain `x²,x⁴,x⁶,x⁷`. Every original satisfying chain has this unique result. Every satisfying seventh-power row extends uniquely to the removed chain by field arithmetic. Affine substitutions are identities. All other nonlinear constraints pass through the original builder. The frozen direct format has a version, public and total column counts, row count, tagged row degrees, sorted sparse column indices and canonical coefficients. A separate reader evaluates it against an arbitrary canonical field assignment. [Compiler and row evaluator](encoding.py) · [Funded expression builder](../../funded-whir/relation/frontend.py)

For private vector W, quadratic ports A/B/C and seventh-power ports X/Y, the six groups contain exactly `[W,Q,Q,Q,S,S]` words. The quadratic-only layout omits X/Y. Each port has one global equation equating it to its affine form on W and the registered statement. Constraint rows with no nonlinear product go directly into the global linear system. All constant and public coefficients go on the known right-hand side. CENSUS.json records private nonzeros, the structurally nonzero known-side terms, and the unpadded global rows. For packing width s each vector is separately padded. Every unused position receives a zero constraint with one private coefficient. At s=101, ordinary registered/direct have 105/249 padding rows; swap registered/direct have 332/222. Direct SLG1 therefore has 45,325 global rows and 406,472 private matrix nonzeros. The independent reader reconstructs each port coordinate, applies the polynomial on every active lane, checks all hidden linear links, enforces canonical field words and checks every tail. Tests change both input and local product consistently and separately change a padding word. Both changes are rejected. [Packed reader](packed.py)

Both encodings include the 45-word header preimage and anchor, two maximum-depth-20 arity-four membership checks with private ordered child wires and one-hot path choices, monotone depth flags, real/dummy restrictions, note identity and ownership-key derivation, nullifiers, typed token openings, integer bounds and exact native and token sums. The program has 160 ordinary or 164 swap Poseidon2 permutations, each with 118 seventh powers. Ordinary fee and zero supply are bound in the 31-word public input. SLG1 constrains its 0-or-3 fee and the eight public u32 authorization-key words, including their contribution to the output raw openings, in its 34-word public input. The public verifier separately recomputes the released ordered receipt hash over two 1,792-byte ciphertexts. The four digest limbs are tied to the instance inside the relation. Symmetric encryption correctness, actual signed pair assembly, branch eligibility and spentness remain duties of their existing components. [Semantic contract](../../funded-whir/relation/README.md)

**Cost-only membership ablation.** Subtracting the two path bodies and their eight final real-root links removes 120 permutations. This identifies the cost of the existing membership checks and retains the input commitment computations, header and shared-depth bookkeeping. Direct MNG1 still has 5,682 private columns and 51 linear, 874 quadratic and 4,720 seventh-power rows. Direct SLG1 still has 6,418 private columns and 62 linear, 1,131 quadratic and 5,192 seventh-power rows. The corresponding quadratic-only residuals are 34,724/38,364 private columns and 19,754/21,899 quadratic rows. All accepted runs use both complete membership checks. A versioned membership replacement would need to authenticate the same note, owner, spent identity and selected state and account for its new checks. [Ablation census](CENSUS.json)

## Public reproduction

Use Python 3.11+, curl, tar and the repository root. The archived reference material contains a previously independently verified funding branch. The replay checks the sealed work, ordered ancestry from genesis, every funded tree root, the receipt digests and all four archived public vectors. The replay samples one publicly positive mined reward locally. It never writes the chosen reward, position or sibling path. Both encoders evaluate all 20 circuit levels on this real path and reject a changed sibling. The archive holds public proof material; its old spend keys and private openings cannot be recovered from it. The full-witness path below supplies the separate end-to-end check with fresh authorized spending material.

~~~sh
set -eu
d="$PWD/experiments/packed-tcith/encoding"
work=$(mktemp -d)
curl -fLsS https://static.crates.io/crates/qp-poseidon-core/qp-poseidon-core-3.1.0.crate -o "$work/poseidon.crate"
echo "5872607e25ea4ee5fb37e64bf1462168e1a36a4e719cdc8a105533c708253918  $work/poseidon.crate" | sha256sum -c -
tar -xzf "$work/poseidon.crate" -C "$work"
constants="$work/qp-poseidon-core-3.1.0/src/poseidon2.rs"
curl -fLsS https://github.com/jouliene/pq-private-chain/releases/download/funded-whir-2026-11-20/independent-public.tar.gz -o "$work/events.tgz"
echo "06c6e392a7896aa8670c365e3895e3d673f676e75919b143be36c823851d4673  $work/events.tgz" | sha256sum -c -
(cd "$work" && tar -xzf events.tgz && sha256sum -c SHA256SUMS)
python3 -IB "$d/encoding.py" "$constants" | cmp - "$d/CENSUS.json"
python3 -IB "$d/check.py" "$constants" --events "$work/public" | cmp - "$d/PUBLIC.json"
~~~

The Python-only check reads the pinned publicly verified release and recomputes its PoW links, roots and public projections. The archived 31/34/34/31 word comparisons use the independently released reference and previous WHIR packets. The new direct circuit has no public proof or wallet openings in the archive. To independently rerun all original public proof verifiers, use the [funded comparison reproduction](../../funded-whir/README.md).

## Reproduce with private disposable funds

Use x86-64 Linux with functioning nested unprivileged bubblewrap, original pinned Rust tools and a new private work directory. These commands mine a fresh local native-for-token branch and stop its nodes; the next command builds isolated capture roles from the original pinned Qnero sources. A fresh setup needs no previous user's wallet. For an existing completed private native-for-token home, reuse that home, its matching capture binaries and the pinned constants. Get the public constants as above. [Original funding and capture instructions](../../funded-whir/wallet/README.md)

~~~sh
umask 077
./pqd swap --home "$work/lab" native-walkthrough
git init -q "$work/qnero"
git -C "$work/qnero" fetch --depth=1 https://github.com/DigitalGuards/qnero.git f04c91307837c0231668383bec76ba98d89d2652
git -C "$work/qnero" checkout --detach FETCH_HEAD
python3 -IB experiments/funded-whir/wallet/build.py "$work/capture" "$work/qnero" "$work/cargo-target"
python3 -IB "$d/funded.py" "$work/lab" "$work/capture" "$constants" | cmp - "$d/FUNDED.json"
~~~

The four separately mounted workers control one seed each. The first three consume real funds from the same previously mined common branch as parallel comparison cases. The fourth independently replays the **original** selected released swap, restores its actual 8-unit native receipt with Alice's backup, and constructs an onward spend of 5 plus fee 3. Fresh original proofs are independently accepted by their released registered verifiers. Each process captures its own full witness through a bounded kernel FIFO, recompiles both fixed shapes in memory, verifies every original or direct row and both complete packed layouts, and matches the same public vector and ordered ciphertexts. Its only export is an allowlisted set of public counts and checks. No proof under a TCitH registration was produced. The experiment measures relation shape and execution equivalence; it supplies no new quantum knowledge, hiding or encrypted-receipt composition theorem.
