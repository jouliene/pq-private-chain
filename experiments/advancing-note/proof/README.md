# N7P2 fixed payment verifier

One 1,764-byte registration verifies both a single positive note and two positive notes of one owner. Both shapes publish 49 statement words, two nullifiers and two output commitments. A public verifier reads the embedded registration, a statement and its proof. It can start in a new process or serve successive requests from a node. The circuit builder runs only for proving and independent registration regeneration. Raw measurements for both input counts and rejection controls are in [MEASUREMENTS.json](MEASUREMENTS.json).

## Public statement and private relation

The statement consists of root (7 words), funded count (1), fee (1), context (12 little-endian u32 limbs), two ordered nullifiers (14 words) and two ordered output commitments (14 words). Every field encoding is canonical over the Goldilocks prime. The proof wire carries no additional copy of these words. The node supplies the expected values after decoding its own canonical transaction.

Use the N7P1 note, asset, position and 40-level binary Merkle formats with the sponge version word changed to 0x4e375032. The width-12 Poseidon2 permutation, seven-word output, five-word rate, and tags 1 (owner), 2 (note), 3 (funded nullifier), 4 (empty leaf) and 256+level (parent) follow the previous implementation. Different suites have different roots and identifiers. Each real nullifier hashes the seven secret words, funded absolute index, and seven-word commitment. Every real membership binds that same note and position to the accepted root. [Previous encoding](../../new-note/candidate/README.md) · [Versioned sponge](src/sponge.rs)

Slot zero must have positive combined native and asset value. Slot one is a second positive same-owner note at a different position or has zero value in both currencies. Its private selector is the zero test on the bounded sum of its amounts. Each amount is below 2^62, so the zero test has its integer meaning. Both positive slots must share the full root. The optional slot conditionally enforces root equality and distinct index. Both slots have constrained ownership. The input format accepts exactly one or two real openings. For one input, the prover uses its owner's key, zero salt/amounts/asset, position zero and zero path words for the internal filler. Filler membership has no bearing on either the state or its zero value. Its private path and salt need no uniqueness assumption.

The public second nullifier for a single input is H(6, secret[7] || first_funded_nullifier[7]). It has the same encoding as a funded nullifier and stays stable across changed context, change address, fee, anchor or proof randomness for the same occurrence. A re-included note at a different index changes the funded nullifier and therefore the padding nullifier. The node records both public nullifiers in the same spent set and rejects a duplicate, regardless of private input count. Privacy of this related keyed evaluation across proofs is an explicit assumption. A payer who holds note openings can retain them. Public funding, repeated transactions, private endpoint compromise and transport metadata have separate disclosure effects.

Count is in [1, 2^40]. The differences count−1, 2^40−count and count−1−index have 40-bit bounds for each slot, as does index. Token amounts are zero exactly for zero asset identifiers and all positive token amounts use the same 256-bit asset ID. The two input totals equal the two output totals with native fee 0 or 3. The node determines when each allowed fee is valid. All sums fit below the base-field modulus. Zero outputs remain valid. [Full relation](src/relation.rs)

## Direct constraints and Fiat–Shamir transcript

The fixed builder adds one dedicated row ahead of blinding. A copy permutation connects wire i (0 ≤ i < 49) to the relation value at position i. The native prover evaluates 49 scalar constraints w_i − s_i in the quotient on its coset. The verifier checks the same degree-one constraints at the quartic opening. Both use the circuit's existing gate selector and randomized quotient accumulation. The registration's selector group for this row has a degree-six filter, giving degree at most seven in trace columns. For n = 16,384 a numerator contribution is bounded by 7(n−1) = 114,681 and its quotient by 98,297. Other gate groups and the existing quotient factor remain in force. The 49 equations fit the existing 118 gate-constraint slots. [Public gate and binding](src/public.rs)

Each invocation installs its canonical s into this one typed evaluator in a local common-data copy. It preserves the complete registered cap, row, gate order, selectors, routing, protocol parameters and registered digest. Witness generators need no statement-dependent preprocessing. A custom serializer assigns a fixed gate tag and serializes only the unbound template. The program computes the following 48-byte digest for the native challenger.

```text
SHA3-384("N7P2/registered-statement/FS/v1" || 00
         || registered_native_circuit_digest[48]
         || LE32(49) || LE64(s_0) || ... || LE64(s_48))
```

After the FRI parameters, the challenger absorbs this digest through qp-plonky2-core's injective seven-byte chunk encoding. This step precedes the empty stock public-input hash, wire cap and first sampled challenge. Compression, decompression, canonical recompression and expanded verification all receive this same digest. The stock four-word public-input hash only handles an empty vector. The seven digest limbs carry all 384 bits. The cost of substituting a statement also depends on the quotient, copy argument, concrete hashes and Fiat–Shamir soundness. [Proof roles](src/main.rs) · [Native SHA3 and SHAKE domains](src/oracle.rs)

The prover and verifier use qp-plonky2 1.5.5, quartic Goldilocks, two PLONK challenge sets, 135 wires and 60 routed wires. FRI uses a 1/32 rate, 32 queries, cap height four, six arity-four folds and no grinding. The proof has 657 gates before backend finalization and 16,384 rows. The backend's accounting gives 2,852 ordinary blind rows and 2 × 2,856 copy-paired blind rows. Secret-bearing oracle leaves use fresh hiding salts. The fixed public row consumes its own space outside the blind rows. No whole-transcript quantum knowledge, adaptive joint zero-knowledge or concrete keyed-Poseidon2 PRF theorem has been established. The recursive evaluator defines the matching arithmetic at a fixed s; a recursive verifier for the full N7P2 transcript has not been implemented or qualified.

## Registration and verification

The SHA3-384 of the embedded registration is `6512fef3faf2e077592284053014091d952dc1194849722d2d42272d8638d44470fbe37a93eda9f0c6f9b1e4a7b202bc`. Its bytes comprise the verifier-only constants/sigma cap and native circuit digest plus serialized common parameters, selector and gate metadata, dimensions and field constants. The trusted binary supplies the gate meaning, SHA3/SHAKE implementation, serialization and native verifier. The deployment therefore also pins its executable and source. No proof supplies a registration or program. The prover regenerates the static registration and byte-compares it against the embedded key. A verifier only decodes those embedded bytes and checks the entire proof fresh. [Embedded key](registered.vk) · [Dependency pins](Cargo.lock)

`verify-stream` first emits a JSON ready record. The trusted local node sends a JSON object containing its expected `statement` object and the `proof` path inside its allowed public filesystem. The service emits `accepted`, byte counts, elapsed time, peak RSS and the fixed key identity on every request. Its stdin is a local node interface. A network peer has no path-selection authority. A malformed request rejects individually. The initial parser is bounded to 1 MiB per proof. Actual admission also enforces the node's canonical frame bounds. Decode/re-encode, query-index checks, decompression, recompression and expanded verification all precede acceptance. [Service implementation](src/main.rs)

## Reproduction

Run from the repository root with Rust 1.93.0. Use an empty output directory name for every check. The witness stays in process memory and the prover's private stdin. The checks save only the synthetic public statement, proof and meters.

```sh
export CARGO_TARGET_DIR="$PWD/.work/n7p2-target"
export RAYON_NUM_THREADS=4
manifest=experiments/advancing-note/proof/Cargo.toml
cargo +1.93.0 build --locked --release --manifest-path "$manifest"
cargo +1.93.0 test --locked --release --manifest-path "$manifest"
binary="$CARGO_TARGET_DIR/release/n7p2"
run=$(mktemp -d)
"$binary" generate-vk "$run/regenerated.vk"
cmp "$run/regenerated.vk" experiments/advancing-note/proof/registered.vk
python3 experiments/advancing-note/proof/check.py "$binary" "$run/two" --positive-only
python3 experiments/advancing-note/proof/check.py "$binary" "$run/one" --single
python3 experiments/advancing-note/proof/size.py "$run/two/proof.bin"
python3 experiments/advancing-note/proof/size.py "$run/one/proof.bin"
```

The Rust unit test fixes s, evaluates the native base and quartic constraint vectors for all 49 individually altered wires, and checks the honest zero residual. That test runs without a challenger. The single-input script separately mutates each coordinate of an actual canonical statement under the public verifier, including changing to the other permitted fee. It also attempts new proofs against changed root, padding nullifier and output commitment, and tests invalid ownership, membership, position, duplicate occurrence, empty inputs, inflation, asset and range. The resident service accepts the original proof after receiving malformed requests. [Control runner](check.py)

## Observed costs

| Native role | One input | Two inputs |
| --- | ---: | ---: |
| Prover process wall | 5.333 s | 5.434 s |
| Prover peak RSS | 1,855,760 KiB | 1,855,916 KiB |
| Public verifier process wall | 13.26 ms | 13.06 ms |
| Public verifier operation | 11.93 ms | 11.82 ms |
| Public verifier peak RSS | 5,840 KiB | 5,704 KiB |
| Canonical proof | 235,746 B | 231,522 B |
| Expanded proof | 267,504 B | 267,504 B |

Each column is one independent relation trial on an i7-8700K with four prover Rayon threads. The operating system and compiler/dependency cache were warm. Fresh verifier process timings include executable startup. Whole-node validation, receipt checks, signatures, block replay and network load require separate measurements.

The observed N7P2 geometry retains the 14,368-byte fixed prefix, 32 four-byte query indices and 136-byte footer. Each distinct initial query needs 243 field words plus four sibling-count bytes. Each distinct folded query needs three quartic field elements plus one sibling-count byte. Required sibling digests contribute 48 bytes each across four height-19 initial trees and folds of heights 17, 15, 13, 11, 9 and 7. Distinct upper five-bit prefixes for all 32 queries attain the maximum. The model matches both actual proof encodings. It gives **246,120 bytes** for the largest honest compressed proof and **232,113.59 bytes** under ideal independent uniform query selection. Signed-frame and archive accounting add the actual node envelope, receipts and signatures. [Executable size model](size.py)
