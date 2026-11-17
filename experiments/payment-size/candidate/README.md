# Reversible CP03 ordinary 2x2 transport

This experiment measures a complete ordinary body that expands to the existing
CP03 verifier input. It preserves the genuine randomized prover, the original
program, proof parameters, salts, masks, all requested query positions, and
the existing full cryptographic verifier.

## Build and exercise

Follow [BUILD.md](../../../BUILD.md) for a clean CP03 installation. Run from
the repository root with its locally approved installation SHA256.

    python3 -I -B experiments/payment-size/candidate/build.py \
      --installation .work/INSTALL_LABEL/fresh/installation.json \
      --approve-installation APPROVED_INSTALLATION_SHA256 \
      --output .work/compact-example01

    bin=.work/compact-example01/cp03-public-fixed-transport
    "$bin" pack fixtures/cp03-reference/payer2x2.body .work/compact-example01/payer.body
    "$bin" verify .work/compact-example01/payer.body
    dd if=fixtures/cp03-reference/payer2x2.body of=.work/compact-example01/expected.bin bs=1 skip=20 count=528 status=none
    "$bin" verify-against .work/compact-example01/payer.body .work/compact-example01/expected.bin
    "$bin" expand .work/compact-example01/payer.body .work/compact-example01/restored.body
    cmp fixtures/cp03-reference/payer2x2.body .work/compact-example01/restored.body
    "$bin" controls fixtures/cp03-reference/payer2x2.body

The driver uses the exact Rust tool from the approved CP03 installation and
links the release artifacts identified by its actual Cargo build receipt. It
rechecks the installation and pre/post inputs, retains hashes of those compiled
libraries and candidate sources, and requires a new output directory. The
linked libraries come from that local trusted build. The hashes recorded by
the candidate builder add local evidence to the original installation's
approval. Running the result requires the compact public body, the binary and
its native linker closure. Fresh-wallet production and isolated measurements
are documented in the parent experiment.

Use verify-against when the verifier already owns the expected statement.
Supply the exact 528 canonical statement bytes from that trusted context.
The command compares the canonical embedded statement byte for byte before
receipt hashing, public preparation or proof verification. An unreadable,
wrong-size or different expected statement fails with ExpectedStatement.
A match runs the same receipt and complete CP03 proof checks as verify,
which otherwise checks the statement carried by the body. The example
uses the released fixture as the trusted source for the expected bytes.

## Body and proof grammar

The body keeps the CP03 ordinary 2x2 prefix at 4,876 bytes. It carries the
528-byte canonical statement and both 2,164-byte receiving envelopes. The body
magic is CPBODC01, and its proof length counts the compact bytes. The ordinary
minimum tariff and zero public credit/debit apply.

The 206-byte proof envelope uses magic CPFRC001 and the existing version-3
CP03 profile, program and statement-frame identities. The inner proof starts
with the same 60,364-byte transcript-bearing head and ends with the same
56-byte terminal section. The payload length names this compact grammar. The
middle sections follow the original CP03 order with these transformations.

1. Rebuild the original fixed batch at index 3 from the compiled arity-2 AIR.
   Check its 512-by-114 canonical table digest, interleave public rows with
   zero rows, run the original PCS LDE and salted Merkle commitment, and
   compare the commitment with the independently prepared CP03 registry. The
   salts use the original public setup seed. Omit all of this batch's query
   rows, salts and its existing pruned Merkle frontier. The two public fixed
   out-of-domain claims in the transcript head remain serialized.
2. Keep the first occurrence, in transcript order, of each exact authenticated
   input coordinate in the other three batches. Apply the same map to the
   vector of row values and vector of salts. They are same-height batches
   indexed by the global 14-bit query coordinate.
3. In binary FRI fold round r, deduplicate each sibling extension value by
   the query coordinate shifted right by r bits, preserving both parent
   index and queried parity. Deduplicate salts by the coordinate shifted by
   r + 1 bits, preserving the parent index. Each existing pruned Merkle
   frontier remains byte-for-byte on the wire.

Query coordinates come from the original typed STARK, PCS and FRI transcript
drivers. Frame, width, round, role and proof-of-work settings come from the
compiled CP03 program and profile. The producer verifies byte equality for
each elided duplicate and the reconstructed fixed batch. The verifier checks
the encrypted-envelope-to-statement receipt digests, restores the exact CP03
object and runs the original engine's verify_bytes. Cold verification charges
the independent public fixed-batch reconstruction plus original registry
preparation.

The expanded body recovers the existing CP03 proof and body identities.
The compact bytes have a different transport identity. Current ledger
admission, block associations, spentness, anchors and storage continue to use
their existing CP03 format and rules.

## Controls and interpretation

The controls command checks candidate rejection of a real encrypted-payload
mutation, a canonical queried main-row change, a noncanonical field, a
below-tariff fee, truncation and trailing bytes. It also expands an authentic
candidate and submits canonical, coherently reframed modifications with
unchanged opening material to the original full proof verifier. Those cases
cover fee value, the output commitment that binds ownership, membership root,
nullifier, and a paired ciphertext/receipt-digest change. They test
transcript/proof rejection and complement the separate invalid-witness checks.
Ciphertext verification is public binding. Receipt decryptability and private
receiving assurance remain separate properties.

Any accepted compact object is expanded and accepted by the original full
verifier for the exact same payment statement. Omitted data can be recovered
from verifier-owned public setup or another location in that proof. For honest
proofs the representation is deterministic public post-processing of the
original proof and carries the same CP03 cryptographic qualifications.

The retained payer fixture's main trace alone carries 736,488 bytes for
159 distinct positions, before hiding helpers, salts, paths, other sections or
body fields. This transport stays above the 175,126-byte research screen.
The measurement concerns the CP03 grammar and this sampled proof.
