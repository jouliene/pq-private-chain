# Decision on the complete 2x2 payment proof

Preserve CP03 as the working protocol. Keep the compact encoding as a reproducible
optional transport candidate. **Defer ledger integration.** It saves about
0.27 MB per payment and passes independent public verification. Its remaining
size and extra cold verifier work give insufficient reason to change consensus
identifiers, fee rules, archive formats or the payment backend.

## Three new private payments

Each row is a fresh funded payment with two inputs, two outputs and independent
wallet keys, proofs and receipts. Each compact file carries both encrypted
receipts, the full statement and the candidate proof. The 4,876 bytes outside
the proof include a 20-byte header, the 528-byte statement and 4,328 bytes of
receipts. An optionally named instance passed to the verifier repeats 528 public
bytes. We charged that input separately on every measured verification.

| Payment | Reference body B | Compact body B | Compact proof B | Saved B |
|---|---:|---:|---:|---:|
| 1 | 1,754,838 | 1,484,274 | 1,479,398 | 270,564 |
| 2 | 1,758,614 | 1,494,506 | 1,489,630 | 264,108 |
| 3 | 1,750,806 | 1,486,258 | 1,481,382 | 264,548 |

The ratio of matched totals gives a **15.182% reduction**. Mean full body size
was 1,488,346 bytes. At 100 million included ordinary payments with this sample
mean, one copy of the bodies would occupy 148.835 decimal TB/year. The earlier,
larger CP03 sample projects 175.127 TB/year. The three matched pairs themselves
imply 26.641 TB/year of savings at that volume. This is an arithmetic projection.
Whether participants will bear those costs remains open.

The tenfold screening target was 175,126 bytes per complete body. On the two
historical genuine 2x2 examples the mandatory distinct main trace values alone
occupy at least 742,848 bytes under this encoding. A new constraint/commitment
construction would have to change which trace information is opened to reach
the target. [Byte accounting and bounds](construction/compaction_floor.json).

## What the verifier reconstructs

From the public, fixed AIR and deterministic preprocessing seed, the verifier
constructs the exact fixed openings the reference verifier expects. Where the
original transcript requests the same coordinate repeatedly, the encoding
retains its first response. Authenticated row, salt and sibling coordinates
follow their respective tree geometry. Every remaining frontier digest is sent.
The prover compares each elided byte, and expansion reproduces the exact
reference body. The candidate then runs the registry-selected cryptographic
verifier. It also checks the fee, ordinary-only grammar, receipt digests and
externally selected statement. [Encoding](candidate/README.md) and
[security obligations](SECURITY.md).

Direct hiding WHIR/sumcheck did not pass the current source and parameter
screen. The retained PCS discloses its requested evaluations. A direct opening
of the CP03 key columns at a multilinear point gives witness-dependent
information. Masking the outer sumcheck and all terminal claims is a separate
construction. One upstream implementation has explicit terminal masks, but
its stock field, digest and parameter schedule cannot support a claim of
preserving CP03's research profile. A transparent recursive wrapper would need
a pinned complete inner verifier, a sound composition and an affordable outer
prover. One authenticated tree alone in the reference sample requires at least
13,881 Keccak permutations. Neither alternative has a measured complete
payment here. The [source screen](construction/SOURCE_GATE.md) links the primary
implementations, precise revisions and runnable calculations.

## Resources and external data

On the primary run the actual CP03 proof worker used 1.83–1.87 CPU seconds
and peaked at 168,176–168,180 KiB. Its registry preparation took 0.59–0.61 s
wall. Packing, including producer-side full verification and a roundtrip,
cost a further 0.82–0.85 CPU seconds and peaked at 88,080–88,084 KiB. The two
workers execute sequentially. Combined proving/encoding used 2.67–2.71 CPU
seconds and 2.72–3.57 s elapsed. Preparation of funded wallet inputs and
supporting credit/restore proofs are outside these ordinary-proof costs. Each
wallet cycle's enclosing process receipt is preserved in fresh-cycles.json.

Cold public checking of a named compact payment took 0.82–0.86 CPU seconds,
86,412–86,420 KiB peak RSS, and 0.84–1.76 s elapsed. The reference
statement/proof CLI took 0.65–0.67 CPU seconds and 63,236–63,360 KiB.
That reference CLI consumes only the full public proof and statement; the
candidate additionally parses the body and checks receipt digests. In the
candidate, reconstructing the fixed public table took 0.165–0.349 s wall,
preparing and checking the complete registry took 0.600–1.260 s wall, and
the final complete reference verifier call took 0.054–0.102 s wall. These
stages are inside the reported total. Fresh-process startup and shared-host
scheduling affect elapsed time. The measurements assume no persistent verifier
cache, per-block batching or per-payment amortization.

The 512 × 114 canonical base-field preprocessing table is 466,944 bytes
before expansion. It is deterministically generated locally, committed using
the original PCS, and checked against the verifier's own registry. No external
table, VK file, online data service, dictionary or original uncompressed
proof was supplied. The primary verifier executable was 6,200,752 bytes and
its four runtime ELF library files totalled 7,858,464 bytes. Exact hashes, OS
requirements, pinned source, Rust toolchain and build process are recorded.
Ledger admission separately needs the selected chain, authenticated root/count,
spentness and current state. The producer needs its private notes, keys,
membership witnesses and randomness. CPU/RSS are finite measurements on the
supported Linux installation. [Raw per-worker and preprocessing results](evidence/three-payments.json).

An initial measurement charged only the bubblewrap launcher. The corrected
harness runs GNU time inside the namespace, directly waiting on the verifier.
Elapsed time includes the outer namespace startup. The original launcher
readings are identified in [fresh-cycles.json](evidence/fresh-cycles.json).
The remeasurement used the same bodies; all byte counts remained identical.

## Independent reproduction

The non-implementing reviewer built CP03 from a clean public checkout of
`8f9bae9b96248e6c147acf9664fd34bb727cb756`, with the original research
and development trees and dependency caches hidden. The reviewer generated
three additional payments using fresh wallet keys and linked the candidate
at executable revision `9dce9420fa4fa96a01b63c70fdbea8e6dde08012`.
The complete payments measured 1,475,378 / 1,478,474 / 1,477,338 bytes,
against 1,746,582 / 1,749,398 / 1,754,198 reference bytes. The aggregate
reduction for this sample is 15.599%. The three cold named-instance checks
used 0.79–0.85 CPU seconds and 86,404 KiB each. All six primary and
independent statement and candidate hashes are distinct. The reviewer also
repeated the witness and public controls, including three whole-payment
substitutions against mismatched verifier-selected statements.
[Independent run index](review/CLEAN_INDEX.json) and
[raw independent measurements](review/CLEAN_COMPARISON.json).

## Positive and negative evidence

The three real payments were generated and admitted by the reference wallet
and ledger before compact encoding. The named-instance verifier ran in a new
process using only its body, the expected public statement, executable, native
runtime and resource meter. It reconstructed the reference bytes and accepted
all three. Swapping two valid statements between two valid payments rejected
both times. The standalone checker verifies ordinary payment contents and
proofs. The implementation decision leaves dynamic ledger checks in CP03.

The actual complete prover accepted a separate positive arithmetic control
and rejected seven canonically encoded invalid witnesses. Flipping an owner
key or the second input's depth-40 sibling, or giving a disallowed index,
failed. Recomputing public commitments after adding one unit to an output
isolated integer conservation as the only failed relation. A changed nullifier,
changed output opening and out-of-range amount also failed. A well-encoded
altered main-row field in the compact proof reached actual cryptographic
rejection. Five canonically reframed statement mutations reached the original
cryptographic verifier *after expansion*, covering fee, output commitment,
root, nullifier and receipt. Ciphertext, fee, length and encoding controls
failed at their respective earlier stages. [Witness controls](evidence/witness-controls.json),
[proof and statement controls](evidence/semantic-controls.json) and
[whole-payment substitution](evidence/expected-statement.json).

Raw [public bodies and expected statements](evidence/three-payments/), the
[build receipt](evidence/build.json) and [reproduction commands](README.md)
are sufficient for a new build and independent public verification. Individual
full-body savings do not establish a more efficient underlying argument,
stronger PQ security, affordable validator participation or production readiness.

## Next research decision

A further tenfold attempt must address the main trace openings directly.
For hiding WHIR, the next discriminating step is to implement and review the
masked outer reduction and linear-form verifier for the pinned R1CS construction,
derive actual randomized code dimensions and security parameters for the complete
2x2 relation, and budget the resulting proof before private integration. That
constructive question remains open. Cold-verifier optimization of this encoding
would affect CPU but cannot remove its measured main-row floor.
