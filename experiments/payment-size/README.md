# Smaller complete ordinary payment experiment

CP03 is the working reference. The reproducible candidate uses the same complete
2x2 payment prover with a new public proof encoding. Its verifier reconstructs
the exact reference proof and checks it using CP03 cryptography. The two
ciphertexts and complete statement are part of each measured payment.

See [construction screen](construction/SOURCE_GATE.md), [relation and assumptions](SECURITY.md)
and [wire accounting](review/CP03_REFERENCE.md). The source screen covers hiding
WHIR/sumcheck, recursive public verification, and the selected representation.

## Reproduce with three new private payments

Use a clean checkout on the platform in [BUILD.md](../../BUILD.md). Run its
prepare/discover/install/build commands with a fresh label such as `size01`.
Inspect the selected runtime and actual installation receipts. Set the two
variables below to the path and reviewed digest of that build. Each private
cycle generates new keys and funding, admits a new 2x2 private spend and
checks receipt. Its other proofs support the transaction history. Only the
ordinary payer proof from each cycle enters the size comparison.

```sh
installation=.work/size01/fresh/installation.json
approval=REVIEWED_INSTALLATION_SHA256
for sample in size01a size01b size01c; do
  python3 -I scripts/private_smoke.py --installation "$installation" \
    --approve-installation "$approval" --attempt "$sample" || exit 1
done
python3 -I -B experiments/payment-size/candidate/build.py \
  --installation "$installation" --approve-installation "$approval" \
  --output .work/size-encoder01
candidate=.work/size-encoder01/cp03-public-fixed-transport
candidate_sha=REVIEWED_CANDIDATE_BINARY_SHA256
python3 -I -B experiments/payment-size/measure.py \
  --installation "$installation" --approve-installation "$approval" \
  --candidate "$candidate" --approve-candidate "$candidate_sha" \
  --samples size01a size01b size01c --output .work/size-comparison01
python3 -I -B experiments/payment-size/witness_controls.py \
  --installation "$installation" --approve-installation "$approval" \
  --output .work/size-witness01
```

The candidate's additional `controls` command takes a full public reference body
and runs the semantic and grammar discriminators. For a retained public sample:

```sh
"$candidate" controls fixtures/cp03-reference/payer2x2.body
```

The candidate build links the approved installation's local Rust artifacts.
Use a fresh target built from the pinned source, vendor and lockfile. The
installation's original build receipt enumerates compiler outputs. The candidate
build records their current hashes and checks stability. These local measurements
require trusting the build host and its compiler, as does the CP03 reference.

The comparison verifies each file in its own new Linux mount, PID and network
namespaces using bubblewrap. Only the selected body, the verifier-selected 528-byte statement, verifier ELF and its
pinned dynamic libraries are mounted, together with GNU time for worker CPU/RSS
and private /proc and /dev. The outer process measures wall time including namespace
startup. GNU time measures CPU to 0.01 s and peak RSS of its verifier child. The expected statement is byte-identical to the one inside a valid body and is
charged separately when externally supplied. There
is no repository, wallet, sender-supplied preprocessing, proof cache, database
or previous process in that filesystem. The process reconstructs all needed
per-proof data locally. The legacy check separately receives the public full
proof and statement. Proving, packing, cold verification, preparation and
source fixture responsibilities are accounted separately in the raw result.

The witness controls generate a deterministic public arithmetic example in RAM,
run a valid proof and vary one relation component at a time. The private cycles
supply independent fresh wallet data and real receipt generation. Outputs are
create-only. Use fresh labels/directories for subsequent executions.
