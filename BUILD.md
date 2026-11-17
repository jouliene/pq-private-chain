# Build and focused checks

The checked-in source and dependency closure are sufficient. No research checkout,
source tarball, private keys, historical wallet, Cargo registry cache or old target
directory is an execution dependency. `source/` is the browsable implementation;
`vendor/` contains the exact pinned registry sources and their original notices.
`IMPORT_MAP.json` distinguishes direct research Git blobs from exact members of
committed accepted source archives. Build and runtime overlays are disposable
installation identities, not protocol or cryptographic parameter changes.

## Required infrastructure

Supported reproduction platform: Linux x86-64, Python3.11+, a C compiler, GNU
native tools, ripgrep (`rg`), curl/tar, Rust1.99.1 installed through rustup, and system OpenSSL/libcrypto
**3.0.13** with development linker files. Node must report **24.22.1**, embedded
OpenSSL**3.5.9**, linux/x64. Node's embedded OpenSSL is separate from the ledger's
native SHA3 library. The build explicitly checks tool versions and actual linked
native files. Other platforms/tool versions are unverified and fail these gates.

Provision the exact Node distribution from the official site and verify the
official checksum before selecting it:

```sh
mkdir -p .tools
curl -fSLo .tools/SHASUMS256.txt https://nodejs.org/dist/v24.22.1/SHASUMS256.txt
curl -fSLo .tools/node-v24.22.1-linux-x64.tar.xz https://nodejs.org/dist/v24.22.1/node-v24.22.1-linux-x64.tar.xz
(cd .tools && rg ' node-v24.22.1-linux-x64.tar.xz$' SHASUMS256.txt | sha256sum -c -)
tar -xf .tools/node-v24.22.1-linux-x64.tar.xz -C .tools
rustup toolchain install 1.99.1 --profile minimal
```

The independently checked official tar SHA256 is
`6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6`
(32026916bytes); the extracted Node ELF SHA256 is
`e32e2d16081cf644f88392934288086e7662529d0d43277c34f7aad2207cfafb`.
The Rust channel manifest is
https://static.rust-lang.org/dist/channel-rust-1.99.1.toml.
Equal version strings alone do not attest equal binaries: review the actual local
runtime candidate below. No credentials or machine-specific approval is shipped.

## Prepare, approve and build

Run from this checkout. Each label is immutable: use a new label for a new attempt;
retain a failed attempt instead of overwriting it. Labels below are examples for
a new clean checkout. The public source stays unchanged; installation edits are
restricted to `.work/smoke01/source/`. Temporary compiler files use the writable
`.work/smoke01/.tmp/`, so a clean sandbox does not need writable global `/tmp`.

```sh
python3 -I scripts/setup.py prepare --label smoke01
python3 -I scripts/setup.py discover --label smoke01 \
  --node "$PWD/.tools/node-v24.22.1-linux-x64/bin/node" \
  --libcrypto /usr/lib/x86_64-linux-gnu/libcrypto.so.3
sha256sum .work/smoke01/runtime-candidate.json
```

Inspect the candidate's exact file hashes, Node live mappings, native linkage and
required version tuple. Supply its actual reviewed digest explicitly:

```sh
python3 -I scripts/setup.py install --label smoke01 --approve-runtime ACTUAL_RUNTIME_CANDIDATE_SHA256
python3 -I scripts/setup.py build --label smoke01 --cargo "$HOME/.cargo/bin/cargo" --seconds 900
sha256sum .work/smoke01/fresh/installation.json
```

Installation replaces only the fixed verifier-owned Node path/native pin table.
The private-smoke helper digest is bound to the actually built helper; proof
programs, worker messages, algorithms, parameters, fixed fees and validation stay
unchanged. The uninstalled public baseline deliberately cannot serve as an
approved runtime. No transaction chooses a program, executable or provider.

Build is offline/locked/release, one job, a new target and isolated Cargo home.
Its source replacement points only to this checkout's checked-in vendor. The
root lockfile is pinned; no registry version selection/download is performed.
Actual compiler artifacts, default features, resolved depfile inputs, selected
tools, source pre/post checks and approved native linkage are retained. All four
binaries are newly built: ledger, private prover, hash helper, provider controls.
Eight real native signature controls and a fresh-process private-parent
installation probe must pass before the final installation is written.

The build prints the final installation digest. Review the actual receipts and
approve that digest for the following commands; an earlier machine's local ELF
hashes or approval cannot substitute for this installation.

## Public verification/state scenario

```sh
python3 -I scripts/replay.py \
  --installation .work/smoke01/fresh/installation.json \
  --approve-installation ACTUAL_INSTALLATION_SHA256 --attempt public01
```

This runs the retained focused scenario against the new CLI:53actual CLI calls
and four native signature positive/negative controls. Genuine public synthetic
credit/payment proofs, conflicts, source authorization, receipt/fee/debit/proof
rejections, all14-table invariance, late-block atomicity, exact history endpoint,
rollback/reinclusion and valid followups are checked. New public databases are
constructed locally. No historical database or cached verdict seeds acceptance.
The source fixtures contain public keys/messages/signatures and proofs, with no
secret signing/receiving keys or witnesses. The99historical proof-campaign controls
are not rerun by this short publication check.

## Fresh private smoke

```sh
python3 -I scripts/private_smoke.py \
  --installation .work/smoke01/fresh/installation.json \
  --approve-installation ACTUAL_INSTALLATION_SHA256 --attempt private01
```

The scenario creates fresh disposable issuer/wallet keys, proves and admits a
credit and private2x2 payment, discovers the receipt to a backed-up rotated key,
disposes original receiver handles, restores only that pre-receipt key backup in
a new process, and proves/admit a **new**1x2 spend. The private backup, note openings,
packets and exact private test oracle stay in bounded RAM pipes. Raw private
stdout/stderr are never logged or hashed. Actual child status, firstwait4,
cleanup, exact fixed result, and unchanged source/runtime pins gate success.
Finite tests do not prove memory erasure or whole-protocol security.

Recovery also needs public inventory/genesis/history, the local public Ledger's
membership API, and an independently supplied validating endpoint. The wallet's
payment-validity/consensus conclusion remains explicitly delegated. This is not
a permissionless issuance, remote private-query or consensus test.

Successful public output includes a reusable three-block workload at:

```text
.work/smoke01/source/experiments/cp03-private-cycle/evidence/private01.public/workload.json
```

Its statements/envelopes/headers/bodies are public. The manifest uses
`CP03-DISTINCT-BLOCK-WORKLOAD01` with one body per block and the six-field public
endpoint; the witness experiment accepts this short scenario without extra proofs.
See `experiments/architecture-feasibility/` for the distinct-payment role and
witness source/commands. Their full previous campaigns are not part of this smoke.

## Outputs and authority

Public operation logs/results are under `.work/smoke01/results/` and `fresh/results/`;
build/inspect/operator/private-parent receipts are under `source/fresh/` and the
private parent evidence path. A failed stage preserves its receipt and partial
public outputs. Absence of the final successful receipt is not a PASS. All these
generated files, native binaries and public databases are ignored by Git.

`fresh/installation.json` is a local operator authority, not a sender-controlled
proof/VK input. `scripts/common.py::load_installation(path, approved_sha)` verifies
its digest and complete pins. It exposes absolute repository/workspace/source/
vendor paths, tools/environment, selected Node/helper and exact operator identity.
`run_private` provides bounded RAM capture with no file sink; private callers must
accept only their exact typed fixed schema. This trusted local installation model
does not attest a hostile host or provide whole-system PQ/privacy assurance.
