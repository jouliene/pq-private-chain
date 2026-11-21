# Reproduce the new private-note experiment

The N7P1 research network starts from its own funded genesis. This workflow independently verifies the three released blocks, funds new wallets, proves and admits a payment, restores its recipient from a 48-byte backup, spends the recovered funds, and admits a signed exchange between two other owners. It also reproduces the historical packet correction and the SHA3 reference's resource screen. The live MNG1 and SLG1 roles continue to govern their original funded state. [Architecture decision](DECISION.md) · [Historical verifier boundary](baseline/LIVE.md) · [Independent review](review/REVIEW.md)

## One command from the public release

Use Linux x86-64 with Bash, Git, curl, tar/xz, sha256sum, Python 3.11+, GNU time at /usr/bin/time, a C compiler, OpenSSL with libcrypto development headers, rustup, and working unprivileged bubblewrap namespaces. The author used a four-thread prover and measured a peak around 1.8 GiB for its native process. Allow additional RAM for compilation, a fresh Cargo registry and build target on disk, and outbound HTTPS to GitHub, Node.js, crates.io and the Rust distribution if the compiler is missing. The C calibration records its local OpenSSL version. [Checked Node distribution and ELF identities](../../BUILD.md)

Paste this block into a shell. It uses an empty clone directory, public HTTPS, the immutable release tag, a new registry cache and a separate output directory. The script downloads each fixture from its public release and validates its committed checksum before use.

```sh
bash <<'SH'
set -euo pipefail
review_dir=$(mktemp -d)
(
  unset GIT_DIR GIT_WORK_TREE GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_OBJECT_DIRECTORY GIT_CONFIG_COUNT
  export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=false GIT_ALLOW_PROTOCOL=https
  git -c credential.helper= clone https://github.com/jouliene/pq-private-chain.git "$review_dir/source"
  cd "$review_dir/source"
  git checkout --detach refs/tags/new-note-2026-11-21
  git merge-base --is-ancestor ceab1e4fd786e8f9ac0a99cc9a805423fe4a3b73 HEAD
  git merge-base --is-ancestor HEAD refs/remotes/origin/main
  test ! -f .git/objects/info/alternates
  git rev-parse HEAD refs/remotes/origin/main
  bash experiments/new-note/reproduce.sh "$review_dir/run" --controls
)
printf 'Public clone and reproduction evidence: %s\n' "$review_dir"
SH
```

From an already checked-out tagged source tree, run `bash experiments/new-note/reproduce.sh /path/to/new-run --controls`. The output directory must be new. Omitting `--controls` skips the additional standalone N7P1 negative-witness campaign. The fresh complete cycle and its admission controls run in both modes. The compiler and proof jobs run sequentially across experiments. Rust 1.93.0 fetches the exact crates from the candidate lockfile before building in locked, offline release mode. Node 24.22.1 is fetched from its official distribution, with separate pins on the archive and extracted executable. The N7P1 proof verifier accepts the public state and a source-built binary.

## What to check

| Output under the new run directory | Acceptance evidence |
| --- | --- |
| baseline.json | Parses both funded TCitH archives, reproduces 139,378-byte reference proof bodies and compares the historical packet boundaries against the checked-in accounting. [Wire analysis](baseline/WIRE.md) |
| sha3-price.json, sha3-calibration.txt, sha3-receipt.json | Regenerates the SHA3 relation and its price, checks native Keccak view execution and runs the ML-KEM receipt component. The large complete proof remains a priced design. Rates and CPU observations vary by host. [SHA3 reference](sha3/README.md) |
| released-replay.json | Uses the committed FOUNDING_ID, independently of genesis.json in the release archive. Compares the full state summary, all block/packet lengths and the 1/1/2 verified-leg pattern against the accepted RESULT.json. The four archive files are public genesis and blocks 1 through 3. |
| fresh/RESULT.json, fresh-replay.json | Generates different seeds, foundation, receipts, proofs and mined headers. Requires the same reconciled balances, supply, fees, spent count and negative controls as the accepted run. A separate public replay must match the newly produced funded state and packet lengths. |
| size.json, frame-risk.json, scenarios.json | Computes the compact proof bound, signed-leg tail under the stated IID-index model and the 10M/30M/100M traffic scenarios. Timings from the accepted reference enter the scenario model. Inspect the fresh verifier's own meters independently. [Size model](candidate/README.md) |
| public-rows.json | Checks all fixed public-row algebraic results on both test domains. This evaluates the static-verifier proposal's public-row term. Complete prover and verifier costs for that proposal remain open. [Alternative](candidate/alternative/README.md) |
| native-controls/ and native-proof-size.json | With `--controls`, generates another fresh proof and tests changed public inputs and inconsistent witnesses, then checks that the proof-size model predicts its exact physical geometry. |
| platform.txt, binary.sha256 | Identifies the source revision, compiler, operating system, OpenSSL, Node and freshly built proof binary for this run. |

Public state validation mounts the arithmetic role, approved Node binary, experiment code and public history in a bubblewrap process without network access or wallet seed mounts. Funded wallet processes see their individual seed and role directory. Fresh test keys and witnesses are temporary. Retain the run directory for public replay, metrics and the fetched source dependencies. Cryptographic qualification, anonymity with adaptive observers, archival-scale verification, and branch/reorganization integration remain separate from the observed cycle. [Candidate relation and assurance](candidate/README.md) · [Delivery criteria](../../docs/DELIVERY.md)
