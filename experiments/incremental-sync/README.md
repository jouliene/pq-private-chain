# Authenticated incremental wallet synchronization

This bounded milestone implements `INCREMENTAL_WALLET_SYNC_GOAL.md`. The native
Goal and global blockchain objective remain ACTIVE. Source review and component
checks are intermediate evidence; this file does not declare acceptance.

The wallet owns its joint cursor, receiving inventory lease, spentness and local
witness state. `localWitnessSyncRequest` emits a common public range from that
state; `synchronizeLocalWitnesses` authenticates the exact selected endpoint and
EOF before publishing the staged joint result. `scan-range` fetches the range
directly from indexed ledger rows. The wire contract is `CONTRACT.md`.

Hash linkage is not payment verification, consensus, freshness or data
availability. Payment validity remains explicitly delegated to the independently
selected validating source. Full proof parameters, source authorization, fees,
nullifiers and admission are unchanged. See the existing security obligations.

## Fresh installation and focused genuine run

Build a new installation from this checkout using `BUILD.md`. Do not reuse an
installation whose source was changed or whose source mount contains databases.
The selected runtime must pass the existing exact version, source, native-library
and process isolation gates. Labels are create-only and failed evidence is kept.
For installation `sync01`, review its actual approval digest, then run:

```sh
.tools/node-v24.22.1-linux-x64/bin/node tests/sync-wallet-parser.mjs
python3 -I tests/run_sync_serving.py \
  --installation .work/sync01/fresh/installation.json \
  --approve-installation ACTUAL_INSTALLATION_SHA256
mkdir -p .work/sync01/source/experiments/compact-all-payments-v3/public
mkdir -p .work/sync01/source/experiments/compact-all-payments-v3/evidence
sha256sum experiments/network-feasibility/wallet-integration/SOURCE.json
python3 -I experiments/network-feasibility/wallet-integration/run.py \
  --label sync-private01 --profile incremental \
  --installation .work/sync01/fresh/installation.json \
  --approve-installation ACTUAL_INSTALLATION_SHA256 \
  --approve-source REVIEWED_WALLET_SOURCE_SHA256
```

The new `PROFILE.json` declares a nine-proof genuine scenario. It reuses the
existing isolated controller/actor, not the closed264-proof full campaign.
There are255 legally admitted empty blocks after a genuinely changing recipient
spend. The old block2 anchor expires while the distinct block3 root remains;
positive admission before expiry, exact Anchor rejection and refreshed proving
are all required. The restored process performs one charged cold full scan and
must create and admit a new proof using only its RAM-transferred backup plus
public inventory/context/history. No old private process survives restoration.

A distinct RAM-restored reference wallet is forced to reconstruct from genesis
at each comparison. Its complete cursor/accounting, discovered/unspent notes,
owned40-sibling paths, accepted anchors and retained semantic journal must match.
Private values and their hashes are never exported. That oracle and adversarial
fixture work are outside measured synchronization roles. They increase whole
experiment process resources, which are reported separately. The rolling wallet
first authenticates genesis0; a malformed258-block suffix tests rejection after
at least one256-block candidate window has been privately applied.

## Evidence scopes

Parser controls use genuine public historical frames but do not verify payment
proofs. The six Rust serving controls use structural empty histories and do not
claim private payment correctness. The nine-proof profile requires actual new
complete proofs and native admission, not stored flags or diagnostic hashes.
Long-trace measurement reuses the release's public genuine payment closure;
fixture verification/preparation is outside measured serving/wallet roles.
It uses a new wallet with no owned historical notes, so owned-note claims come
only from the genuine fresh private scenario.

Ordinary unchanged-head sync returns its existing private view without a history
request or authentication. Branch selection immediately revokes old views and
prepared private packets; failed replacement leaves the old committed image
private and revoked. Shallow replay uses only an exact retained authenticated
joint checkpoint. Deep replay and cold recovery remain explicitly charged scans.
The single serving read snapshot can block a concurrent DELETE-journal writer;
it is not a distributed serving or concurrency guarantee.

Approximately1.75MB per complete payment and175TB/year per first body copy at
100M offered payments remain unresolved. This change does not implement remote
pruning, bootstrap availability, mnemonic/unknown-key recovery, full PoW or
formal joint PQ/privacy security. Final results, tested/published revisions,
independent reproduction and CI must be recorded before bounded completion.
