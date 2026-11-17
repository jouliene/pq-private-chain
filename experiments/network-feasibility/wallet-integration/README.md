# Isolated local-witness wallet experiment

This is Gate3 of `NETWORK_FEASIBILITY_GOAL.md`. It uses the actual CP03 wallet,
ML-KEM receiving, fixed native selective frontier and unchanged complete-payment
prover, followed by genuine public ledger admission. The public controller has
no membership-path RPC. The wallet receives the same complete reduced history
and independently selected public endpoint; payment validity is delegated to
that validating endpoint. This is not distributed consensus or IP anonymity.

`GATE3_PROFILE.json` is the before-execution declaration. Its small profile creates
five proofs and exercises receipt, local witnesses, recipient spending and a
backup-only fresh-process spend. It does not test anchor expiry or reorganisation.
Only after reviewing that result may the full264-proof profile run: genuinely
changing roots, old-anchor expiry, old-note refresh, selected-branch replacement,
orphan rejection, joint rollback, deep replay and restored spending. Bounds are
research allocations, not owner annual budgets or production service targets.

## Reproduction prerequisites and commands

Use a new installation built from this checkout following `BUILD.md`; historical
research files, previous experiment databases and private fixtures are not needed.
The additional isolation prerequisite is Linux x86-64 with `/usr/bin/bwrap`,
enabled user/PID/mount/network namespaces, and procfs access to the caller's own
children. The experiment fails if required isolation is unavailable. It does not
disable it or request privileged fallback. CPU0 must be available; admission uses
CPU1 when available, otherwise CPU0, with the actual choice recorded.

Create the two empty Parent output mountpoints in that NEW installation's source
tree. For an installation label `wallet01`:

```sh
mkdir -p .work/wallet01/source/experiments/compact-all-payments-v3/public
mkdir -p .work/wallet01/source/experiments/compact-all-payments-v3/evidence
sha256sum .work/wallet01/fresh/installation.json
sha256sum experiments/network-feasibility/wallet-integration/SOURCE.json
```

Inspect and explicitly approve those identities before substituting the two
digest arguments below. Do not copy another installation's digest or alter pins.

```sh
python3 -I experiments/network-feasibility/wallet-integration/run.py \
  --label local-small01 --profile small \
  --installation .work/wallet01/fresh/installation.json \
  --approve-installation APPROVED_INSTALLATION_SHA256 \
  --approve-source REVIEWED_SOURCE_SHA256
```

Labels are exclusive. Preserve a failed label and its source identity; a changed
candidate needs a new source manifest and label. After independent small-result
review, `--profile full` uses the same command with a new label and the declared
5400-second/264-proof ceiling. One heavy campaign runs at a time. Do not repeat
closed large campaigns merely to refresh a report.

## Evidence and interpretation

The run directory is `.work/LABEL` under this experiment. `RESULT.json`, the two
process receipts, native CLI receipts and Parent records distinguish observed
failures, positive public admissions, exact accounting and resource scopes.
Every generated body, including eventually orphaned drafts, must first receive
a positive genuine native admission. Later early Anchor rejection alone does
not establish proof validity. Rejection compares all fourteen public SQL tables.

Private backups use bounded RAM/pipe frames, with no file or hash sink. Actual
termination of the original actor precedes restored-process launch. Public
inventory, genesis, history and selected endpoint remain recovery prerequisites;
a backup predating unknown random receiving-key rotations is insufficient.

Node SELF, its waited-descendant CPU, nested proof-worker metrics, native admission
and controller costs have different scopes. Never add nested worker costs twice
or report bubblewrap wait4 as whole-wallet cost. Procfs RSS is finite concurrent
sampling, not exhaustive coverage of every short-lived helper. Refresh currently
rereads common history from genesis; all read bytes/time are charged. Bounded
live witness state does not imply constant scan traffic.

See `STATUS.md` for actual outcomes and next allocation. Source review, component
tests and the historical isolation pilot are not complete Gate3 acceptance.
The formal composition qualifications in `docs/network-feasibility/OBLIGATIONS.md`
remain unchanged by a successful finite run.

## Independent public replay of the complete chronology

The full campaign is reproducible from source with fresh private keys using the
`full` profile above. To independently verify its public consequences without
regenerating264 proofs, use `public_replay.py` with a newly built installation.
The optional milestone release contains only the exact public genesis,264 full
bodies and a comparison manifest (462551040-byte tar). It contains no original
database, receiving inventory, private backup or cached-verdict authority.
Release availability and actual verification status are recorded in STATUS.md
and the release's delivery-result.json; the commands alone are not evidence of
publication or success.

```sh
mkdir -p .work/full01-input
curl --fail --location --output .work/full01-input/full01-public-closure.tar \
  https://github.com/jouliene/pq-private-chain/releases/download/network-feasibility-2026-11-17/full01-public-closure.tar
echo '29541085933138adb13e11fb1f91b247b03f8c20e10d68c978d6d7034ecfccc4  .work/full01-input/full01-public-closure.tar' | sha256sum -c -
tar -xf .work/full01-input/full01-public-closure.tar -C .work/full01-input
sha256sum experiments/network-feasibility/wallet-integration/PUBLIC_REPLAY_SOURCE.json
timeout --signal=TERM --kill-after=10s 1200s \
  python3 -I experiments/network-feasibility/wallet-integration/public_replay.py \
  --label public-full01 \
  --installation .work/wallet01/fresh/installation.json \
  --approve-installation APPROVED_INSTALLATION_SHA256 \
  --approve-source REVIEWED_PUBLIC_REPLAY_SOURCE_SHA256 \
  --public .work/full01-input/full01-public-closure/closure.json \
  --approve-public 6ee13309b7c0d5fafb6363787076a86be0334799c850e670147571903cbae094
```

Review the actual local installation and source identities before supplying the
two approval arguments. The outer1200s guard covers startup/copy/postflight as
well as the driver's900s replay guard. Each label is exclusive. All264 proofs
receive genuine native verification into a new database, including previously
orphaned bodies. The sequence checks old-anchor eligibility/expiry, four rollbacks,
replacement-branch eligibility, two atomic Anchor rejections, final selected head
and all14 canonical tables; only the local catalog identity is excluded.

Public replay cannot establish private discovery, journal restoration or backup
handling. The independent acceptance scope additionally requires a new isolated
small5 private cycle and review of the actual full private campaign's pinned
source/evidence. See `../review/GATE5_REPRO_SCOPE.md`; a material private-state
finding requires the shortest affected genuine private reproduction.
