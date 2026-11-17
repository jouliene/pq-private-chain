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
