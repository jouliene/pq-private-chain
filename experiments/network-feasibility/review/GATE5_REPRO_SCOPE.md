# Gate5 independent reproduction scope

Status: source-directed scope, not executed. Allocation25 full01 remains live.
Reviewer owns this note only. Root selects the immutable clean revision and
allocates each job; no additional heavy work is authorized by this note.

## Decision

The smallest defensible reproduction is a fresh clean build, a new isolated
small5 private wallet cycle, and fresh public-only replay of full01's complete
branch/expiry chronology. The existing12s transport2x3 diagnostic under a fresh
transport build is optional corroboration, not another mandatory network gate.
Do not regenerate264 or864 proofs merely to repeat an unchanged campaign.

This is sufficient for criterion5 **conditional on independent acceptance of
full01's actual private expiry, joint rewind/deep replay and backup receipts** at
the same wallet/helper/observer source. It is not an independently repeated full
private expiry/rewind campaign. Fresh small5 exercises the changed private local
witness/receipt/key-inventory/process boundary; public full replay independently
checks every full01 proof under the clean verifier, exact anchor expiry, branch
eligibility, rollback and conservation. Source review plus full01's actual private
evidence must connect the private state changes to those public outcomes.

Current source inspection reveals no unresolved invariant that requires all264
private proofs to be regenerated. A missing branch mark, wrong selected note,
unexplained private state transition, changed coordinator/helper, lost source
correspondence or private fallback finding invalidates this scope decision. First
reproduce the affected shortest private sequence; do not replace it with public
replay or automatically repeat unrelated funding/rolling proofs.

## Clean inputs and actual commands

Root creates a clean checkout of the final reviewed revision. Record its full
commit, clean tracked-file status and exact CORE, wallet SOURCE and transport
SOURCE/profile hashes. Do not copy targets, old installations, databases used as
the destination, runtime approvals, secret keys or backup bytes. Select the
approved official Node and required Rust/OpenSSL through BUILD.md. Hide research,
original checkout/old installations and Cargo registry/git caches during execution;
retain minimal /dev and writable new-checkout work directories. Absolute runtime
paths are reapproved through discovery, not rewritten in canonical source.

Run existing commands from the clean checkout, sequentially under allocation:

```sh
python3 -I scripts/setup.py prepare --label gate5
python3 -I scripts/setup.py discover --label gate5 --node "$G5_NODE" --libcrypto /usr/lib/x86_64-linux-gnu/libcrypto.so.3
python3 -I scripts/setup.py install --label gate5 --approve-runtime "$G5_RUNTIME_SHA"
python3 -I scripts/setup.py build --label gate5 --cargo "$G5_CARGO" --seconds 300
python3 -I experiments/network-feasibility/wallet-integration/run.py --label reviewer-small01 --installation .work/gate5/fresh/installation.json --approve-installation "$G5_INSTALL_SHA" --approve-source "$G5_WALLET_SOURCE_SHA" --profile small
```

Variables are actual independently inspected identities/paths, not supplied by a
transaction. Discovery approval and final fresh installation approval are separate
readbacks. Build must produce four fresh ELFs, default-feature/dependency closure,
provider controls and Parent installation probe. Reuse existing common.run and
first-wait4 records for outer guards. Do not run the older3proof private_smoke as
a substitute: its local Ledger membership dependency is precisely what Gate3
replaces. No additional53-call legacy campaign is required absent a new change.

Fresh small5 requires five new complete proofs and positive native admissions,
actual original exit0 before a distinct restore process, rotated-key backup made
before receipt, new restored spend, live namespace/FD/socket denial and actual
prover observations. Preserve both process receipts, Parent/public-body associations,
all14 final state hashes and separate CPU/RSS scopes. No private transcript/hash
may be used to establish independence.

## Full01 public replay: finite exact transcript

Export only an explicitly hashed allowlist from successful full01: public
genesis.bin; all264 public .body files; RESULT and two process receipts; two
Anchor rejection snapshots; relevant public Parent/proof associations; final
all14 canonical snapshot. Public receiver inventory/destination are unnecessary
for replay. The original DB may be read solely by an external oracle to generate
the reference canonical snapshot; never seed the new destination with it.

The exact full public chronology driver does **not yet exist**. A small reviewer
script may be added under a separate Root assignment, invoking only the existing
ledger CLI and transport/oracle.py. It needs no new verifier, protocol parser,
generic campaign framework or private key. These are the actual supported CLI
forms, using the approved installation's ledger_binary and proof_environment:

```text
ledger init-retain NEW_DB CHAIN GENESIS 2147483648
ledger admit NEW_DB CHAIN BODY [BODY...]
ledger rollback NEW_DB CHAIN ACTUAL_CURRENT_BLOCK_ID
ledger head NEW_DB CHAIN
ledger scan NEW_DB CHAIN NEW_SCAN_FILE
ledger check-scan CHAIN GENESIS NEW_SCAN_FILE HEIGHT BLOCK_ID NEW_CHECKED_FILE
```

Resolve the binary from the approved installation's operator record. Before/after
pin and ELF checks, fixed resource limits, typed exit/stderr validation and actual
first-wait4 receipts reuse common.run and the reviewed held-FD ledger invocation.
Load/check the whole installation at start/end, not once per264 operation.

Execute this fixed sequence, taking rollback IDs from actual newly returned heads:

1. Admit credit-0 and credit-1 together (h1), then ordinary-receipt (h2).
2. Admit old-anchor-draft (h3), rollback to h2. Admit recipient-spend (h3).
   Admit the same old-anchor-draft (h4), rollback to h3: common-prefix eligibility.
3. Admit rolling-000 through rolling-254 in order, one per block, reaching h258.
   Check changing roots and actual h2 root/count absence from current anchors.
4. Admit the unchanged old-anchor-draft: require exact Error::Anchor and unchanged
   all14 tables. It already had two positive genuine public verifications.
5. Admit refreshed-old-spend (h259), then orphan-child-draft (h260); rollback
   child to259, then refreshed parent to258. Admit replacement (h259).
6. Admit unchanged orphan-child-draft: require exact Error::Anchor and all14
   unchanged. Its proof had positive verification before orphaning.
7. Admit restored-spend (h260), export/check common history against the actual
   selected endpoint, and compare final canonical all14 state to full01.

There are264 distinct proofs and265 successful proof admissions (old draft twice),
264 successful block admissions, four rollbacks, two typed Anchor rejections and
260 final blocks. Selected state must have261 bodies/cores,522 leaves,516 NFs,
two consumed sources, total1.1B, fees551305634 and liabilities0. Canonical table
comparison excludes only independent body_cache.catalog_id; keep quotas, retained
bodies, undo, anchors and every other column. All public body bytes must be exact,
including ultimately orphaned bodies. Fresh verification is mandatory; neither
original Parent verdicts nor original DB contents authorize a new acceptance.

The replay establishes public consequences of the private full01 path. It cannot
by itself establish discovery/secret wiping/private journal restoration; those
remain explicit full01 source/actual-evidence review obligations.

## Optional short network corroboration

Transport/ledger source has not changed since its independently reviewed actual
Gate2 PASS; the new changes are wallet/helper/controller. Repeating transport is
not necessary to resolve a new acceptance invariant and must not block the minimal
Gate5 scope. Run the existing command only if Root chooses it and the finite public
closure below can be staged without a new relocation harness or source adaptation.
Otherwise omit it and state that network evidence was independently reviewed,
not independently rerun in this clean-wallet reproduction.

Reuse the genuine public2x3 diagnostic workload, not full864 generation. Existing
prepare_pipeline.py accepts exactly(2,3) or(96,8), so the new small5 wallet workload
cannot be silently substituted. Copy a hashed public evidence bundle containing
diagnostic workload/genesis/headers/bodies/proof-costs, producer public DB and
supervisor receipts. Its eight Parent JSON/.claim files and corresponding
manifest/proof/statement directories must be placed at the exact historical
relative locations under the **new** installation source_root: prepare_pipeline
requires them for copied-byte accounting. They are untrusted public provenance,
not source/runtime/verification authority. Check installation pins remain intact.
No original database/source directory needs to remain mounted.

```sh
python3 -I experiments/network-feasibility/transport/build.py --label reviewer-build01 --installation .work/gate5/fresh/installation.json --approve-installation "$G5_INSTALL_SHA" --approve-source "$G5_TRANSPORT_SOURCE_SHA" --seconds 180
python3 -I experiments/network-feasibility/transport/pipeline.py --label reviewer-diag01 --installation .work/gate5/fresh/installation.json --approve-installation "$G5_INSTALL_SHA" --approve-source "$G5_TRANSPORT_SOURCE_SHA" --build-label reviewer-build01 --approve-build "$G5_TRANSPORT_BUILD_SHA" --workload "$G5_PUBLIC_DIAG/workload.json" --approve-workload "$G5_PUBLIC_DIAG_SHA" --approve-profile "$G5_PROFILE_SHA"
```

Require the actual fixed12s endpoint, all three ACKs, bounded credits/queues,
different-unadmitted-body transfer overlap, restart/current-tip retry, fresh8proof
and2signature admissions, source/destination all14 comparison, real receiver
mount denial and complete role/byte/disk receipts. This reproduces the changed
network mechanism, not the original96 capacity measurement. Retain independent
review of full96x8 results and the costly full-RETAIN participation limitation.

## Acceptance and limits

Reviewer must execute the allocated clean jobs and inspect raw outcomes, not only
Root summaries. Failures get new labels and preserved receipts. Root retains final
integration/publication responsibility. This scope is not fulfilled by today's
note, successful old smoke, full01 alone, or a public replay plan without execution.
No annual storage affordability, remote pruning, permissionless issuance, WAN
anonymity, continuous host attestation or joint PQ theorem follows from these tests.

## CI source review while allocation25 runs

The current smoke.yml adds bubblewrap and the exact isolated small profile after
the existing public/private/witness checks. It does not change namespace policy,
sysctls or approval checks. The artifact allowlist contains eight fixed public JSON
paths (four existing, four Gate3), not databases or private streams. Actual hosted
runner CPU0/1 availability and userns/seccomp/procfs compatibility remain untested;
failure must not be converted to a skipped isolation requirement. Source review
found no blocker to executing this CI step. Recommend `if: always()` on the fixed
public artifact upload so a failed Gate3 run's safe RESULT/claim/actor receipts are
retained; retain the exact allowlist and never substitute a directory/raw-log glob.
