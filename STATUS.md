# Network feasibility: local acceptance passed; delivery incomplete

Canonical project: `/home/neo/jouliene/pq-private-chain`.
Native/global Goal read back ACTIVE on 2026-11-17 at14:26UTC.
Execute NETWORK_FEASIBILITY_GOAL.md. No owner budget/resource limit was imposed.
Criteria1..5 have reviewed evidence. Criterion6 still needs successful automatic
full smoke and release readback. No milestone/global completion is claimed.

## Current ownership and allocation

Latest published checkpoint before this change:29e7e0e63c084314b06e49ee25e8d0044941fe00.
Baseline:d8f800037b5efbb76a5a1d6d4d3100e55f676a00.
Independent clean private/public execution:a9357c27d7458277b80b78ac887696a9ea9a99a8.
Later changes concern CI wrappers/workflow, documentation and safe evidence;
payment/wallet/inner isolation/proof parameters are unchanged.
Root owns integration, acceptance, workflow, status and all Git operations.
arch_private_repro owns ci_noble.sh; arch_proof_alternatives owns independent
CI_ORDER_REPAIR_REVIEW01.md; arch_consensus_roles produced the public UID control.
All previous heavy/local jobs are terminal. Allocation39 completed: actual hosted
pilot44103979712 PASS at29e7e0e, ordinary host/guestUID1001, exact libcrypto3.0.13,
Python3.12.3, unchanged nested true and Node. Raw evidence:ci-noble-hosted03.
Allocation40: ONE fresh automatic full smoke under reviewed workflow14a01f3d...:
Ubuntu22 host, pinned Noble userland, same inner source/discovery/build/runtime,
five newly proved isolated payments/recovery, then public/legacy private checks.
One heavy job;20min limit. No large264/864 rerun or proof parameter change.

## Accepted execution and architecture

- Gate1:96 genuinely distinct ordinary payments, separate producer/archive/
  validator transport, complete durable retention, invalid-final-payment atomicity,
  interrupted transfer and archive crash/lost-ACK controls passed review.
- Gate2:8x96 ordinary payments. All768 accepted by287.618316s within363.294720s,
  despite90.824782s validator downtime. All queues/credits drained;14 canonical
  tables agree except local catalog identity.864 proofs/96 source signatures,
  1728 leaves/1536 nullifiers,fees1825416864,total9.6B,liabilities0.
  1513556768 full-body bytes retained; no pending/missing/unexported obligation.
- Gate3 full01:264 new proofs,265 positive admissions,264 successful blocks,
  four rollbacks,two atomic Anchor rejections. Local receipt/witness spending,
  changing-root expiry and refresh, selected-branch rewind/replacement, deep
  replay, original-process exit then backup-only new-process spending passed.
  Finalheight260,522leaves,516nullifiers,fees551305634,total1.1B,liabilities0.
  457020724 full-body bytes retained; no pending obligation. Raw safe receipts:
  `experiments/network-feasibility/wallet-integration/evidence/wallet-full01/`.
- Independent acceptance: clean masked checkout build, four new ELFs and8provider
  controls; NEW isolated five-proof cycle with backup-only spend; fresh public
  replay of all264 full01 proofs and exact canonical14state. Independent replay
  did NOT regenerate the full private264 campaign or rerun unchanged Gate2.
  Safe evidence: `experiments/network-feasibility/evidence/gate5-clean/`;
  scope and actual reviews: review/GATE5_REPRO_SCOPE.md,
  GATE5_SMALL02_ACTUAL01.json, GATE5_PUBLIC01_ACTUAL01.json,
  GATE3_FULL01_ACTUAL01.json and PIPELINE_FULL03_ACTUAL01.json.

CP03 is provisionally retained for a finite research participation model:
full-RETAIN validators plus a separately provisioned opaque serving archive.
Mean ordinary body1751265.75B projects175.126575decimalTB/year per full copy at
100M offered payments/year. The owner set NO annual traffic cap and has NOT
adopted an annual cost model. No year-long capacity/economical-node claim.
Current wallet rereads common prefixes: full01 made265reads/187364746B; the last
restore input alone was1374318B. Single-pass scan projections are not actual
annual traffic of this implementation. Complete role/resource scopes are in
`docs/network-feasibility/RESOURCE_DECISION.md`; formal/privacy limitations are
in OBLIGATIONS.md and docs/SECURITY.md. No whole-protocol PQ/privacy theorem,
network anonymity, permissionless issuance, full consensus or production claim.

## Preserved CI findings

| Run/control | Actual outcome and implication |
|---|---|
|44088764296/c5e2f36|Build/legacy checks passed; isolated prelaunch failed. Public control reproduced source-tree DB rejection after legacy smoke. Reviewed reordering preserved isolation.|
|44090899086/246ab53|Build passed; isolated child exited1 before any private stage. Different startup failure.|
|44092592703/ef9262a|Ubuntu24 unchanged public true failed loopback RTM_NEWADDR EPERM. No build/private proof. Exact AppArmor causation unproved.|
|44094941105/6542294|Same unchanged public true+Node passed on ordinary Ubuntu22. This refuted the earlier external-only conclusion.|
|Local rootless Noble, allocation35|Default apt exited100 due single-UID setgroups/seteuid; preserved image/attempt. No authentication or apt sandbox bypass.|
|44100085183/afe1619|Admin image apt could not create tempfiles for authentication. Not evidence repositories unsigned. Verified archive mode01777 versus incorrect extracted0775 motivated exact tar-mode repair.|
|GNU tar permission control|Old flag0775 rejected; preserved modes01777 passed. No privileged operation.|
|44101616123/3d4e31b|Signed package provisioning PASS, host caller1001, Python3.12.3 and actual libcrypto3.0.13. Nested public true failed uid-map EPERM with outer UID0. No build/private work.|
|NESTED_UID_CONTROL01|Local identical inner true/Node: outerUID0 fails same uid-map error; actual nonzero1000 passes. Both capabilities zero;0.629859s. Not uniquely proved hosted kernel causation.|

Safe failed evidence is under experiments/network-feasibility/evidence/ci-*;
UID control/review are under review/. No historical failure is relabelled PASS.
Only the fixed fresh-image signed package provisioning uses normal administrative
access on disposable hosted CI, before secrets exist. Chroot is not a privilege
sandbox. No privileged host mounts, host security change, apt authentication
bypass, loader injection, root wallet or extra capabilities are used.
The exact reviewed wrapper7b332a5c875b861faa9606530a62463fb588d741f89f778a7c908fc9ff2fc2b9
changes only outer UID/GID0 to the caller's actual nonzero UID/GID. Original host
nonroot guard and all inner sandbox/provider checks remain.

## Exact next actions

1. Commit reviewed full workflow and actual environment receipt; ordinary push
   triggers the automatic smoke. Observe its exact revision and terminal result.
   A successful environment pilot alone is not full payment CI acceptance.
2. Read the fixed public results and obtain independent final source/evidence
   review. Discovery/approval/build/verifiers all use the same Noble view.
3. If actual full CI passes, preserve fixed public records, independently review,
   reconcile delivery identity, publish network-feasibility-2026-11-17 and verify
   exact revision/run/assets. Prepared full01-public-closure.tar is462551040B,
   SHA29541085933138adb13e11fb1f91b247b03f8c20e10d68c978d6d7034ecfccc4.
   It contains only genesis/264 public complete bodies/manifest, no DB or secrets.
4. Do not repeat closed264/864 campaigns. A new failure needs a named discriminating
   question before another run. No final delivery-result.json exists until success.

The optional owner server has two disks and more than2TB available on the second.
Its inspected runtime does not yet match BUILD.md; no remote install/heavy campaign
has run. Storage is an optional experiment resource, not an annual protocol budget.
See review/REMOTE_REPRO_REQUIREMENTS.md for nonsensitive actual observations.

Next investment after this bounded milestone: authenticated common-history suffix
sync from wallet-owned joint cursors, preserving ownership-independent fetches and
atomic rewind checks. It does not solve the175TB/year first-copy payment obligation.
Full PoW/permissionless issuance follows the explicit payment/storage participation
decision. Formal PQ/privacy assurance and production readiness remain separate.
