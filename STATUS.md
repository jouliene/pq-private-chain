# Network feasibility: local acceptance passed; delivery incomplete

Canonical project: `/home/neo/jouliene/pq-private-chain`.
Native and global Goal read back ACTIVE on 2026-11-17 at13:29UTC.
Execute NETWORK_FEASIBILITY_GOAL.md. No budget/resource limit was imposed.
Criteria1..5 have reviewed evidence. Criterion6 remains incomplete. The original
hosted runner failed namespace startup; the alternate Ubuntu22 public probe
passed. Exact Noble userland provisioning and full automatic CI remain pending.
Do not call this milestone or the global blockchain complete.

## Exact current revision and jobs

Public implementation/diagnostic revision:
`ef9262a3277e9d4f1aa412237630038ad78bdca7` (ordinary push and GitHub main readback).
Public baseline: `d8f800037b5efbb76a5a1d6d4d3100e55f676a00`.
Reviewed clean private/public execution revision: `a9357c27d7458277b80b78ac887696a9ea9a99a8`.
Subsequent changes are workflow diagnostics, documentation and safe evidence;
the accepted payment, wallet, isolation policy and proof parameters are unchanged.
All local/heavy jobs and specialist tasks are terminal. Root owns acceptance,
Git and restart. No unallocated experiment is running. Do not restart closed jobs.
The later documentation-only checkpoint preserves this failure; its skipped CI
is not a PASS or a replacement for the actual failed ef9262a run.

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

## Actual CI failures and independent disposition

1. CI44088764296 on c5e2f36 failed before Popen. Prior legacy private smoke passed
   and retained ledger.sqlite inside installed source_root, which the isolated
   wallet deliberately rejects. A public tree discriminator proved the ordering
   incompatibility; the sanitized historical first exception remains unknown.
   Reviewed fix246ab53 moves the unchanged isolated test before legacy smoke.
2. CI44090899086 on246ab53 passed build and got beyond that pre-Popen obstruction.
   The isolated wrapper exited1 after0.065790911s with no actor stage/events/proofs.
   No private stderr was persisted. This is a distinct startup failure.
3. CI44092592703 on ef9262a executed the reviewed PUBLIC-ONLY preflight before build.
   The unchanged sandbox around `/usr/bin/true` failed in0.004740970s, exit1:
   `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`.
   Node, build, wallet and proofs did not run. Source pins remained unchanged.
   Local same-source true/officialNode probes passed. Hosted AppArmor userns
   restriction reads1 versus local0; no kernel audit proves unique causation.

Actual failed run: https://github.com/jouliene/pq-private-chain/actions/runs/44092592703
Exact public receipt9ce0c4cfaab5f97b249b4a7a8aeca297cf91f05049c4fecadc8a0e44c5ece6bf.
Safe receipts/run metadata are committed in evidence/ci-failed01,ci-failed02 and
ci-hosted-preflight01 under experiments/network-feasibility. Independent source,
control and final hosted disposition: review/CI_ORDER_REPAIR_REVIEW01.md.
No isolation prohibition, host security setting or cryptographic parameter was
relaxed. No identical retry is justified; the remaining prerequisite is external
runner capability, not a payment-construction impossibility.

## Exact restart and remaining delivery

Required prerequisite: an approved CI execution environment already supporting
Linux x86-64 unprivileged user/PID/mount/network namespaces, isolated loopback
setup, seccomp, own-child procfs observation and the exact BUILD.md runtime.
Provisioning/changing host security policy or registering a new CI service was
not performed or silently authorized as a workaround. The optional owner server
is not yet a compatible CI installation; its storage alone does not establish one.

1. Inspect this checkpoint, actual HEAD/status/agents/jobs and the preserved failed
   records. Reuse completed proof/network evidence; do not repeat large campaigns.
2. On the properly provisioned supported runner, checkout the current reviewed
   source, provision official checksum-pinned Node as in BUILD.md, then execute:

```sh
mkdir -p .work
python3 -I experiments/network-feasibility/wallet-integration/ci_preflight.py \
  --node "$PWD/.tools/node-v24.22.1-linux-x64/bin/node" \
  --output "$PWD/.work/resume-isolation-preflight01.json"
```

   The output label must be new. Both public probes must actually pass; true-only
   success is not Node or wallet acceptance. No security-policy disabling or
   skip-on-failure. A new denial requires its own evidence, not more proving.
3. After the actual prerequisite passes, review the supported runner selection and
   execute the unchanged full automatic smoke: fresh build/runtime approval,
   isolated five-proof wallet/backup spend FIRST, then public/private/witness checks.
   Read back actual head SHA, run URL/conclusion and fixed public artifact receipts.
4. Only after successful CI publish `network-feasibility-2026-11-17` with the
   prepared archive and actual delivery-result.json; verify tag/SHA/asset digest.
   No release or successful delivery record currently exists. Update GOAL/STATUS,
   hand off immutable commit/compare/commands, keep the global Goal ACTIVE.

Prepared archive `.work/network-delivery01/full01-public-closure.tar`:
462551040B, SHA29541085933138adb13e11fb1f91b247b03f8c20e10d68c978d6d7034ecfccc4.
It contains only manifest/genesis/264publicbodies, no DB/inventory/privatebackup.
Closure SHA6ee13309b7c0d5fafb6363787076a86be0334799c850e670147571903cbae094.
Reproduction commands are in wallet-integration/README.md; all packaging/replay
copies are charged separately in evidence/GATE5_PUBLIC_STORAGE01.json.

After completing this milestone, the recommended next bounded implementation is
common authenticated-history suffix continuation, one reviewed outcome then stop.
It cannot fix the initial175TB/year full-copy cost; global payment/storage design
remains ahead of full PoW/issuance. Standalone valid-work PoW remains preferred.
No next-stage implementation is allocated here.

Optional server: second disk `/mnt/data` measured2739028307968B free (~2.74TB).
Key-authenticated read-only/basic namespace inspection passed; no password read,
sudo, installation or remote heavy job. See review/REMOTE_REPRO_REQUIREMENTS.md.
This is available experiment space, not an owner annual budget. Canonical root
remains this repository. Prior detailed allocation journals remain in Git history.

## Allocation34: supported alternate-host discriminator

Previous goal turn is PROGRESS: it corrected a real test-order defect and produced
an exact hosted startup-denial receipt. On continuation, readback confirms the
blocker unchanged, but ordinary supported runner selection is an independent
authorized route; treating all further work as external-only was premature.
The reviewer explicitly reassessed that conclusion.

One manual public-only Ubuntu22.04 preflight is allocated: unchanged namespace/
seccomp/probe and official Node SHA; no build, private actor, hostpolicy change or
new CI service. Root owns workflow/Git/execution. Independent review is in the
existing CI_ORDER_REPAIR_REVIEW01.md. Ubuntu22 remains a listed GitHub runner
(its deprecation is noted in the official runner-images documentation).
A pass proves only startup. Existing installation requires /usr/bin/openssl and
clean runtime linkage to exact3.0.13; project-local LD_LIBRARY_PATH is not an
accepted adaptation and is explicitly prohibited in private children. Source
analysis found that merely changing --libcrypto cannot make the full build work.
If host startup passes, evaluate a bounded exact Noble userland environment or a
coherent reviewed installation adaptation before any full build. No accepted
proof/wallet/runtime check is weakened, and no full264 campaign is repeated.

Allocation34 actual terminalPASS: manual public probeCI44094941105 on6542294.
Ubuntu22 kernel6.8.0-1070-azure, unchangedtrue/officialNode both exit0 in
0.007580535s/0.014726646s, exactstdout/no stderr, source pins stable. Root and
independent reviewer read actualreceipt3bcbc6bf593fa40bb93f57060defff1f2c25f57fd31b61a2be86c650b635353d.
Safe fullreceipt/CI metadata are in evidence/ci-ubuntu22-preflight01. This resolves
the claim that an external newservice is necessarily required; it does not pass
fullCI or the exactNoble runtime gate.

Allocation35: one projectlocal officialNoble24.04.5 rootfs provisioning and nested
publicpreflight, beforeanynativebuild. Root owns execution/workflow/Git;
arch_private_repro owns scripts/ci_noble.sh only; arch_proof_alternatives reviews.
Rootfs checksum from officialUbuntu metadata:
e77b6f10c2590cef872b33ee9f635a0e3fd1f57fb074c0e52b5c7f56147a0c86.
No hostpolicychange, newservice, loaderinjection or acceptedcorechange. Trydefault
apt behavior; stoponrequiredprivilege/workaround. Sameguest/userlandmustcontain
allruntime discovery/build/private/publicverification; no oldapproval reuse.
Firstgate: guestOpenSSL3.0.13/Python/Nodeidentity and unchangednestedpublicpreflight.
No264regeneration; fullfreshsmallCI onlyafterreviewedactualenvironmentgate.

Allocation35 terminalFAIL: rootlessdefaultapt exits100 in5.831600s because it
cannot setgroups65534/seteuid42 in a singleUID namespace. NoREADY, nativebuild or
privateproof. Frozenwrapperbc47bc40 and exactpubliclogs/receipt are preserved in
evidence/ci-noble-rootless01; rootfs/archive remain87MiB/29MiB, no cleanup/reuse.
Do not retrythatmode or disableAPTsignature/_apt checks.

New bounded decision: the rootless-only provisioning premise was researcher-set,
not an owner/private-wallet requirement. GitHub explicitly provides passwordless
sudo for software installation. Independent review conditionally permits normal
signed/defaultapt in a fresh projectlocal chroot on the disposableUbuntu22 VM,
BEFORE anysecret exists, followed by originalnon-root hostUID execution of ALL
discovery/build/wallet checks viaunchangedbwrap. Chroot is not a privilege sandbox;
trusted signed maintainer scripts execute administratively, like existinghostapt.
No hostproc/sys/run/socket or repository/toolchain bind insideprivilegedchroot,
no hostpolicychange, no privilegedwallet, no APT sandboxoverride/DPKGforce.
Concretewrapperdiff requires independentreview, then ONEpublichostedpreparepilot
before fullCI. Newruntimeapproval/providercontrols remainmandatory.

Allocation36 sourceGO: scripts/ci_noble.shd4099b43d9d2e612c54d344e8acb703992aeed85854b1651365a984cc3e8c82e
and manualworkflow23a4460aed2772b97ea60539c0c94cfdc0652392a176612a3096d1bdfb22bbce.
ONEfreshhostedprepare-only run,360s+10skill and8minjob. HostEUIDnonzero bothmodes;
onlyfixedfreshimage sudo-n/env-i/mknod/chroot signeddefaultapt provisioning is
administrative. No privilegedmounts/hostservices/hostpolicychange. Actualcaller
UID, packageinventory, exactOpenSSL/Pythonidentity and unchangednestedpublic
preflight gateREADY. Allfuturebuild/privatechecksremainunprivileged onhost via
readonlyguestuserland. No fullbuild/proof allocated untilactualPASS andreview.
