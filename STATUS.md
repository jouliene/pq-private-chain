# Network feasibility: local acceptance PASS; publication pending

Canonical project: `/home/neo/jouliene/pq-private-chain`.
Native Goal read back ACTIVE2026-11-17 12:59UTC; global blockchain ACTIVE.
Execute NETWORK_FEASIBILITY_GOAL.md. Published historical baseline:
`d8f800037b5efbb76a5a1d6d4d3100e55f676a00` (GitHub readback12:43UTC).
Current tested source revision: `a9357c27d7458277b80b78ac887696a9ea9a99a8`.
Public main c5e2f36ddb6c225e7d4c17363ffe0eeba93ce49f includes these reviewed
commits. Its automatic CI44088764296 FAILED at the isolated wallet prelaunch.
Exact fixed public failure receipts are preserved; correction is limited to test
ordering. No external blocker or cryptographic parameter change.

## Accepted results

- Gate1:96 genuinely distinct ordinary payments, separate producer/archive/
  destination transport, durable retention, malformed-final-proof atomicity,
  interruption and archive crash/lost-ACK controls passed independent review.
- Gate2:8x96 ordinary offered workload passed;768 accepted by287.618316s before
 363.294720s endpoint despite90.824782s validator downtime. All queues/credits0,
  all14 canonical SQL tables equal except catalog ID.864 distinct proofs and96
  signatures checked,1728 leaves/1536 NFs, fees1825416864,total9.6B,liabilities0.
  1513556768 full-body bytes retained, pending/missing/unexported0. Closed: no rerun.
- Gate3 full01:264 distinct new proofs,265 positive admissions,264 block admissions,
 4 rollbacks and2 typed Anchor rejections with all14 tables unchanged. Actual
  receipt/local witnesses, changing-root expiry/refreshed old-note spend, joint
  shallow rewind/orphan rejection, deep replay, original exit0 then backup-only
  fresh-process new spend. Finalheight260,261bodies,522leaves,516NFs,total1.1B,
  fees551305634,liabilities0;457020724bodyB retained, pending/missing/unexported0.
  Root recomputed actual14SQL/retention; independent full review passed.
  RESULT2835c26138b20e75716b6ce048e55731b41001b38f2a2dfdf7768a2b55068637;
  reviewbdb31d729f01ecc3cf9013f28b5ccba4465aa81f42518362c2631a3882a71784.
- Independent fresh build: four new ELFs,113 new compiler artifacts,294 unique
  depfile inputs,8 provider controls and fresh Parent probe passed under masked
  original/research/cache paths. Compilation108.237161s/424728KiB; no cache fallback.
- Independent fresh small02: five NEW genuine proofs/admissions, local receipt/
  witness spend, original exit0 then new backup-only process/new spend passed.
  Root+reviewer recomputed14SQL and body/proof associations. Actual namespace
  collisions correctly classified child-local while controller namespace excluded.
  RESULT5253c2e8c998ae3aef3377dd775b1d2b12e60fb1e9c20d6c42167494d4d4225b;
  reviewfb88c43c4775061414aea738c4e17da45e79330d3b554b59958e817515e72523.
  Finalheight4/leaves10/NF4,fees10570146,total1.1B,liabilities0. No private log/hash.

## Independent reproduction complete; delivery restart

All local jobs are TERMINAL. Do not poll/restart sessions94376,37519,87239,11900,
44915 or repeat their labels. Root read the actual public result and independently
recomputed the fresh canonical14SQL map equal to the approved reference; both
Anchor before/after maps and checked-scan bytes agree. Independent reviewer confirms
criterion5 PASS under the explicitly scoped cleanbuild/newsmall5/fullpublic replay.
No second full-private264 campaign or unchanged Gate2 network rerun is claimed.

Public RESULT973cd516e921a7d71223ec4d62d037f5c9784098de7170cf6cbd56d22061074b;
independentreview3218e857b24929a8821bacbc498b41f0b98b7110d7b9c7af7e151ef92dede4b9.
Actual outer341.039873s;273 nativeCLI calls CPU324.287667s,4rollbacks,
2atomicAnchor rejections,265positiveproof admissions,264successfulblocks.
All264proofs independently checked;0newproofgeneration. Finalheight260,
522leaves/516NFs,fee551305634,total1.1B,liab0;457020724bodyB retained/no pending.
Native process peak81248KiB is not aggregate outer RSS. Public replay directory
926965760allocatedB includes462280798 copied public input bytes plus freshDB/etc.
Post-run export/replay/release copies are separately counted in
`evidence/GATE5_PUBLIC_STORAGE01.json`, not hidden in original run measurements.

Root owns final integration/Git/publication/acceptance. Specialists completed
implementation/review/reproduction. No heavy local job; no further local proof
campaign is justified. The next allocation is automatic hosted CI after the final
reviewed push. Preserve exact executable/source identities:
- Clean execution revisiona9357c27d7458277b80b78ac887696a9ea9a99a8.
- Fresh build revisionb6c6e5938c4ba67a874826f85257e43dfff2f500; later experiment-only
  changes had zero intersection with10867 approved installation inputs.
- Clone installation `.work/gate5/fresh/installation.json`:
  6c0aeae40546a2744c20e10c5cf3f23c316ef4a93e2f2144f07d71bdc4d41b77.
- Wallet SOURCE04be2910ea2ef974bb87778b0b8e605f299bdc44b9987afecddcc86df4b63eaaa8.
- PUBLIC_REPLAY_SOURCE044c767420e675de473fbbc4006338d3ce070dc496372d8b9181e63ba4ba1d90c6.
- Public closure6ee13309b7c0d5fafb6363787076a86be0334799c850e670147571903cbae094.
- CORE1b9888399a91102b84f05970ce65100d77a0a8a56519c35b13cbb8deb915a1aa.

Next: finish final documentation/evidence review, commit and push without force,
read back exact publicSHA, wait for actual automatic pushCI. Preserve any CI
failure and repair only its cause without weakening runtime/isolation requirements.
After successful CI, publish the prepared exact public archive and
`delivery-result.json` on release`network-feasibility-2026-11-17`, verify readback
and give immutable revision/compare/CI/commands to owner. That delivery record is
the authoritative completion readback beyond this pre-publication checkpoint.
Until it exists, criterion6 and this bounded milestone are NOT complete.
Global blockchain remains ACTIVE; no production or joint PQ/privacy claim.

## Preserved failures and source correspondence

Original small01/02 procfs-observer failures remain failed. Source03's bounded
20ms/16-attempt complete-policy or confirmed-exit retry did not change permissions.
Root full01 ran Source03fc065433ebe8cdfb4150dcee76056c00683633b01d70c6416837c16b6185f50e
and original gate3a installationc025a573103f652004cfe7400ef7fff3db0ef32c1458b0103fa753b477a2546b.
Do not relabel them Source04 or transplant their installation approval.

Independent reviewer-small01 failed before keys/proofs at capability-boundary.
Public allocation29 reproduced a numeric-PID false negative: externalPID3 and
innerTID3 were different namespace/start identities, all path/FD/socket checks
passed. Historical sanitized clause remains unrecovered. Source04 changes only
probe/config/live consumers, not wallet.mjs, sandbox policy, crypto, IPC or observer
retry. Independent source review and27 public metadata controls passed; an earlier
negative-control expectation failure is also retained. Source04 small02 then passed
in the original nested namespace shape. No264 regeneration or core rebuild needed.

Root's proposed BUILD.md cross-reference overlapped a pinned input; clone update
stopped before mutation. Root removed only that new seven-line addition, restoring
exact approved bytes in a9357c2. All41 final changed paths had zero installation-pin
overlap; canonical5793CORE files and both current source approvals were verified.
No approval rewrite or native rebuild was used to hide a change.

## Resources, evidence and next decision

CP03 provisionally retained for finite full-RETAIN validators plus separate opaque
archive. Ordinary mean1751265.75B implies175.126575TB/year/bodycopy at100M offered
payments/year. Owner set NO annual traffic cap and has NOT adopted annual costs.
Wallet full01 did265 history reads187364746B versus last1374318B scan. Current
refresh rereads the prefix; one-pass502.242GB/year projection is NOT annual traffic
of this implementation. BoundsK8/R8/A256, finite tiny state and sampling remain explicit.
Separate functional/resource/formal/privacy scopes and measured CPU/RSS/disk are in
`docs/network-feasibility/RESOURCE_DECISION.md` and `OBLIGATIONS.md`.

Next recommended bounded development AFTER this milestone: authenticated common
history suffixes, one reviewed implementation/result then stop; no further tuning
chain. This fixes repeated prefixes but leaves first-copy storage unchanged. Global
priority then is complete payment/storage cost or an explicitly adopted participation
model; fullPoW/issuance deferred, standalonePoW remains preferred consensus direction.
No next-stage implementation is allocated by this checkpoint.

Safe raw evidence: wallet-integration/evidence/wallet-full01/, reviewer-small01/;
independent compact receipts in evidence/gate5-clean/: FILES01 contains24files/84119B;
FILES02 adds8files/351447B and preservesFILES01 unchanged.
FILES02sha4c94ac105dde31105019685bf01a60bf45df4ee087cd7dad4608ebb4bd52e9fc.
Existing Gate1/Gate2 evidence is closed and preserved. The optional public replay
release tar is prepared but NOT published: .work/network-delivery01/full01-public-closure.tar,
462551040B/SHA29541085933138adb13e11fb1f91b247b03f8c20e10d68c978d6d7034ecfccc4,
only manifest/genesis/264bodies. See wallet-integration/README.md for portable commands.

Optional server: second disk `/mnt/data` was measured2739028307968B free (~2.74TB),
correcting the earlier system-only figure. Key-authenticated read-only access/basic
namespace pilot passed. No password read, sudo, install or remote heavy run. It is
not a prerequisite or an owner annual storage budget; compatibility remains scoped
in review/REMOTE_REPRO_REQUIREMENTS.md. Canonical root unchanged.

Owner short reports delivered around12:28,12:37,12:43,12:45,12:49UTC; next regular
12:58UTC with material updates sooner. No invented completion percentage.

Publication checkpoint13:03UTC: ordinary push succeeded; public main readback
exactc5e2f36ddb6c225e7d4c17363ffe0eeba93ce49f. Automatic pushCI44088764296
is IN_PROGRESS on exactly thatSHA, https://github.com/jouliene/pq-private-chain/actions/runs/44088764296.
No source/parameter change since independentexecutiona9357c2; final commit added
reviewed docs/safeevidence only. Releaseartifact notyetpublished. Continue actualCI
readback, then release/upload/verify; criterion6 NOTcomplete until then.

## CI failure and allocation32: test-order correction

Actual pushCI44088764296 terminated FAILURE13:05:29UTC on c5e2f36. Clean build,
public verification, legacy fresh-private and witness probe all passed. Isolated
wallet failed pre-Popen: ValueError/fixedreasonnull, zeroevents/proofs/nativecalls/
observerepochs and no childexit receipt. Seven fixed public JSONs are retained in
`experiments/network-feasibility/evidence/ci-failed01/`; no private raw output.
The exact historical exception text was sanitized and has NOT been recovered.

Source reconstruction found legacy private_smoke leaves public ledger.sqlite in
installation source_root; the unchanged wallet mount policy rejects every DB in
that tree before spawning. A public-only clean-tree/SQLite discriminator confirms
this ordering incompatibility. Minimal correction moves isolated small5 directly
after build, before the unchanged legacy public/private/witness step. No source,
crypto/profile, permissions or policy change; no evidence deletion. Wallet README
now states the clean installation/order prerequisite. Independent source review
passed in review/CI_ORDER_REPAIR_REVIEW01.md; Root read the actual public control
and confirmed no accepted installation/source-pin overlap. Next is one genuine
hosted clean CI rerun after ordinary commit/push.

Root owns Git/status/publication; arch_private_repro owns failure diagnosis;
arch_consensus_roles owns terminal public tree control; arch_proof_alternatives
owns independent repair review. No local heavy job. Allocation32 is the next
automatic hosted CI after reviewed push; preserve failed44088764296. Do not rerun
closed network/fullwallet campaigns. Release and criterion6 remain pending.

Allocation32 publication readback: ordinary push of reviewed workflow repair
246ab5388c960ef5575acf56e4d5faa28b6df4b3 succeeded. GitHub main equals that SHA.
Automatic pushCI44090899086 is IN_PROGRESS on exactly that SHA; previous failure
44088764296 remains preserved. No source/proof/profile or installation-pin change.
Next: actual CI outcome and fixed public receipts; if successful, publish and
verify the prepared release artifact/delivery record. No new local heavy job.

Allocation32 terminated FAILURE (CI44090899086). Build passed; isolated child
now starts but exits1 after0.065790911s, with no fixed actor stage, event, proof
or observation epoch. The old pre-Popen ordering obstruction was passed; this
is a distinct unlocalized namespace/runtime startup failure. Fixed public
records and actual CI metadata are preserved in evidence/ci-failed02. No private
raw stderr was retained or reconstructed, and no exact kernel cause is claimed.

Allocation33: add a minimal public-only startup preflight before CI build. Use
unchanged isolation.command/seccomp for /usr/bin/true then official pinned Node
--version, bounded separate records and only public stderr. It must fail CI on
failed prerequisites; never disable host policy or skip wallet checks. Independent
review and one cheap local control precede the next ordinary push. If hosted
preflight fails, no build/proof campaign runs; investigate that exact evidence.
Root owns workflow/status/Git; arch_private_repro owns ci_preflight.py;
arch_proof_alternatives reviews. No heavy local job; previous jobs terminal.

Allocation33 source review GO: new public diagnostic only; final script
e4a245ed6f31a314e10ab50a12f0e498cf5741718ae33d321b6b6d911f0619ee.
Reviewer-requested inclusive final10s guard applied; both tiny local versions
preserved. Final true/Node probes exit0 in0.016010s/0.019177s; complete receipt
review/CI_PREFLIGHT_LOCAL02.json543e6e1e2f8ed2861dc51bf657f25704f4e144253220c9415c82f4aee7522d58.
This is startup evidence only, not a new private/proof campaign or hostedPASS.
Next: publish this reviewed early discriminator; actual hosted failure determines
the remaining prerequisite without rebuilding if preflight fails.
