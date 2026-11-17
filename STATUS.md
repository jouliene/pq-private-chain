# Authenticated incremental synchronization — ACTIVE

Canonical:/home/neo/jouliene/pq-private-chain. Owner baseline:2b87d1e5fcb9090390c476138bbd174d6034a6a9.
Actual HEAD equals baseline; tracked work was clean before this milestone.
Prior network-feasibility and its264/864 proof campaigns are closed preserved
history. Native Goal user-edited objective read back ACTIVE. No budget imposed.
All six new completion criteria remain pending; design/source work is not PASS.

## Ownership and current allocation

- Root: semantic contract, Goal/status, source manifests, integration experiments,
  experiments/network-feasibility/wallet-integration/{run.py,wallet.mjs} and wallet-witness/joint_controls.mjs,
  experiments/incremental-sync/{CONTRACT.md,non-review experiment files}, Git/CI,
  final primary evidence verification, acceptance and publication.
- arch_consensus_roles (existing Sol/high): actual Rust direct-range serving,
  ledger {store.rs,main.rs,lib.rs,scan.rs,new continuation module}, tests/sync-serving*.
- arch_private_repro (existing Sol/high): actual wallet recovery.mjs/local_witnesses.mjs,
  tests/sync-wallet*. No ledger/integration/controller edits.
- arch_proof_alternatives (existing Astra/high): NON-IMPLEMENTING independent
  contract/source/privacy review and later clean reproduction; owns only
  experiments/incremental-sync/review/. No implementation edits.

No nested agents. One heavy build/proof job at a time, only after explicit Root
allocation. S01 component source is frozen and independently source-reviewed. Root allocation S02
completed: immutable sync01 build and six structural Rust controls PASS.
S03 sync-private01 incremental nine-proof scenario completed PASS. No heavy job
is currently running; S04 trace awaits script freeze/source review. Wallet author now owns lightweight trace.py/trace.mjs
measurement implementation; reviewer owns final integration source review. Failed run labels remain immutable.

## Agreed implementation seam

436-byte version1 request/response headers CPHREQ01/CPHCONT1 bind block version,
chain/genesis, exact160-byte base and target cursors and u64 exact frame count.
Per-frame bounds and parser windows stay bounded; one whole selected endpoint is
one wallet commit. No256-total-range cap, arbitrary imported base, untrusted page
commit or old-prefix construction. Native indexed read snapshot includes actual
row/blob counters and SQL fullscan-step counters; startup/open costs are separate.
Ready same-head sync requires zero history RPC/read/authentication. Selected-branch
zero range still authenticates header/EOF before minting a new view. Branch choice
revokes old private views/packets; old committed image stays intact but revoked
until the replacement candidate authenticates. Retained bases are session-owned.

## Next decisive work

1. Implement the agreed source and independently review exact format/atomicity.
2. Root integrates existing genuine actor/controller with incremental sync and
   private-RAM equivalence against full replay, plus targeted failure controls.
   Proposed nine-proof branch/expiry scenario replaces255 rolling proofs with
   legal empty blocks AFTER a genuinely different root, making oldh2 ineligible.
   Reviewer approved this discriminator; no proof allocation yet. It is not a claimed result.
3. Reuse actual prior public genuine history for fixed-length long-trace byte/
   read/authentication counts. Resolve portable fixture preparation without a
   hidden untracked DB dependency or fabricated admission. Oracles/prep stay out
   of measured roles; new proof generation only for the small private scenario.
4. Freeze manifests, allocate one fresh build and focused controls, then the
   genuine changed path. Diagnose failures without weakening safeguards.
5. Non-author clean reproduction, actual existing automatic CI, publication and
   exact SHA/readback; update costs and one next proof-size/storage experiment.

## Acceptance checklist

1 actual serving+wallet code:pending;2 exact linear read/byte/auth evidence:pending;
3 genuine payment/recovery/branches:pending;4 adversarial atomic controls:pending;
5 independent clean reproduction:pending;6 passing actualCI/publication:pending.

Historical implementation/reference findings, full evidence and replay artifact
remain at baseline and release network-feasibility-2026-11-17. No need to recreate
that release, change proof parameters or prepare the optional remote server now.

## S02 checkpoint

Both component sources frozen; public parser31 controls reported PASS (Root readback
pending), native tests not yet run. Integration now forces true genesis reconstruction
in the private RAM reference, after independent review found legacy full-prefix
authentication reused prior transition state. Genuine scenario starts rolling wallet
at authenticated genesis0; malformed258-block suffix exercises rollback after a
complete256-block staged window. Branch packet oracle corrected to require retired
unused packet deletion and rejection. No acceptance claim or newproof result yet.

## Verified S02 / running S03

- Root independently executed31 public parser controls:PASS.
- Fresh offline/locked sync01 build:PASS,109.2033s,424576KiB maximumRSS;
  eight actual provider controls and private installation startup probe passed.
- Six compiled serving controls:PASS,0.05s test body. Writer failure/retry,
  selected range beyond256, corrupt unrequested prefix and snapshot lock covered.
- Installation approval:4dbabf63c36a7e26136d43490ef1d032cd4e46958bd2027f0f439fd46d2ade3d.
- CORE:6737bffc428f5f1e795b35ba41455a92cc34f9779ff8b12b0d7678062a20af9f.
- Wallet runner SOURCE:94c5912d4892677caa82cf72eb65572362be05f826408bb7f8e6762f3b9c3232.
- Public replay SOURCE:e81dcae1e1afed73fc839f00b67f75277299cf4f4bc623b0117e123e36300366.
- S03 running command uses --label sync-private01 --profile incremental and above
  installation/source approvals. Raw public receipts live under
  experiments/network-feasibility/wallet-integration/.work/sync-private01/.
  Inspect its actual process/RESULT before any retry; do not duplicate the job.
- Next after S03:diagnose outcome; ifPASS prepare one new public replay DB from
  existing full01 public closure (no new264proof generation), then trace and
  independent clean-checkout reproduction. No native source edits pending.
- Reviewer approved final integration and new CI/test wrappers at source level.
  Actual integrated PASS, measurements, independent reproduction and CI remain pending.

## S03 actual integrated result

PASS, RESULT SHA33ba6bd9ad24537f7427b911c1be6393970c058ea52fd64a34c96244035f31b4.
Nine newproofs/ten positive admissions;255legalemptyblocks;44malformed continuation
atomic controls including one258-frame truncation after the first staged256window.
Thirteen true genesis-reference equivalence checks and13same-head noops; one
equal-public-range/different-owned-state comparison. Shallow rewind, deep full
replay, stale view/packet revocation, expiry refresh and two all14-atomic Anchor
rejections passed. Originalprocess414.14s exited before freshrestore14.82s and
newproofadmission. Finalheight260/leaves12/NFs6,fees12682394,liabilities0,
remaining1087317606 from1100000000 synthetic total. Coldrestore read94218B/259blocks.
Rawpublic evidence copied under experiments/incremental-sync/evidence/sync-private01/.
Source/runtime unchanged. Core source checkpoint commit:
fb5e8dbeffc3f551962d4c1d971ebdb3b6ecdce2. Not yet pushed or independently reproduced.

S04 refinement: reuse the already independently accepted public-only Gate5 replay
DB as an explicitly approved development dataset instead of repeating its264proof
verification solely for preparation. Prior RESULT:
/tmp/pq-gate5-20261117-01/experiments/network-feasibility/wallet-integration/.work/reviewer-public01/RESULT.json
SHA973cd516e921a7d71223ec4d62d037f5c9784098de7170cf6cbd56d22061074b.
It is not an implicit source dependency or a new cryptographic verdict. Trace
checks actual current native head/all14/genesis against that approved primary
evidence; fixture work excluded from measured roles. The portable clean-review
recipe reconstructs onefreshpublicDB from release closure using public_replay.py,
so independent reproduction does not depend on this historical directory.

## S04 running checkpoint

Trace source freeze independently approved:trace.py9a1aceeeb8688dcbbd3815bef4723f42007da1d1d86d8a68162ce73f15e5e364,
trace.mjs8b896e4fb7866e2638812d7f86e36d733e380c663a4c64795338b6956ef328f2;
TRACE_SOURCE f10c13580d84cbf5730f7f9aae2795a4e1e922d2c581dcb704ddadda4edded62.
Root started sole heavy trace01 at experiments/incremental-sync/.work/trace01,
1800s internal guard. Inspect process/RESULT before retry. Old approved fixture
and genesisSHA8d4abb801ecdb45806601b92c48c5b38f78675014729468e25e1bf16bd61f1c6
are explicit arguments. No other jobs allocated. Expected counts are analytical
oracle only:responses196066/742114/1492866B for32/128/260; oldprefix counterfactual
3222784/45159040/181853424B. Runtime measurement pending.

Reviewer independently validated S03 actual public proofs,14-table final state,
same nullifier in old/refreshed/restored spends,44failure controls and process
isolation. PRIVATE_ACTUAL01.json records this; clean execution remains pending.
