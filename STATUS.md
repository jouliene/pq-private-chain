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
Current sole heavy allocation S03 is sync-private01 incremental nine-proof scenario;
no other build/proof/trace job may overlap. Wallet author now owns lightweight trace.py/trace.mjs
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
