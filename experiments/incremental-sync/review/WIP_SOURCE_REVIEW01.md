# WIP integrated source review

2026-11-18. Non-implementing source review only; no native execution, build or
proof run. These are live WIP observations, not approval of a frozen source hash.

## Material finding W1: reference was not rebuilding private state

`wallet-integration/wallet.mjs` initially reused a persistent reference session
and called `recoverLocalWitnesses` after each suffix update. In the new shared
`recoverLocal(..., continuation=false)`, `from = recoveryBase(value)` still cloned
that session's current joint state and filtered already-applied blocks. The
reference authenticated a full prefix but did not reconstruct receiving,
spentness and frontier state from genesis. It could share an incremental
state-transition defect with the tested session.

Root accepted the correction: before every reference recovery, select that
reference session's authenticated genesis -> current target, catching only
LocalWitnessReplayRequired when outside its journal, then recover the complete
prefix. Perform this outside measured synchronization spans, after any failure
controls needing the previous valid reference view. No new proofs are needed.
Final source and actual distinct-session nonempty comparisons remain to review.

## Inspected boundaries that currently support the proposal

- Continuation header is436B, fixed magic/version/context/base/target, exactu64
  frame count. JS compares the whole expected header before applying records and
  checks exact final cursor/EOF; parsing windows remain bounded, range is not
  limited to256frames.
- `localWitnessSyncRequest` derives its base from private current/selected journal
  state. `synchronizeLocalWitnesses` derives it again; no imported native state.
  Ready identical full cursor takes a zero-read/no-revision path. Selected replay
  remains distinct and cannot use that shortcut.
- Recovery clones the selected bounded checkpoint/journal, publishes only after
  exact endpoint and cleanup, and revokes on cleanup failure. Branch selection
  revokes capabilities before lookup while retaining old images privately;
  absent selectedBase makes replay start at genesis.
- Boolean equivalence requires two distinct valid private sessions and checks
  chain/genesis/version, configured bounds, genesis/current cursor, anchors,
  NF-keyed openings and40siblings, plus semantic retained journal. Random tokens
  are used only to join each session's own witness map, not compared across
  sessions. It exports no private bytes/hash or arbitrary callback.
- Rust uses a single Deferred snapshot, exact base/target indexed lookup and
  only requested reduced-history rows. `CountedWriter` distinguishes bytes
  actually written from fetched/framed bytes, including interrupted writes.
  Startup tip reads are separately scoped. The selected query fullscan-step
  count is explicitly not a physical-disk-byte count or all-SQL counter.
- The nine-proof fixture is coherent: two credits; receipt; old draft;
  recipient spend; refreshed old spend; orphan child; replacement; restored
  spend. The255 legal empties preserve the already-different h3 root and all
  count/accounting fields while advancing height, making h2 ineligible at258.
  Native positive old/orphan proofs precede later Anchor rejections. Final
  selected state expects6bodies/12leaves/6nullifiers, fees12682394 and260blocks.
- Full reference scans and their costs are marked separately from sync spans;
  whole actor CPU/RSS still includes reference activity and must remain so
  labelled. A dedicated long public trace supplies scalable append measurements.

## Remaining checks before frozen-source execution GO

Review the applied W1 correction and fixed genuine adversarial controls, especially
h1->h258 truncation AFTER a full256-block candidate window; no early publication,
retry exactly once, and selected replay stays nonspendable on failure. Review
final source/profile pins and native report/terminal count schema correspondence.
Actual compiled serving controls, private nine-proof integration and clean
reproduction remain unexecuted acceptance gates. This review does not replace
them with source assertions or approve WIP for execution.

## Frozen wallet component source disposition

Actual hashes checked against the author's freeze:

- recovery.mjs:89306534e504303690c9651e39faa3786a32edcef69e76dafe3083af9da56c66
- local_witnesses.mjs:8fc5306c9da5561eae0264c15214a514b8af84210e70aaef905219483690d472
- tests/sync-wallet-parser.mjs:528a4cf7e52a15c0b70a713bda535c1213907d253d3e3c479315c25139bdd58b
- tests/sync-wallet-controls.mjs:69043a331cb12eef98537a9c9f70a43e91bfbb1bcde7c8fb3c88beb2f459f47c

Wallet component SOURCE GO: no remaining material blocker found in authority,
private candidate publication, selected checkpoint lifetime, cleanup failure,
no-op packet preservation or semantic comparison. The fixed private controls
are definitions requiring actual genuine-session invocation. Parser controls
were source-read; this reviewer did not execute them. The whole integration
still requires W1's actual actor fix, final fixed failure/retry controls and
source freeze/readback before allocated execution.

## Final integration source readback

W1 is resolved in the actual actor: every reference comparison now first selects
that reference's authenticated genesis -> target and replays the full history;
only expected LocalWitnessReplayRequired is caught.

W2 found during final readback: actor expected `.retired` on the lifecycle of an
unconsumed packet after branch selection. Existing retirePayment correctly wipes
and deletes such a packet immediately, returning null from paymentLifecycle;
the assertion and subsequent dispose would fail. Root corrected only the actor:
assert lifecycle===null and publicPayment rejects; no second disposal. Actual
corrected source was inspected, with core payment lifecycle unchanged.

The late-window negative now starts from the rolling wallet's authenticated
GENESIS state before funding. Its next range has258frames. The parser parses
frame257, then applies the first256candidate blocks; truncation of frame258
therefore tests failure AFTER tentative receipts/frontier/spentness publication
inside the candidate, with committed state still compared privately to reference.
The previous257-frame proposal would have failed before applying the window.

Final integrated SOURCE GO for Root-allocated fresh build, compiled serving/
parser controls, then bounded genuine nine-proof execution. No remaining material
source blocker found. This is not execution acceptance or permission to skip any
actual control. Reviewed exact inputs:

- runner:1f280a0abbf6af9eb1a2ae705f52cf0534a1d42e8abb47b9d018c5afc0419616
- actor:a09b0ba9510db87722db6634145a534c8ba81a44c1896fe9fcfea88328879b6e
- profile:4986215372c6de93bf7ef400300771a70965303f0ab65ccd3788dfb323acceec
- continuation.rs:7d80639763c69cda71dbdea10e299f628da374f4ac794b5e903b301b0dfe7fec
- store.rs:6c3c7000e55e06419fac95664d38868ff2bea279474d91cb11e62b5174ebf057
- main.rs:8c211f08c8382663f75aa9ce766fbc9c32a4e8c033c4c3ba3aa337e5bedd29ae
- lib.rs:57ce7cd7b5a8992e914c9c49b7182f68f2330e19caa40888d669eb447aaa7911
- tests/sync-serving/controls.rs:3de2727ad96663a14b2d8d29a71a64e3d9bbe7f2eb1793a129329d9efb1cf7a9

Wallet/parser/control four pins remain as listed above. Reviewer performed only
source reads and these small public source hashes; no crypto/native build/test.

## Focused control runner and automatic CI source review

Reviewed tests/run_sync_serving.py
SHA256c3b0239b065057c3bb089a463a59aee72c883a2d6e4fd00af341b81a0730e77d
and .github/workflows/smoke.yml
SHA2561e59a56329d02cff1a6ef2148bf494f50398a37c52bc07f5fdbe4684211d6fa4.
SOURCE GO, no concrete blocker. The public runner uses an approved installation
for this repository, its toolchain/environment, offline/locked release Cargo,
one build job, the fixed sync_serving_controls filter,300s/4MiB bounds, exact
six-pass output and installation postcheck. Its stdout/stderr are structural
public controls, not wallet/private process streams.

CI preserves the reviewed Ubuntu22/pinned Noble/nonroot runtime/isolation path.
Parser and serving controls plus the genuine incremental nine-proof profile
precede legacy private_smoke, which creates the source-root database rejected by
wallet isolation. Existing public replay/private3/witness checks remain required.
Fixed additional artifacts are public parser/serving records, without a directory
glob or private actor stream. Actual hosted CI remains a separate gate; Root's
local actual build/control results were reported but not independently rerun in
this source review. The reviewer starts no competing job while genuine S03 runs.
