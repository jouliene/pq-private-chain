# Incremental synchronization acceptance record

Status: implementation, genuine scenarios, exact scaling and independent clean
reproduction PASS. Actual publication/CI remains required. The bounded milestone
is not yet complete; the global blockchain objective remains ACTIVE.

Baseline: `2b87d1e5fcb9090390c476138bbd174d6034a6a9`.
Current executable source checkpoint: `17dd4e73f4fbde9fee2129d0fd761b864eefe42f`.
The source and wire contract are independently reviewed. Initial review found
that the old reference authenticated a prefix while reusing transition state;
the reference now reconstructs from genesis. A test incorrectly expected an
unused revoked packet to remain allocated; it now requires deletion and rejects
access to that handle. Neither correction changes the payment predicate.

## Genuine integrated execution

Root ran the new `incremental` profile in a fresh immutable `sync01` installation.
The independent reviewer checked the actual public proof/statement/Parent
associations, selected SQL state and exact source correspondence.

| Observation | Actual result |
|---|---:|
| Newly generated complete proofs | 9 |
| Positive native proof admissions, including rollback/reinclusion controls | 10 |
| Selected final height / bodies / leaves / nullifiers | 260 / 6 / 12 / 6 |
| Legally admitted empty blocks after a genuine root change | 255 |
| Malformed continuation atomic-rejection controls | 44 |
| Truncation after a complete candidate window was applied privately | 1 |
| True genesis-reference comparisons / unchanged-head controls | 13 / 13 |
| Equal public requests from wallets with different ownership | 1 comparison |
| Typed Anchor rejections with all14 tables unchanged | 2 |
| Synthetic source total / fees / outstanding source liabilities | 1100000000 / 12682394 / 0 |
| Remaining note supply by conservation | 1087317606 |
| Backup-only cold scan before newly proved accepted spend | 94218 bytes, 259 blocks |

The old anchor draft, refreshed spend and restored spend have the same public
nullifier and three different anchor roots. The old draft was genuinely verified
before expiry; the orphan-only child was genuinely verified before branch
replacement. Rejection at the later Anchor gate is therefore not substituted for
proof validation. Shallow joint rewind repairs discovery, spentness and paths;
deep selection revokes old capabilities and explicitly requires full replay.

The original process exited successfully before the new restore process started.
The backup was created after receiving-key rotation and before receipt; only its
bounded RAM channel plus public inventory/context/history crosses this boundary.
No backup, key, opening, witness or digest of private material is published.
The trusted joint cursor/checkpoint is process-local in this prototype; clean
restart/recovery pays the disclosed full scan. Durable wallet-state persistence,
unknown receiving keys and mnemonic recovery remain outside the claim.

Functional evidence: [raw result](evidence/sync-private01/RESULT.json),
[original process](evidence/sync-private01/original-process.json),
[restored process](evidence/sync-private01/restore-process.json),
[independent readback](review/PRIVATE_ACTUAL01.json).
The RESULT SHA256 is
`33ba6bd9ad24537f7427b911c1be6393970c058ea52fd64a34c96244035f31b4`.
Readback and the separate clean execution below are distinct evidence.

## Resource scopes of that functional experiment

The original/restore process spans were414.143s and14.818s. Their Node SELF CPU
was18.91s/2.95s; waited-descendant CPU was56.98s/7.57s. Sampled concurrent wallet
process-tree peaks were430944KiB/362944KiB. The nine proof workers totalled16.493s
wall and16.280s CPU; those nested costs are already included in the wallet spans.
Native CLI SELF CPU was334.996s, largely repeated process/registry startup across
legal empty admissions and other commands. This is a sequential instrumented
experiment, not a persistent-node throughput result.

Successful wallet synchronization spans totalled404478 input bytes and11.190s,
including the charged initial scans, deep replay and cold recovery. They exclude
full-reference oracle and malformed-fixture work. Whole process memory/CPU
includes those controls and cannot be relabelled ordinary-update cost. Maximum
committed state Buffer payload was39712B; maximum retained journal Buffer payload
was355488B at the declared K8/R8 bounds. These are not whole-heap or peak-RSS
measurements. The long trace separately establishes ordinary append scaling.

## Component controls

A fresh offline/locked build passed with eight actual provider controls and the
private installation startup check. Root executed31 public parser controls and
six compiled direct-serving controls. The serving tests cover indexed retrieval
past an intentionally corrupt unrequested prefix, more than256 frames, exact
base/target/context rejection, partial writer failure and clean retry, and a
read snapshot that blocks concurrent replacement until completion. Structural
empty histories and parser fixtures are labelled separately from genuine proofs.
See [build and serving evidence](evidence/sync01/serving-RESULT.json).

## Executed exact scaling result

All420 sequential append operations passed on the fixed, already genuine public
history. Every received frame was authenticated by the actual wallet. Current
native head, genesis and all14 canonical tables match the independently accepted
source dataset, and the source database remained unchanged. Each case used a
fresh zero-owned wallet and a separate same-backup reference held at genesis
until its final full replay. These cases establish the common-history mechanism;
the separate genuine scenario establishes owned-note paths and spending.

| Final prefix | Actual request bytes | Actual response bytes | Actual authenticated blocks / payment records | Old repeated-prefix response bytes (exact counterfactual) | Old authenticated blocks (counterfactual) |
|---:|---:|---:|---:|---:|---:|
| 32 | 13952 | 196066 | 32 / 33 | 3222784 | 528 |
| 128 | 55808 | 742114 | 128 / 129 | 45159040 | 8256 |
| 260 | 113360 | 1492866 | 260 / 261 | 181853424 | 33930 |

For frame sizes F_i and N one-block updates, actual protocol responses are
`sum(F_i) + 436*N` and requests are `436*N`. The old repeated-prefix response
obligation is exactly `sum((N-i+1)*F_i)`. Old timing was not rerun and is not used
to infer this result. Exact measured server counters match the separately derived
[expected counts](EXPECTED_COUNTS.json). All measured history SELECT fullscan-step
counters are zero; source queries and a corrupted-unrequested-prefix control
provide additional evidence that prefix work was removed.

At N260 the server read260 requested headers (72864B) and261 reduced records
(1301438B). It also read259 base headers (72584B),260 target headers (72864B), and
one fixed tip header per process (72800B total) plus260 body-length scalar rows.
Startup also checks bounded genesis/source registry and cache/tree/runtime
metadata. These are SQL logical values, not physical page or disk-I/O counts;
index depth and cache effects are not claimed constant. No full historical prefix
is generated and discarded by the measured serving path.

| Prefix | Successful wallet sync elapsed | Node SELF CPU | Waited helper CPU (100Hz ticks) | Fresh server CLI elapsed / SELF CPU | Sampled sync-bracket tree RSS maximum |
|---:|---:|---:|---:|---:|---:|
| 32 | 0.678s | 0.508s | 0.17s | 36.896s / 36.409s | 90876KiB |
| 128 | 2.526s | 1.833s | 0.67s | 147.574s / 145.506s | 93332KiB |
| 260 | 6.330s | 4.381s | 1.92s | 297.583s / 293.455s | 146768KiB |

The fresh CLI pays repeated verifier-registry/startup cost; these timings are not
persistent serving throughput. Startup/serving spans nest inside CLI wall/CPU.
The wallet RSS bracket includes its baseline heap and uses finite sampling;
whole Node maximum165340KiB also includes setup/reference replay/cleanup.
Retained state/journal payload counters appear in every raw row. No timing ratio
is used as the linearity criterion. At prefixes 32/128/260 the maximum committed
Buffer payloads were 4576/17008/33472 bytes; retained journal payloads were
37456/149168/298672 bytes, with at most nine checkpoints. These counters include
bounded accepted-anchor history and exclude heap/object/allocator overhead.

The actual experiment control pipes carried649970B wallet-to-controller and
61884B controller-to-wallet across all cases. That includes hex requests, paths
and measurement telemetry; it is a separate transport layer from the binary
436B protocol requests and file-carried history. The preloaded261-endpoint
schedule was191593B of JSON; genesis was5672B, full260 scan1379506B, and the three
reference-prefix files2247926B. Preparation, final reference replay and endpoint
acquisition/freshness are outside measured range roles and are not declared free.

[Raw trace](evidence/trace01/RESULT.json) SHA256:
`aa14df387f1c2c3e5fdaa502b3bc66aba700b0ea66e412de4a6195bffb0dffe7`.
The clean reviewer rebuilt the public fixture from the published closure and
reproduced this trace, so the historical development dataset is not a hidden
reproduction dependency.

## Independent clean execution

The non-implementing reviewer used a clean checkout of
`17dd4e73f4fbde9fee2129d0fd761b864eefe42f`. The canonical development tree,
historical research tree, prior replay directory and Cargo registry/Git caches
were hidden by the outer namespace. Only declared installed toolchain/runtime
prerequisites were available. Public history was downloaded independently from
the existing release; no development database or private fixture was copied.
Exact command vectors, source/runtime identities and observed boundary checks
are in [the review directory](review/).

The fresh offline build passed; 31 parser and six compiled serving controls
passed. The first standalone parser invocation failed because its read-only
outer namespace omitted a writable TMPDIR. That failure is retained. Only the
outer test environment was corrected to use the clone's private temporary
directory; source, masks and runtime checks were unchanged.

The independently generated nine-proof cycle passed all 44 malformed controls,
13 full-reference comparisons, 13 no-op controls, anchor/branch checks and the
new-process backup-only newly proved spend. All nine public proof bodies differ
from Root's run. The final accounting is identical. Its RESULT SHA256 is
`b9aeb7a80377b5b0d8859f4c6f3c7da6cfa5ce368c09f717fb71d0e97ca49ef3`.
See [independent private readback](review/CLEAN_PRIVATE_ACTUAL01.json).

For portable trace preparation, the reviewer genuinely verified the published
264 existing proofs into a fresh ledger: 265 positive admissions, four rollbacks,
two atomic Anchor rejections, and exact selected head/all14 table equality. No
new 264-proof generation campaign occurred. This preparation took 341.146 seconds
outer wall time and is excluded from synchronization roles. Its RESULT SHA256 is
`91a1b0020fc0b130d27e0160047139424aa41ee46bf7c8b65299ad262dcdda5b`.
See [independent public fixture readback](review/CLEAN_PUBLIC_REPLAY_ACTUAL01.json).
The independently executed long trace also passed, with all 420 per-row public
contexts, request/response sizes, logical read counts, wallet authentication and
retained payload counts exactly equal to Root's run. The separate analytical
oracle agrees. Outer wall time was 506.864 seconds; timing is not the equality or
linearity criterion. Independent RESULT SHA256:
`66b986d62009a2db90607c88a64e299631772b4de000c00d7624287eb0db3568`.
Raw independent receipts are retained under
[evidence/clean-review01](evidence/clean-review01/), with their fixed allowlist and
original hashes in [CLEAN_SAFE_EVIDENCE01.json](review/CLEAN_SAFE_EVIDENCE01.json).
The [final independent disposition](review/CLEAN_REPRODUCTION01.md) gives GO for
publication and actual CI, with no unresolved material implementation/privacy
finding. Actual CI/publication is still pending.

## Unchanged limits and stopping boundary

Hash linkage does not establish payment validity, consensus, endpoint freshness
or availability. The selected validating source retains that explicit delegation.
The single serving snapshot may block a concurrent DELETE-journal writer.
Requests concern only common public ranges; IP addresses, timing and source
selection are not hidden by this mechanism.

Complete ordinary bodies still average1751265.75B in the accepted network sample:
175.126575TB/year per first body copy at100M offered payments/year, before other
state and replication. The owner set no annual traffic budget and has not adopted
that storage model. Incremental wallet updates do not implement remote pruning,
bootstrap availability, full consensus or a formal PQ/privacy theorem.

After the remaining actual CI/publication gate, stop this
synchronization milestone. The next experiment must address complete-payment
proof size or the full storage/participation obligation; no additional wallet or
CI tuning milestone follows automatically.
