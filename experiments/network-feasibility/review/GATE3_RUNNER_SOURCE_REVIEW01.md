# Gate3 isolated runner: source acceptance review

Initial candidate: `wallet-integration/run.py`
`de5ebe8b9f93831501a642e570727f9d15b10ef4fe008335f96d8707553f3bd9`.
This identity is a reviewed predecessor, not final execution approval. The
author/Root are applying bounded corrections before freezing. No native/private
run or repeated component campaign was performed by this reviewer.

## Narrow required corrections

1. Reject RPC must recheck the registered body's current SHA256, as positive
   admit already does, and retain its label/hash in the all14-table rejection
   receipt. An early Anchor result alone cannot bind the rejected bytes to the
   proof previously positively admitted.
2. Actual Node lookup must additionally compare `/proc/HOSTPID/exe` identity to
   approved Node, not only its reported namespace PID. A dev/inode comparison is
   sufficient here; repeated binary hashing during samples is unnecessary.
3. Controller validation of each Parent receipt should explicitly match its
   binary/source-manifest/approved-runtime identities against the loaded approval.
   The fixed actor already performs this check, but the controller's independent
   provenance receipt should bind the same identities, not flags alone.
4. Use explicit `uri=True` for the final SQLite `file:...?mode=ro` connection;
   do not rely on SQLite global URI defaults for the read-only oracle.

Root separately identified and is fixing the historical Gate2 database
prerequisite: a new clean run must not require an old run's database merely to
reach the denial controls. The fresh real ledger created after init and present
before restore must still be denied and externally checked; the public sentinel
and deliberately inheritable descriptors supplement that actual boundary.

The final public native-work-complete handshake is also pending. Node must have
finished/awaited all private child work while still alive for external self and
reaped-child CPU readback. Node child totals include Parent/prover/helper work;
separately reported proof-worker CPU is a subset, not another additive total.
Bwrap leader wait4 and finite sampled process RSS remain separately qualified.

## Source paths that are coherent

The launcher approves exact runner/profile sources and the complete installation,
uses the installed Node and Parent approval, and constructs a new allowlisted
root with a read-only source/common history plus only the declared writable public
body and fresh Parent public/evidence overlays. It never mounts a host root or
controller ledger directory. The fixed RPC vocabulary supplies common scans and
native public heads; it has no membership, owned-index or arbitrary command route.
The actor and coordinator use no ledger import. This is not an arbitrary-code
sandbox claim or a guarantee against a privileged host.

Before any secrets, the actor invokes the descendant denial probe. During work,
the controller checks sampled actual Node descendants' namespaces, seccomp,
mount permissions and forbidden DB device/inode handles. Each Parent worker
namespace PID must have a live sample. Source review plus inherited kernel
policy is the basis for short-lived helpers that sampling can miss; the receipt
must not call sampling exhaustive process coverage.

Backup is accepted once as a bounded private frame into a mutable RAM buffer.
It is never decoded, hashed or passed to a public recorder by this controller.
After handoff, further original actor RPCs are prohibited. The original actor
must actually reach exit0 under first wait4 before a new actor starts; restore
receives the existing backup buffer only after its own boundary handshake.
Consumed queue bytes and remaining buffers are cleared on both success/failure.
This is a no-persistence boundary, not a JS/Python allocator erasure theorem.

Every newly generated public body is tied to Parent statement/proof artifacts,
then must obtain at least one positive genuine native ledger admission before
overall success. Positive stale/orphan controls are real admission plus rollback.
Expected Anchor failures compare all14 actual SQLite tables before/after. Final
small/full accounting is internally consistent:5/261 selected bodies,4/516
nullifiers,10/522 leaves,4/260 selected blocks, fees10570146/551305634, total1.1B,
liabilities0. Full generation264 includes the three ultimately noncanonical
proofs; positive repeat admissions do not become new proof generation.

Private stdout/stderr have bounded RAM capture and fixed typed public summaries;
raw streams and private exception payloads have no persistence sink. The complete
source/installation is checked again after the run and on failure. Native public
CLI results are exact-schema/typed-error checked and have individual first-wait4
receipts. Heavy source hashing and SQL correctness oracles are outside wallet
service spans, but remain part of controller cost.

Disposition: **await final frozen corrected identity and handshake review for
small-run GO**. This review does not establish actual wallet capability isolation,
backup spend, resource acceptance or the full expiry/reorg sequence.

## Final frozen source disposition

**GO for Root's bounded small-five-proof diagnostic**, at:

- SOURCE.json: `216ec4a20d50a4dc9125ef0624882bcd2e9e347c4f25d3732c3ef179937592d5`
- run.py: `e074057760d27ee3792b8199cb08ad11149d5056918c7853e48ebd0358bdd560`
- wallet.mjs: `0edab447223b3424e4db9c7342f9f4e887eb4344685cdfc4bf57460c13a0722f`

Independently rechecked all seven exact manifest file hashes and read the final
changed ranges. All four reviewer corrections above are implemented. Anchor
rejection now requires the same registered body hash and prior positive admission,
recorded with label/hash. Actual Node executable device/inode is matched. Parent
binary/source/build/approved-runtime identities and normalized runtime digest
are checked against the loaded approved installation; the digest construction
matches the installed Parent's map normalization/framing. Final SQLite inspection
explicitly uses URI read-only mode.

Root's portability fix uses a real local SQLite sentinel plus the current run's
ledger; historical Gate2 databases are optional extra denials. After init, actual
Node sampling must observe the new ledger still inaccessible. Restore receives
its actual device/inode denial identities too.

Each actor now sends the public `native-work-complete` handshake only after awaited
session/wallet cleanup. The controller requires no remaining Node children,
rechecks live namespace/mount/FD policy and records actual live Node self and
reaped-child CPU ticks. Success requires this per-actor receipt, not only a global
mark. The original actor then transfers backup and exits; actual exit0 still
precedes fresh restore. Bwrap wait4, Node self/child totals, per-proof worker data,
concurrent sampled RSS and controller/native admission costs remain distinct.
The public terminal serialization/exit tail is outside that native-work sample.

No remaining source blocker was found. No new native/crypto/private execution was
performed during this review. Actual small-run source/ELF/process receipts,
positive admissions, backup-only restore and resources must be reviewed before
the full264-proof scenario is allocated or any Gate3 acceptance is claimed.

## Small01 failure and Source02 procfs correction

Small01 actually failed with PermissionError; see GATE3_SMALL01_FAILURE_REVIEW01.json.
Its first credit was registered but had no positive admission. The second Parent
terminal receipt is absent. The original receipt does not identify the failing
procfs operation, so an exit race remains a plausible diagnosis, not a proven
syscall attribution. No wallet integration PASS follows from that attempt.

**Source GO for a fresh-label small-five retry**, at SOURCE.json
`e57fbee1d951b33051e4329b4dc6e17d01719d3b2c77f1e43b53037f5dcb5c2e`
and run.py `b6fc63dda50d034072b51106fbe1e5f9e238ea179c74f9024bd75a8d18ce4158`.
Reviewer read the complete diff against preserved Source01, verified all seven
live file pins, and confirmed run.py is the only changed manifest dependency.
The original runner e0740577 is preserved. No native or proof job was run here.

The correction captures stat identity before sensitive observation and checks
identity again before recording a successful sample. PermissionError is omitted
only when stat and the PID directory are both absent, or when a fresh stat proves
the captured starttime still identifies a Z/X process. Live, unreadable, ambiguous,
unbound and changed-identity cases remain fatal. Child enumeration is inside the
guard; denied-path stat no longer conceals PermissionError through exists().
Fixed operation/errno/identity/classification fields are retained without the
exception message. Exit omissions are bounded in detail (first64) with an exact
counter. This preserves the documented finite-sampling scope; it does not prove
that every short-lived helper was observed.

Reviewer also read runner_controls.py
`505f6e48d64abc2709e03f41c131659bb158f4355d2519aa7483cf3d320bf232`:
the five new mocked procfs controls distinguish same-identity exit from live,
reused/unbound, missing-stat-only and inaccessible observations, including actual
sampler success/failure paths and absence of raw error-message persistence.
Their reported twelve-control PASS is author evidence, not a reviewer rerun or
real-kernel race reproduction. Actual retry receipts remain required; the earlier
failure and absence of a complete wallet result are unchanged.
