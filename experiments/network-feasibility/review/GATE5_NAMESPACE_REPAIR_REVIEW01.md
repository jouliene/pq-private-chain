# Gate5 namespace-aware probe repair review

Status: controlled public failure reproduced; successor source GO below.
No reviewer native/proof/build rerun is authorized by this note.

Independently read allocation29 probe.py, RESULT01.json and REPORT01.md. The
diagnostic preserved the exact outer clean-review bwrap argv and actual frozen
isolation.command/filter. Its harmless controller was PID3 in namespace2891;
an intentionally held inner thread was TID3/TGID2 in namespace2897, with a
different starttime. Inner PID1/self/thread had matching root identity. The actual
old inspect() rejected exactly `host process root inaccessible` solely because
the numeric /proc/3/root path existed in that different namespace. Both denied
paths returned ENOENT, inherited sentinel-inode FD exclusion and all three socket
EPERM checks passed; seccomp2 remained active. Three explicit subprocesses and
one public thread completed in0.094498s, without wallet/key/proof execution.

This proves an identity-confusion defect in the old assertion. The historical
reviewer-small01 failure sanitized its exact clause, so the diagnostic does not
recover that missing trace or establish which original thread occupied3. The
failed clean attempt and original Source03 remain preserved. The defect is a
possible false rejection; the experiment does not show controller-root access.

Required narrow repair: bind the actual controller PID namespace in public config;
require child /proc/1/ns/pid to match child /proc/self/ns/pid and exclude the
controller namespace. A present same-number PID must be classified in the child
namespace, not treated as an outer identity. Missing paths require confirmed
absence; unreadable/ambiguous/mismatched identity remains fatal. Replace the
misleading numeric-root-absence boolean with namespace-exclusion evidence and
cross-check the result against actual outside Node/controller namespace links.
Update every consumer through the shared fixed validator; retain exact result
fields and bounded public metadata.

Do not change isolation.command, seccomp, mounted source/output trees, forbidden
DB paths/inode FDs, socket controls, actual executable/namespace readback or mandatory
prover observations. Do not work around the issue by allocating large PID numbers
or suppressing the outer PID namespace. New source identity and actual clean
small5 success remain mandatory before the conditional full-public replay.

Prior full01 applicability is scoped: its existing distinct-process namespace
readbacks, mount/FD/socket controls and genuine private/public proof outcomes remain
valid evidence at their original hashes. An experiment-only identity-aware probe
repair does not change the cryptographic/wallet implementation or retroactively
make the observed full01 run a clean reproduction. Absent another finding, it
does not justify regenerating264 proofs. Gate5 must still complete independently.

## Frozen successor source disposition

**Source GO for Root's manifest freeze/clean-checkout update and a new-label small5
execution**, at these independently checked hashes:

| File | SHA256 |
|---|---|
| run.py | 3e99ecde6534fa1dceee15f02c0f6eb636659aacd13bf118cab5faf827477a75 |
| isolation_probe.py | f9352dcfb3dd62353fee7e212cdaa567c98ad9fd5f7aecffae8e6847da4c0c63 |
| isolation_control.py | 64199d4f41f9925df4565f8ea14f5859fca4cdeef12e87fe9c54a39b9b53c1b7 |
| namespace_controls.py | 6d6c40aeca36876c30b3d0aaeb2e6148a687bc3ff744459dd8260f17ff3a74b9 |

Read complete diffs against the unchanged independent clone and all27 controls.
Controller config now binds actual PID and PID-namespace link. The probe rejects
the controller's own namespace before any unnecessary PID1 inspection, verifies
child-scoped procfs, and permits same-number process/thread existence only with
matching child namespace. Missing namespace link with a present directory fails;
PermissionError and unexpected identity remain fatal. A shared validator checks
reported controller identity, child/procfs identity, exact exclusion boolean and
the two permitted numeric-path classifications. Both the live wallet controller
and standalone isolation_control call it using actual external namespace links.
The saved public descendant fields use the new namespace-exclusion semantics.

isolation.py remains f5c3bef9... and wallet.mjs remains0edab447... byte-exact.
The diff changes no seccomp/mount policy, socket or forbidden-file/FD checks,
cryptographic/wallet code, private IPC, observer retry, or prover-observation gate.
There is therefore no new reason to discard the full01 cryptographic/joint-wallet
result or regenerate264 proofs. Source04 and public replay's runner dependency
must be frozen explicitly; do not relabel earlier receipts with new source IDs.

Read actual GATE5_NAMESPACE_CONTROLS02.json
`db27b9c41dc4bbc2ef97a1709f04098ced8ba07d6e1eca30f58b9bdc2107cd77`:
27/27 pass, exact source pre/post, no children. These are simulated metadata
controls plus one real own-namespace negative, not a repaired isolated wallet run.
The earlier control receipt a44d8360... remains failed: it rejected the same
namespace with PermissionError before the expected typed ValueError. Reordering
the already-mandatory own-namespace rejection fixes that diagnostic ordering
without accepting an unsafe case. Reviewer did not rerun these controls.

No remaining source blocker. Actual clean nested-namespace small5 must still
establish both actors' corrected boundary evidence, new genuine proofs and
backup-only spend before the allocated full-public replay can proceed.
