# CI order repair — source review

**Source GO for the workflow-only ordering repair. Actual hosted CI remains
mandatory; no successful hosted wallet execution is inferred.**

Reviewed current smoke.yml SHA256
`a9b56d4002c41b4cc9093d021d3a5ef20eb2caa04912e924e14c1209ef0ec016`
and wallet-integration/README.md SHA256
`4fe5321f6c3ee49e45614b7761057cb5a8dff179693a103edb389d94b5e83760`.
Compared with the previously executed clean-checkout workflow. A mechanical text
comparison confirms every named step body is byte-identical except two explanatory
comments; the isolated wallet step moves after build and before the legacy
public/private/witness step. No command, approval hash calculation, source/profile,
provider check, permissions, namespace policy or fixed public artifact allowlist
was changed. README documents the exact clean-installation prerequisite and
preserves previous evidence rather than deleting a database to bypass rejection.

The established source obstruction and limits of the sanitized historical failure
are recorded in CI_PREREQUISITE_REVIEW01.md. The legacy private-smoke receipt
actually passed and its cycle source retains ledger.sqlite under the installation
source tree. The unchanged isolation preflight rejects such a mount before Popen.
Reordering removes that obstruction. The isolated test's own controller database
and Parent public overlays are outside the mounted installation source, so its
completion does not introduce the reverse dependency into subsequent legacy tests.

Use a fresh hosted job. Preserve the failed run44088764296 and all its available
fixed public results. If the new job exposes a real hosted namespace/procfs or
other prerequisite failure, diagnose that new evidence; do not suppress controls
or label a skipped private test successful. This source review executed no child,
proof, build or namespace control. The separately allocated public discriminator
is additional evidence, not required as a substitute for actual hosted CI.


## Actual public ordering discriminator

Read CI_SOURCE_TREE_CONTROL01.json SHA256
`c355d548936020a6cc2966bff04f5be9caab136b1a4101803d0924fe126680ad`.
Its inline public source imports unchanged isolation.py and actually compares a
clean synthetic source directory with the same directory after creating a harmless
8192-byte SQLite file at the legacy cycle's relative path. Actual exit0,
0.041866702s total: clean accepted; database-bearing tree rejected with
ValueError('no database in wallet mount'). No wallet/native/proof subprocess was
launched by that control. The workflow digest in its receipt is the concurrently
reordered candidate, not the old failed workflow. This confirms the specific
source-order obstruction, not the sanitized historical first exception.

## New CI44090899086 failure and next discriminator

Read the fixed failed02 public receipts. The reorder progressed to an actual
wrapper child: first wait4 exit1 after0.065790911s, no fixed actor failure stage,
zero events/proofs/native CLI calls/sampling epochs and stable source/runtime.
This is a distinct post-Popen startup failure. No exact namespace, kernel or
runtime cause follows from these sanitized records. The ordering repair remains
valid; actual hosted wallet acceptance remains absent.

Recommend one public-only preflight after tool provisioning and before build:
import unchanged isolation.py, use its network_filter and command with the same
namespace/seccomp policy, fresh minimal public fixture mounts, cwd=/tmp and fixed
/usr/bin/true. Close unrelated FDs, pass only the filter FD, bound execution10s
and each output stream8KiB, clean/reap the process group, and retain exact command,
source digest, exit/signal/timeout plus public stderr in one fixed always-uploaded
JSON. A nonzero result fails the job; do not skip the private test, relax host
restrictions or expand mounts to achieve a pass.

This probe distinguishes failure of the namespace/root setup and system loader
from later Node-specific requirements. It cannot by itself attest the wallet's
actual runtime mount closure or live descendant observation. If true succeeds,
a separate harmless Node --version probe through the same command and explicitly
selected runtime mounts may discriminate those remaining startup requirements.
Never expose the real actor's stderr/raw streams to obtain that diagnostic.
No new execution was performed by this review.


## Public preflight source review

Read ci_preflight.py and the workflow addition. The only subprocess commands are
fixed /usr/bin/true and the explicitly SHA-pinned official Node24.22.1 --version.
Both use unchanged isolation.command/network_filter, no writable/project-tree
mount, a minimal public environment, close_fds with only the filter FD passed,
4GiB AS, CPU0, no core dumps and first-wait4 process-group cleanup. Per-stream
capture is capped8192B, overflow fails, and output is checked against the exact
empty/Node-version values with empty stderr required for success. Public stderr
is retained only for these no-secret commands. Sysctl access is read-only; no
host restriction is modified and no wallet/private actor is invoked.

Workflow placement is before prepare/build and after declared tool provisioning.
The exclusive receipt .work/ci-isolation-preflight.json does not pre-create the
setup label .work/ci01. The always-upload allowlist adds exactly that public JSON;
all actual wallet and legacy checks still remain required after a passing preflight.
A passing public probe is explicitly scoped to startup, not the complete wallet
mount closure or full isolated payment acceptance.

One narrow source correction requested before freeze: enforce the10s deadline
when terminal status is observed and when assigning final pass. The initially
reviewed loop checked terminal status before elapsed time, permitting a terminal
first observed beyond the declared deadline to be classified successful. This is
a diagnostic bound issue, not an isolation-policy bypass. Retain the actual exit
and resource evidence on that failure. The source otherwise has no material
review finding; final digest/control readback follows the author's correction.


Final source readback resolves the deadline finding: the inclusive final
wall_seconds, including cleanup/drain, now sets timeout when it reaches10s before
pass assignment. **Source GO** for ci_preflight.py SHA256
`e4a245ed6f31a314e10ab50a12f0e498cf5741718ae33d321b6b6d911f0619ee`
and workflow SHA256
`bdf722494b046a7ccde2412c9c74902f5f6bb682af5dbd26b0f5f31585f74f6a`.
No remaining material source finding. This reviewer performed source inspection
only; local author controls and actual hosted preflight/CI are separate outcomes.


Read the author's actual final local public control CI_PREFLIGHT_LOCAL02.json,
SHA256 `543e6e1e2f8ed2861dc51bf657f25704f4e144253220c9415c82f4aee7522d58`:
both fixed probes exit0/first_wait4, exact expected stdout, empty stderr,
no timeout/overflow; true0.016009982s and Node0.019177161s. Exact final script and
unchanged isolation pins match before/after; official Node hash matches before/
after. The source GO stands. This is a local result with the recorded local
kernel/sysctls, not proof that the hosted runner permits the same namespaces.
The earlier pre-correction local receipt remains separately preserved; no private
or genuine proof test was added or relabelled by this diagnostic.


## Actual hosted preflight — external prerequisite not satisfied

Independently read run44092592703 at revision ef9262a's public receipt, SHA256
`9ce0c4cfaab5f97b249b4a7a8aeca297cf91f05049c4fecadc8a0e44c5ece6bf`. The unchanged fixed /usr/bin/true sandbox exits1 after
0.004740970s with first-wait4, empty stdout, no timeout/overflow and public stderr:
`bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`.
Only one probe ran; Node, compilation and wallet/proofs did not run. Source pins
are stable. The hosted record reports userns_clone=1, AppArmor unprivileged-userns
restriction=1 and a nonzero namespace limit. The local final control used the same
isolation/preflight source and identical bwrap/true binaries, passed, and recorded
restriction=0. The environments also differ in kernel and other host properties;
this is not a controlled proof of a unique AppArmor cause.

The observed blocking prerequisite is precise: this hosted environment does not
permit the selected unchanged sandbox to configure its isolated loopback address.
It is not a payment-proof failure, Node-runtime failure, missing-binary error or
wallet result. [Ubuntu24.04 release notes](https://documentation.ubuntu.com/release-notes/24.04/#unprivileged-user-namespace-restrictions)
document that its default restricted unprivileged-user-namespace policy can allow
namespace creation while denying subsequent capabilities. That is consistent with
the observation, but no actual kernel/audit denial establishing AppArmor as the
unique cause was captured. Preserve that uncertainty and all preceding failures.

No further identical hosted retry, native rebuild, proof campaign, crypto change
or wallet workaround is justified. The meaningful remaining work within this
milestone is preserving the fixed failure evidence, recording exact supported
runner prerequisites and pending criterion6, and a resumable public handoff. The
existing independent local build/private/public acceptance remains valid at its
stated environment and scope. Publication of source does not turn failed automatic
CI into a pass or complete this milestone's delivery requirement.

Resume first with this exact public preflight on an independently approved,
properly provisioned supported runner that already permits the required sandbox
operations. If it passes, run the unchanged automatic build/provider/public/private/
wallet checks and retain their actual results. Merely naming a different runner,
using an optional server or copying an old successful receipt does not satisfy
that gate. Do not remove namespace isolation, disable host restrictions, broaden
host access, suppress failures, or launch a new CI-infrastructure project as an
implicit part of this narrow repair. Runner provisioning/selection remains an
explicit prerequisite decision for Root/owner, not a claimed completed action.
