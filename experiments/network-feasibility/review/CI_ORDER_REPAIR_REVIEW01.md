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


## Reassessment: one supported alternate-host trial

**GO for one public-only Ubuntu22.04 hosted preflight with the unchanged script,
isolation policy and official Node digest, before any build.** Choosing another
ordinary supported runner within the existing automatic workflow is routine CI
compatibility work authorized by the delivery objective. It need not create a
new service or infrastructure project. The prior external-prerequisite disposition
must not be read as forbidding that discriminating trial or requiring a separate
owner permission merely to select a supported runner.

This changes the host premise while keeping the tested boundary: same user/PID/
mount/network/IPC/UTS namespaces, capability drop, fixed seccomp, empty host-root
policy, FD handling and fixed public commands. Keep the10s per-probe/8KiB per-stream
limits, record actual host/kernel/bwrap/runtime/source identities and preserve
both earlier hosted failures. Do not change a host restriction, request privileged
exceptions, suppress a failure or replace the real private tests with the probe.
A host label is not a cryptographic/security guarantee; the exact unchanged
controls and actual receipts determine the limited result.

Passing this public startup probe would justify separately allocated fresh runtime
discovery/approval and the existing actual CI checks. It would not transplant an
old installation approval, establish the complete wallet mount/observation
boundary or complete criterion6 by itself. An exact project-local libcrypto is
compatible with this approach only if the existing explicit installation mechanism
captures its identity and real loaded dependency closure, with genuine provider
checks still mandatory. No system-library overwrite, global loader setting or
permission relaxation is implied. The separate source review of that dependency
path remains required before a native build. This review started no host trial,
build, private process or new proof campaign.


Reviewed environment-probe.yml SHA256 `cbc42b0fee3749fb07bde88847f8191029b90bb3a0daf007dde00169c67f71d2`: **source GO**.
The manual-only Ubuntu22.04 workflow uses the same pinned checkout/upload actions,
contents:read and no persisted checkout credentials. It provisions only ordinary
public startup prerequisites, verifies the official Node archive checksum, invokes
the unchanged fixed preflight and always uploads exactly one public receipt. It
has a5-minute job guard in addition to the script's per-probe bounds, performs no
build/proof/private test, and changes no host restriction or isolation policy.
A diagnostic-only commit using [skip ci] avoids an identical known-unsupported
Noble automatic attempt; it is not an automatic acceptance result. Dispatch this
probe once and inspect its actual receipt. A manual diagnostic pass cannot replace
successful automatic push/PR smoke or complete the milestone.


## Conditional Noble userland on a supported alternate host

Source/design assessment only; no rootfs experiment was run. A pinned official
Noble userland inside project-local storage, entered through unprivileged bwrap on
a host that passes the unchanged public namespace probe, is a potentially coherent
environment repair. It leaves the payment relation and inner wallet isolation
policy unchanged. The host still supplies the kernel; an image label alone proves
neither kernel compatibility nor security equivalence.

Conditional GO requires one namespace-consistent installation: explicit official
archive digest/provenance; setup/discover/install/build and all public/private/
wallet checks run inside that same outer rootfs; fresh approval of actual loaded
runtime files and new ELFs; genuine provider checks; and actual Source04 nested
process/mount/FD/namespace readback. The inner wallet /usr must be the selected
Noble /usr. A host-side hash of identically spelled /usr paths is not a hash of
those installed files. No old installation approval or host library/tool fallback
may fill a missing rootfs dependency. Bind only explicit needed project/tool
surfaces; no broadened inner host-root mount is warranted.

The next discriminator, if the alternate-host public probe passes, is public-only
nested startup and exact Node/OpenSSL identity in the proposed environment before
compilation. This is not permission to repeat264 private proofs. Provisioning must
remain one bounded environment recipe/workflow with declared dependencies and
failure receipts. If package ownership/setup requires host privilege, weakened
loader/source checks, privileged containers, policy changes, a package-manager
emulation layer or ongoing service machinery, stop and report the specific
obstruction rather than expanding this milestone into CI infrastructure work.
The practical single-UID provisioning and exact rootfs source still need author
verification; this is conditional design acceptance, not an implemented-source or
runtime PASS.


Read actual Ubuntu22 public diagnostic run44094941105 at6542294, receipt SHA256
`3bcbc6bf593fa40bb93f57060defff1f2c25f57fd31b61a2be86c650b635353d`.
Both unchanged probes pass: true0.007580535s and Node0.014726646s, first-wait4 exit0,
exact stdout, empty stderr, no timeout/overflow, stable source and official Node
identity. This supports the proposed one bounded provisioning/nested-public-probe
step. It is not a Noble rootfs result, fresh native installation or full automatic
payment smoke PASS; those boundaries remain outstanding.


## ci_noble.sh preparation-source review

Read the proposed two-mode wrapper, including candidate2199c556. It selects a
fixed official Ubuntu base archive digest, leaves apt signature verification and
its default sandbox/dpkg behavior unchanged, clears the guest environment and
imports only the repository, explicit read-only Rust directories and prepare-only
DNS configuration. The guest run mode uses a read-only rootfs and new network
namespace, with the repository's writable rootfs alias masked empty/read-only.
No host /usr or host library tree supplies the guest runtime. Root UID inside the
new user namespace is not host-root permission.

The corrected candidate requires Python>=3.11, OpenSSL CLI3.0.13 and actual loaded
libcrypto version(3,0,13), then runs the unchanged public nested preflight before
READY. It invokes no compiler or private actor in prepare. Its quoted dpkg-query
format is literal. The saved inventory hash authenticates that metadata file,
not the current contents of every rootfs file; fresh runtime discovery and provider
checks remain mandatory before installation acceptance.

Requested one final small guard: canonical nonsymlink .tools/.work parents and
nonsymlink run inputs, since fresh leaf checks alone permit redirected parents.
No such redirection was observed; this closes the stated project-local path
contract. Otherwise the design supports one externally time-bounded public prepare
pilot. Actual default single-UID apt feasibility remains unproved; preserve any
failure rather than forcing ownership/signature/sandbox exceptions. No wrapper
execution or dependency installation was performed by this reviewer.


Final wrapper SHA256
`bc47bc40a889106301ddb2495a666aec3ed96d2488f48baf10a7038a86828a2b`
resolves the path finding: both modes reject redirected/noncanonical existing
.tools/.work/rootfs/record directories and symlink READY/base/inventory metadata.
The inventory-integrity qualification is explicit. **Source GO for one externally
bounded prepare-only public pilot**, not a native build or wallet result. The
source has not established that default apt works in this single-UID mapping;
that is the pilot's discriminating question and a failure must remain fail-closed.


## Rootless provisioning failure and distinct administrative preparation option

Read the actual allocation35 provision-public.log: default apt fails changing
supplementary groups/GID65534 and UID42 (_apt), including setgroups EPERM and
setegid/seteuid EINVAL. Root reports terminal100/5.8316s and no READY; this is a
failed single-UID provisioning attempt, not a proof/runtime acceptance. Preserve
that label/log and do not silently rerun it with altered apt sandbox semantics.

**Conditional design GO for one fresh public hosted administrative preparation
pilot.** The prior rootless-only restriction was an experiment guard. It is not
an owner requirement that all dependency installation be unprivileged. GitHub's
[hosted-runner documentation](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
explicitly supports passwordless sudo for installing tools. Normal signed apt in
a freshly pinned project-local chroot on the disposable Ubuntu22 VM can be a
separate trusted provisioning role, while all subsequent runtime discovery,
approval, build, nested probes and real wallet checks retain the original
unprivileged host caller and unchanged bwrap boundary. This is not an exemption
from the denied Ubuntu24 namespace policy.

Minimum source controls for that narrow successor: canonical nonsymlink fresh
rootfs and exact archive; privileged execution limited to a fixed package-prepare
command, never the entire wrapper/run mode or a private actor; cleared environment
and no keys/credentials; no repository/Rust/host-root/proc/sys/run or service-socket
bind into the privileged chroot; default signed apt and _apt sandbox behavior;
public exit/log and actual package inventory; completed provisioning followed by
an explicit non-root host-identity check and unchanged nested public preflight.
Keep version/provider/loaded-runtime gates exact and obtain a new installation
approval. A native build or private campaign is not approved by this design note.

A chroot is not a security sandbox against root. Signed package maintainer scripts
are trusted administrative provisioning code in this disposable VM, comparable
to the already used hosted apt step. Do not describe the operation as unprivileged
or permission-confined merely because files are under .tools. No host restriction
is disabled, no privileged wallet is permitted, and no broad host/service access
or runtime fallback should be introduced to rescue a failed pilot. The prior
single-UID failure remains preserved; this explicitly reviewed successor changes
the provisioning role only. No administrative operation was performed by reviewer.


## Administrative preparation successor — exact source GO

Read all127 lines of ci_noble.sh SHA256 `d4099b43d9d2e612c54d344e8acb703992aeed85854b1651365a984cc3e8c82e`. **Source GO for one externally
bounded hosted prepare-only pilot**, not for native compilation/private execution.
Both modes reject a root host caller. Only the fixed prepare heredoc uses sudo-n
with a cleared environment: it creates four standard device nodes in the fresh
image, installs image-only policy-rc.d exit101, and invokes fixed chroot/default
signed apt commands. No privileged mounts, host proc/sys/run sockets, repository
or Rust bindings are present in that administrative block. mknod failure, apt
failure or nonzero status stops before READY; public provision status/log are
retained. The rootless failure is not overwritten by this successor.

After provisioning returns, non-root host UID/EUID are explicitly recorded.
All inventory, actual Python/OpenSSL CLI/CDLL version checks and nested public
preflight use the original unprivileged-host bwrap path: read-only guest root,
network namespace, explicit read-only Rust directories, cleared environment and
masked writable rootfs alias. Only successful exact gates produce READY. The
run mode cannot invoke sudo, accepts no privileged fallback, and remains subject
to fresh actual runtime discovery/approval. Namespace UID0 is distinct from a
root host caller. No inner wallet/proof/provider/security parameter changes occur.

The image-only service-start denial is an explicit standard provisioning setting,
not a host policy change. The privileged chroot is trusted package preparation,
not claimed to confine malicious root code. Official archive identity and apt
verification remain essential trust premises. Actual package/rootfs compatibility
and all later CI results remain unverified until their allocated executions.
Reviewer executed no sudo, chroot, package installation, native job or proof.


Reviewed companion environment-probe.yml SHA256 `23a4460aed2772b97ea60539c0c94cfdc0652392a176612a3096d1bdfb22bbce`: **source GO with that
wrapper for the same single public hosted pilot**. It remains manual-only,
contents:read, pinned checkout/upload actions, no persisted checkout credentials,
Ubuntu22 and no build/proof/private commands. The unchanged host public preflight
must pass before preparation. Preparation has GNU timeout360s with10s kill-after,
inside an8-minute job bound. The always-upload list contains only the fixed host
and nested preflight records plus public base/package/provisioning/identity logs.
No rootfs, database, credentials or arbitrary tree is uploaded. This adds no
host-policy relaxation and is not final automatic acceptance.


## Hosted administrative prepare failure: archive permission restoration

Read actual run44100085183's provision-public.log. Each downloaded InRelease is
followed by inability to create /tmp/apt.conf.* for apt-key. Apt then reports GPG/
unsigned-repository errors and stops. This establishes a temporary-config failure
before successful repository authentication, not a demonstrated invalid upstream
cryptographic signature. Do not bypass signature verification or the _apt user.
The historical hosted /tmp mode was not captured.

The reviewed extraction command used --no-same-permissions. Root's separately
reported exact-archive/local-extraction control found archive tmp and var/tmp01777
but extracted directories0775, consistent with the command's umask behavior.
The smallest coherent packaging correction is --same-permissions on the already
SHA-verified official base archive, retaining --no-same-owner, then public record
and assertion of exact01777 ordinary nonsymlink tmp/var/tmp directories before
any privileged package provisioning. This restores the selected image metadata;
it is not a host/tmp permission change or an apt trust-policy exception.
A fresh hosted prepare remains necessary; no local crypto/native rerun is useful.


Final permission successor SHA256
`3b29531619e25c9a3863083a5cc03eee0eb1f145f14beeddea0c5375a159a33e`:
**source GO for one fresh bounded hosted prepare retry**. Read the exact change:
verified-archive extraction preserves permissions and the pre-sudo Python lstat
guard records/requires tmp and var/tmp to be ordinary directories with exact01777.
A symlink cannot satisfy S_ISDIR on lstat. No signature, apt sandbox, host/tmp,
provider, runtime or private-test requirement changes.

Read the author's tiny public control source and actual RESULT SHA256
`576ecdb77338fd59ef059c5275c1910b8816571f288bbc38666b19eec60b32e2`:
actual GNU tar under umask0002 produces0775 with old flag and01777 with corrected
flag; the exact extracted wrapper guard rejects the former and accepts the latter.
Both commands exit0, the complete control passes in0.011674651s, and wrapper pins
are unchanged. It uses a synthetic directory archive, not a new hosted apt run;
that scope is explicit. The old failed image is not rewritten. Preserve the new
image-temp-permissions.json in the workflow's fixed public upload list so the next
hosted result has actual mode evidence. Reviewer performed no control rerun.


## Conditional full automatic Noble-userland workflow candidate

Reviewed .work/network-delivery01/smoke-noble-candidate.yml SHA256
`14a01f3d834e54a691f243feef6351916d878af32dde10b7cc556d31781978e6`.
**Conditional source GO**, effective only after the corrected public hosted
prepare/nested-preflight actually passes and Root allocates the fresh automatic
CI run. This file is a candidate, not an executed workflow or successful delivery.

A mechanical comparison confirms all three inner command blocks are unchanged:
prepare/discover/approve/install/build; isolated small5; legacy public53CLI,
private3proof and witness checks. The only wrappers around them are quoted
heredocs through ci_noble.sh run, so HOME/PWD and runtime approvals are evaluated
inside Noble rather than expanded by the host shell. Each inner shell retains
set -euo pipefail and failure propagates through bwrap; no test is skipped or
converted to optional. Required order remains fresh build, isolated wallet, then
legacy source-mutating private smoke.

The host changes to Ubuntu22, retains exact Rust1.99.1 provisioning and verified
Node archive, and runs the unchanged host public preflight before the bounded
Noble preparation. Compiler/system SSL development packages move to the declared
Noble apt preparation rather than becoming host library fallbacks. The wrapper
preserves the host HOME and explicit Rustup/cargo-bin paths at the same guest
locations read-only. The build still selects $HOME/.cargo/bin/cargo under that
guest; fresh build/runtime checks must detect any real toolchain incompatibility.
All installation, runtime mapping, provider, private and public checks remain in
the same rootfs namespace. Interpret /usr hashes in that namespace, not on the
outer host merely because a path has the same spelling.

Automatic push/PR and manual triggers, contents:read, pinned actions, no persisted
checkout credentials and the20-minute job bound remain. The fixed always-upload
list adds only base/provision/package/identity/public-preflight records, including
image-temp-permissions.json. No rootfs, DB, private stream or arbitrary directory
is uploaded. Actual nested process observation and complete genuine checks are
still mandatory; a provisioning pass does not establish them. No reviewer build,
proof or workflow execution occurred.


## Provisioning success, nested UID-map failure

Read actual hosted run44101616123 records: package provision exit0, both image
temporary directories01777, post-provision host UID/EUID1001, Python3.12.3,
OpenSSL CLI and loaded library3.0.13. Its nested public preflight observes outer
namespace UID/GID0 and fails the first true probe with
`bwrap: setting up uid map: Operation not permitted`, exit1/0.004467813s.
No Node probe, native build or private wallet passed at this stage. Earlier apt
failure is resolved in this attempt; do not conflate it with the new failure.

Mapping the outer runtime to the actual ordinary nonzero caller UID/GID is a
legitimate narrow candidate: administrative package preparation no longer needs
that runtime namespace to be root. It does not add a capability or change the
inner wallet's namespace, cap-drop, seccomp, mount, FD or process-observation
checks. The [Linux user_namespaces manual](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
describes extra CAP_SETFCAP conditions for mappings of parent-namespace UID0
since Linux5.12. This supports testing the identity distinction, but is not proof
that this precise hosted denial arose from that rule. No CAP_SETFCAP exception,
privileged runtime or host policy change is warranted.

Conditional design GO for the already allocated public0-versus-ordinary-UID
matrix and subsequent exact-source review. Preserve actual identities/maps and
all failure receipts. Passing that control would support one corrected public
hosted nested-preflight attempt; it would not establish complete wallet/runtime
acceptance. No reviewer execution or new privilege request occurred.


## Actual UID matrix and exact ordinary-UID successor

Personally read NESTED_UID_CONTROL01.json SHA256
`e2d2899ddcf2b4dea9ae90af15ef80a045ce69783c87241cfbc546648c513e5e`:
the two actual public cases total0.629859452s. Explicit outer UID/GID0 reproduces
nested uid-map EPERM; explicit ordinary UID/GID1000 passes both unchanged true
and official Node-version probes. Both outer observations report zero effective,
permitted and bounding capability masks. Actual namespace identities/UID and GID
maps, exact inner commands, terminal statuses and stable source hashes are
retained. This is a local host-/usr control, not a Noble hosted result or uniquely
instrumented attribution to a specific kernel permission rule.

Read the successor ci_noble.sh SHA256
`7b332a5c875b861faa9606530a62463fb588d741f89f778a7c908fc9ff2fc2b9`.
Mechanically replacing its sole `--uid "$UID" --gid "$(/usr/bin/id -g)"` occurrence
back with `--uid 0 --gid 0` reconstructs the exact prior approved wrapper digest
3b295316...33e. Thus no other provisioning/run/runtime/inner-policy change is
hidden in this successor. The ordinary caller is selected explicitly rather than
assuming untested defaults; the host-nonroot guard remains. No capability is added.

**Source GO for ONE fresh bounded public hosted environment pilot.** That pilot
must still demonstrate actual Noble ordinary-UID nested startup before a full
native automatic CI allocation. No private job, provider shortcut, policy
exception or new review framework is authorized by this finding. Prior failed
hosted and rootless attempts remain unchanged. Reviewer ran only read/hash/source
comparison, not the public matrix or any namespace/crypto campaign.


Conditional full-automatic source disposition reaffirmed for the unchanged
candidate14a01f3d...1978e6 with ordinary-UID wrapper7b332a5c...fc2b9. Rechecked
both exact current identities. The earlier complete inner-block comparison and
workflow review remain applicable; the wrapper successor changes only the
reviewed outer UID/GID selection. **Conditional GO for one full automatic run
only after actual hosted environment pilot44103979712 passes and its public
receipts are read back.** A running pilot is not that result. No new source
finding, additional maintenance scope or reviewer execution was introduced.


## Actual hosted ordinary-UID Noble pilot — full automatic run GO

Independently read downloaded pilot44103979712 at29e7e0e's fixed public records.
Base receipt binds exact official archive and wrapper7b332a5c...fc2b9. Both image
temporary modes are01777; provision exits0, post-provision caller UID/EUID1001
and sudo_used_for_run=false. Actual Python3.12.3, OpenSSL CLI3.0.13 and loaded
libcrypto(3,0,13) pass. Saved package inventory agrees with its recorded SHA256
`e894e76f4c6843fb2b0215d0b00bc8ded1ec92ab5ad43b57fe266a3ed891a22c`.
This validates inventory metadata consistency, not a full rootfs content attestation.

Nested public-preflight receipt SHA256
`7231b2d29d22eb40727a236d181281a509c679002a111b27f5cef2be45b8c93d`
observes UID/GID1001 and passes true0.006835119s plus official Node0.010680202s.
Both retain first-wait4 exit0, exact stdout/empty stderr, no timeout/overflow,
stable source/Node identities and the actual inner cap-drop ALL, user/network
namespaces and seccomp arguments. The separate outer host preflight also passed.
No Node version result is mistaken for a private wallet or native provider result.

**GO for ONE full automatic CI using the previously reviewed unchanged candidate
14a01f3d...1978e6 and wrapper7b332a5c...fc2b9.** The candidate's public preparation
condition is now supported by actual hosted evidence. Fresh runtime approval,
new native build/provider checks, genuine isolated small5 and every retained
legacy public/private/witness check still must execute and pass. This is not
criterion6 completion, a whole-protocol theorem, or permission to skip a later
failure. No reviewer execution or extra campaign was performed.
