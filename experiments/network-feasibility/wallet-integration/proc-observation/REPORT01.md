# Public proc observation discriminator

One allocated public run, `public01/RESULT.json` (pinned by FILES01.json), reproduced
25EACCES observations under the unchanged wallet isolation.command policy: user/
PID/mount/network/IPC/UTS namespaces, dropped capabilities and the fixed seccomp
filter. Only harmless `/usr/bin/true` and Python sleep/self-exec children were
used, via Node's held-FD exec pattern. No key, backup, private wallet state,
proof generation/native build, FD contents or symlink targets were read.

**The campaign reached its10s budget and was killed/reaped; it is not a launch
PASS.**96was a ceiling, not an observed completion count.76child PIDs were sampled;
1220full public policy observations succeeded. The child actor did not emit its
terminal completion count, so actual completed launches are unknown. No budget
extension or second run was performed.

All25EACCES events had a pre-error stateR and captured starttime;23were at FD
 directory enumeration and2at FD identity stat. In19cases the immediate
post-error identity still had the same starttime and stateR. Nevertheless every
case then independently failed both the identity read and PID-directory lookup,
within0.053–0.578ms. No persistent/unreadable case remained in the bounded window.
No EACCES→later-full-same-PID success was observed. Raw records preserve operation,
PID/start/state before/after, each attempt and final disappearance. The permission
itself was never used as exit evidence.

This demonstrates why oneR/starttime snapshot after EACCES does not establish a
persistent restriction: harmless children showed the same pattern and then
vanished. It does **not** identify the exact kernel point (fork/exec versus exit
teardown), nor reconstruct the historical fate of the small02 helper, which was
killed by the safe abort. The original completed four-proof/receipt/spend work
stays separate from that failed restore-observation run.

## Primary evidence and limits of explanation

Linux documents different proc operations and access checks; readable stat
identity fields do not imply permission for all FD metadata. Stat stateR and
starttime describe snapshots, not an atomic policy observation. See the primary
[proc_pid_stat manual](https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html)
and [proc_pid_fd manual](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html).

Upstreamv6.8
[proc_fd_permission](https://github.com/torvalds/linux/blob/v6.8/fs/proc/fd.c#L315)
uses VFS permission checking with a same-thread-group exception. Separately,
[task_dump_owner](https://github.com/torvalds/linux/blob/v6.8/fs/proc/base.c#L1707)
selects proc ownership using effective credentials, dumpability and whether the
task still has an mm. These show that FD/proc visibility is not decided solely
by the state letter. They are explanatory source context, not an instrumented
trace or exact-source attribution for this Ubuntu6.8.0-149patched kernel. The
[official proc documentation](https://www.kernel.org/doc/html/latest/filesystems/proc.html)
also warns that open proc entries do not prevent PID reuse. No ptrace, permission,
dumpability or namespace control was changed in this investigation.

## Correction implications

A runner/reviewer-approved tiny fixed deadline/attempt cap can restart the
**whole** policy observation for the same captured PID/starttime. It can conclude
only full unchanged-policy success or separately confirmed same-identityZ/X or
identity-plus-directory absence. Partial pre-error checks cannot be reused.
Persistent live/unreadable, ambiguous or changed-identity results remain fatal;
no identity rebinding, FD-check omission, inherited partial success, permission
loosening or retroactive PASS is justified. A retry can still miss very short
processes, so mandatory proof-worker observation and descendant isolation evidence
remain separate acceptance requirements. Root and the runner author/reviewer own
any fix; this directory changes no runner/security code.
