# CI prerequisite review — failed run44088764296

Scope: read-only workflow, private-smoke/cycle, wallet controller and isolation
source plus downloaded fixed public receipts for commit c5e2f36. No process,
namespace, proof, build or Git operation was executed by this review.

The failed wallet RESULT records ValueError with no retained fixed reason,
zero events/proofs/native CLI calls and unchanged source/runtime. The original
actor receipt has zero sampling epochs and no actual_wrapper record. Given the
reviewed Actor.run/finally path, this points to launch failure before a Popen child
was assigned. It does not establish a hosted namespace denial or recover the
sanitized exact exception clause. The successful earlier legacy private-smoke
receipt records actual exit0 and its source-root public workload path.

A concrete ordering defect exists independently of that missing exception text:

- The workflow runs scripts/private_smoke.py before the isolated wallet step.
- That script executes source/wallet/cp03/cycle.mjs. Its main creates
  experiments/cp03-private-cycle/evidence/private01.public under the approved
  installed source tree and creates ledger.sqlite there (lines178/188 of the
  inspected source). The successful cycle retains that public ledger.
- Actor.launch supplies the entire installed source_root to isolation.command.
  inspect_tree rejects any descendant ending in .sqlite/.db or SQLite sidecar
  suffix before building/spawning the bwrap command. Its fixed message contains
  spaces, so the controller's conservative reason allowlist records null.

Recommended smallest candidate repair: move the unchanged isolated-wallet step
immediately after prepare/install/build, before the legacy public/private/witness
step. Preserve every existing command, source/runtime approval, fixed artifact
upload, namespace/mount/seccomp/FD control and actual five-proof acceptance.
Do not delete the previous smoke evidence, exempt a database from inspect_tree,
mount more of the host, disable user namespaces or turn a failure into a skip.
A new fresh CI runner is required; merely rerunning the wallet step in the
already contaminated installation is not a valid test of the ordering fix.

A cheap discriminator, if needed, can exercise unchanged inspect_tree/command
construction on a synthetic public clean directory, then its .sqlite descendant.
No genuine wallet/native work is needed to demonstrate this pre-Popen conflict.
The exact historical exception remains unrecorded; successful new CI must still
establish hosted namespace/process observation compatibility and all real wallet
checks. AppArmor/user-namespace/procfs/affinity prerequisites remain possible
later failures, not established causes of this attempt. Do not preemptively
weaken them. Existing independent local acceptance is not invalidated by this
workflow sequencing defect; criterion6 remains pending actual successful CI.
