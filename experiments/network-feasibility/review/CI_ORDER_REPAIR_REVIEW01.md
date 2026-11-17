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
