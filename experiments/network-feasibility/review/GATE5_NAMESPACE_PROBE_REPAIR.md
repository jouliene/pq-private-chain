# Gate5 namespace probe repair proposal

Status: narrow implementation completed under Root allocation30; independent
source review pending. No source manifest regeneration, private retry, native
operation or build was performed. Root owns final approvals and clone update.

## Actual discriminator and its limit

`wallet-integration/pid-namespace-probe/RESULT01.json`, SHA256
`3f4f1ff2ed50c6b95fc93dbf8d2931dea059d8c6cc7887d4a89c03b9c075436e`,
terminated0 in0.094498s. It preserved the reviewer's actual outer namespace argv
and called the actual fixed isolation command/filter and frozen probe `inspect`.
The outer controller was PID3, start86032965, namespace `pid:[4026532891]`.
Inside the wallet-like namespace, `/proc/3` was a harmless thread of TGID2,
start86032970, namespace `pid:[4026532897]`, equal to inner self and PID1.
Its root existed. The frozen assertion failed with the exact fixed reason
`host process root inaccessible`; both denied paths returned ENOENT, all three
live inherited-FD identity checks passed, all three sockets returned EPERM,
and Seccomp was2. The discriminator created no wallet keys or proofs.

This demonstrates a numeric-PID false negative, not leaked controller-root access.
The original clean small01 stored only a sanitized capability-stage failure, so
this does not recover its unrecorded exact failing clause or retrospectively
turn it into PASS. A new genuine small5 label remains required after review.

## Minimal identity contract

Replace the numeric-root-existence assertion with these mandatory conjuncts:

1. Public config supplies `controller_pid` (positive exact integer in the
   controller's own PID namespace) and `controller_pid_namespace`, read directly
   from `/proc/self/ns/pid` before launch. No legacy/default fallback.
2. The probe reads its own namespace links and `/proc/1/ns/pid`. The procfs PID
   namespace must equal its own PID namespace and differ from the configured
   controller namespace. A matching controller namespace or wrong procfs fails.
3. If `/proc/CONTROLLER_NUMBER/ns/pid` exists, it must equal the probe namespace;
   classify it `child_namespace`. A local thread is allowed on the same basis.
   If that lookup returns ENOENT, require the numeric `/proc` directory itself
   to be absent (using `lstat`, catching only ENOENT), then classify `absent`.
   Permission failures, live entries without readable namespace, mismatches and
   ambiguous observations remain fatal. Do not classify EACCES as absence.
4. External `run.find_node` still binds the actual descendant Node PID, approved
   executable inode and actual pid/mnt/net links. It additionally compares the
   reported controller namespace with its own actual link, the reported procfs
   namespace with the actual Node PID namespace, and the collision classification
   with its corresponding reported namespace/null field.

The fixed result replaces misleading `host_proc_root_denied` with:

```text
controller_pid: positive exact integer
controller_proc_namespace_excluded: true
controller_pid_namespace: "pid:[...]"
procfs_pid_namespace: "pid:[...]"
controller_number_classification: "absent" | "child_namespace"
controller_number_pid_namespace: null | "pid:[child namespace]"
```

The exclusion field describes the checked namespace contract; it does not claim
that an unrelated child-local `/proc/N/root` is absent or attest the entire host.

## Exact proposed edit boundary and live callers

Targeted `rg` over live Python/JS callers found three files:

* `wallet-integration/run.py`: `Actor.launch` writes both new required config
  fields instead of `host_pid`; `Actor.find_node` checks all identity conjuncts
  and replaces the old result field in its explicit public receipt allowlist.
* `wallet-integration/isolation_probe.py`: capture namespace links once; add the
  procfs/controller/collision checks above after unchanged path/FD/socket checks;
  return the fixed replacement fields. Use ordinary typed failures, not optional
  or bypass modes.
* `wallet-integration/isolation_control.py`: the standalone public launcher also
  produces the required config fields. Its existing external pid/mnt/net checks
  remain; cross-check the new fields for both top-level and descendant probe
  records before success. This is the live standalone caller, not a new harness.

`wallet.mjs` already forwards the probe result unchanged and checks Seccomp2;
it needs no edit. `isolation.command`, network filter, launch FD handling,
filesystem mounts, denied DB path/inode checks, public-only output allowlist and
all actual Node/prover sampling remain byte-for-byte unchanged. Historical
`freezes/`, `evidence/isolation01/` and the decisive discriminator are immutable.
Other `host_pid` fields describe external sampled process IDs and are unrelated;
do not globally rename them.

Root must preserve the exact failed source, approve the narrow successor diff,
update the experiment source approvals (including the public replay's run.py pin)
and update the clean clone coherently. Wallet/core/helper/runtime installation
pins and cryptographic code do not change; no core rebuild is expected.

## Bounded regression controls before a genuine retry

Use focused public namespace-check controls, not wallet/prover mocks:

* PASS: distinct controller namespace with child-scoped procfs and confirmed
  absent numeric entry; PASS: the same contract with a verified local process
  or thread using the controller's numeric PID.
* FAIL: own namespace equals controller even when the numeric entry is absent;
  procfs PID1 differs from self; a present collision reports another namespace;
  collision namespace read is EACCES; ENOENT lookup leaves a live numeric entry;
  config PID is missing/bool/nonpositive or namespace field is missing.
* FAIL: external consumer sees a forged controller/procfs/collision field or
  disagrees with the actual Node namespace. Both standalone and integrated
  consumers must exercise the same result contract.
* Preserve existing actual path, inherited DB-FD, socket, mount, Seccomp and live
  prover observation requirements. A verified local numeric collision cannot
  excuse failure of any of them.

The actual public discriminator above supplies the positive collision evidence.
It is not independent private-cycle acceptance. Root allocation and review must
precede a fresh clean small5 run; retain original small01 as failed.

## Implemented source freeze and control receipts

Only the three live files above plus dedicated `namespace_controls.py` changed:

| File | SHA256 |
|---|---|
| run.py | 3e99ecde6534fa1dceee15f02c0f6eb636659aacd13bf118cab5faf827477a75 |
| isolation_probe.py | f9352dcfb3dd62353fee7e212cdaa567c98ad9fd5f7aecffae8e6847da4c0c63 |
| isolation_control.py | 64199d4f41f9925df4565f8ea14f5859fca4cdeef12e87fe9c54a39b9b53c1b7 |
| namespace_controls.py | 6d6c40aeca36876c30b3d0aaeb2e6148a687bc3ff744459dd8260f17ff3a74b9 |

Both live consumers call the same fixed result validator in isolation_probe.py.
The runner loads it only at the actual private boundary, so importing run.py for
public replay does not load the probe or construct private configuration.

Preserved `review/GATE5_NAMESPACE_CONTROLS01.json` is FAIL: the one real
same-namespace rejection returned PermissionError on this host's PID1 read rather
than the control's expected ValueError. This was already fail-closed; no wallet
or child ran. The check now rejects equal controller/self namespaces before the
unnecessary PID1 read. `GATE5_NAMESPACE_CONTROLS02.json` then passed all27 controls,
terminal0, with before/after source equality. Its test-body wall is0.000498s;
process SELF is0.030034user/0.005005sys seconds, maxRSS18304KiB. The invocation
used CPU0,128MiB AS and an outer10s guard, and created no child jobs:

```sh
ulimit -v 131072
exec timeout --signal=TERM --kill-after=1s 10s taskset -c 0 python3 -I -B \
  experiments/network-feasibility/wallet-integration/namespace_controls.py \
  --output experiments/network-feasibility/review/GATE5_NAMESPACE_CONTROLS02.json
```

All four edited/new Python inputs also passed in-memory syntax compilation.
No historical result/source, isolation policy, wallet/core, installation,
approved manifest or clean clone was edited. Both controls receipts are retained.
