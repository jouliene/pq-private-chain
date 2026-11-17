# Hosted isolated-wallet failure — first bounded diagnosis

Status: source/artifact diagnosis and fix proposal only. No canonical source,
workflow, manifest or installation was changed; no build, proof, namespace or
wallet process was run for this investigation.

## Established observations

Hosted push CI44088764296 tested public revision
`c5e2f36ddb6c225e7d4c17363ffe0eeba93ce49f`. Retained artifacts are under
`.work/network-delivery01/ci-failed01/`. Build, public replay, old fresh-private
smoke and witness probe passed. The isolated-wallet result is FAIL/ValueError,
fixed reason null, with zero events, registered proofs and native CLI calls.
Its original-process record has zero sampling epochs and **no actual_wrapper**.
The claim was written and source/runtime postchecks passed.

`Actor.run` writes that record in `finally`; a returned child from Popen would
be reaped by `finish_wait` and obtain an actual_wrapper. Thus this points to
Actor.launch before a successful Popen return, not the later proc observer or
cryptographic actor boundary. The sanitized artifacts do not retain the exact
ValueError predicate. Missing first-stage metadata must not become a fabricated
hosted syscall trace.

## Deterministic sufficient cause from the exact step order

The failed c5e2f36 workflow runs `scripts/private_smoke.py --attempt private01` **before** the
isolated-wallet step, reusing the same installation source_root. That successful
receipt explicitly names:

```text
/home/runner/work/pq-private-chain/pq-private-chain/.work/ci01/source/
  experiments/cp03-private-cycle/evidence/private01.public/workload.json
```

`source/wallet/cp03/cycle.mjs:178` creates that output directory and line188 puts
the real public `ledger.sqlite` inside it. Its cleanup wipes private objects and
does not delete the public DB. The later witness probe consumes that workload;
it does not remove the DB. This is an execution/source correspondence argument,
not a direct read of the vanished hosted filesystem. Current known local fresh
Gate5 installations did not run this older private smoke first; no new private
run is necessary to reconstruct this layout condition.

`Actor.launch` calls `isolation.command(readonly_trees=[source_root, common],...)`
before Popen. `inspect_tree(source_root)` rejects every descendant name ending in
`.sqlite` (also .sqlite3/.db/-wal/-shm/-journal) with the fixed ValueError text
`no database in wallet mount`. The top-level result permits only lowercase/
underscore error codes, so this space-containing reason is deliberately reduced
to null. That failure shape matches the hosted result. Other earlier allowlist
predicates remain possible as the *first* actual failing predicate; the artifact
does not distinguish them. The generated DB is nevertheless sufficient to make
that failed workflow ordering fail this unchanged policy.

The public replay's own databases are under workspace/public01-work, outside
source_root. The old private cycle is the identified contaminating step.

## Minimal fix proposal

Move the existing complete **Isolated local witnesses and backup-only
fresh-process spend** step immediately after successful installation/build and
before **Genuine public and fresh private checks**. Keep every command, approval,
namespace option, mount/tree check, live PID/FD/socket check and artifact retention
unchanged. The new isolated wallet writes its ledger outside source_root and
uses already-reviewed fresh public/evidence overlays. Its public proof outputs
are permitted regular files; they do not create an in-source DB. Later public
replay/private smoke/witness checks still execute and retain their own outcomes.

Do not allow databases into the wallet mount, skip inspect_tree, move/remove an
existing evidence DB to conceal the issue, disable AppArmor/usernamespace policy,
remove outer isolation or weaken runtime identity. Reordering is a workflow
dependency fix, not proof that the hosted kernel supports the full namespace
boundary. A subsequent hosted failure still needs its own preserved evidence.

## Proposed public-only discriminator before a genuine retry

Use unchanged `isolation.command` on a fresh tiny public tree: construction must
succeed while clean; then create a real synthetic SQLite at the exact relative
legacy output path and require the exact tree-policy ValueError. Do not invoke
the returned argv or Popen. Suggested bound: CPU0,128MiB AS,5s wall, zero child,
native or proof jobs. Retain an exclusive receipt with source pre/post hashes and
fixed outcomes; retain the public test DB. This distinguishes command-construction
policy from unsupported hosted namespaces without weakening either.

Executable proposed body (not executed by this review):

```python
from pathlib import Path
import hashlib, importlib.util, json, sqlite3

base = Path.cwd() / 'experiments/network-feasibility/wallet-integration'
path = base / 'isolation.py'
digest = lambda: hashlib.sha256(path.read_bytes()).hexdigest()
before = digest()
spec = importlib.util.spec_from_file_location('fixed_wallet_isolation', path)
isolation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(isolation)
work = Path.cwd() / '.work/ci-wallet-order-discriminator01'
work.mkdir()
source = work / 'public-source'
source.mkdir()

def construct(fd):
    return isolation.command(readonly_trees=[source], readonly_files=[],
        writable_public_trees=[], cwd=source, argv=['/usr/bin/true'], filter_fd=fd)

with isolation.network_filter() as fd:
    clean = construct(fd)
    db = source / 'experiments/cp03-private-cycle/evidence/private01.public/ledger.sqlite'
    db.parent.mkdir(parents=True)
    with sqlite3.connect(db) as connection:
        connection.execute('CREATE TABLE public_control(value INTEGER NOT NULL)')
        connection.execute('INSERT INTO public_control VALUES(1)')
    rejected = False
    try:
        construct(fd)
    except ValueError as error:
        rejected = str(error) == 'no database in wallet mount'
    after = digest()
    result = {'format': 'CP04-CI-WALLET-ORDER-DISCRIMINATOR01',
              'passed': bool(clean) and rejected and before == after,
              'clean_command_constructed': bool(clean), 'database_tree_rejected': rejected,
              'source_before': before, 'source_after': after,
              'child_or_native_jobs': 0, 'returned_command_executed': False}
    with (work / 'RESULT.json').open('x') as output:
        json.dump(result, output, sort_keys=True, indent=2)
        output.write('\n')
    assert result['passed']
```

This establishes the precise public layout discriminator only. Root should review
the minimal workflow reorder and rerun hosted CI under a new immutable revision.
All original failure receipts remain FAIL. No264-proof regeneration or unrelated
component replay is justified by this pre-child ordering defect.

Root integration note: the separate executed public discriminator is
CI_SOURCE_TREE_CONTROL01.json; do not run the unused proposal again. The exact
workflow-only repair is independently reviewed in CI_ORDER_REPAIR_REVIEW01.md.
