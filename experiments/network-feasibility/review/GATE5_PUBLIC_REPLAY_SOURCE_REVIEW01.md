# Gate5 public chronology source review

Disposition: **source GO**, conditional on Root freezing the exact three-file
PUBLIC_REPLAY_SOURCE manifest and on successful independent review of full01.
No replay/build/proof execution was performed by this reviewer.

Read complete public_replay.py
`ca27d58994db90607d757ed6ae1c2fb3473997594456c271c93a5cf97b6f810f`
and public_replay_controls.py
`ba592ee83d8028ea1924ecf2cac27ac7fc71a40732676e1d4808164c27230189`.
Confirmed current runner reuse and native check_scan output semantics against
source. The eight reported grammar/copy controls are author evidence; they are
not actual ledger replay or proof verification.

The input is an explicitly approved bounded public closure, not an old database,
Parent verdict, key, backup or membership service. Exact264 labels and expected
arities are fixed. Chain, CPGEN004, CPBODY03, declared statement/proof/auth sizes,
distinct artifact paths/digests and exact14 reference map are checked. Paths are
normalized relative, reject symlinks/escape, and files are copied through held
descriptors with size/hash/stability checks into an exclusive new directory.
The reference head/state is comparison-only; a new native ledger starts from
genesis and validates every admitted proof with the installation-selected program.

The fixed sequence performs both positive old-draft admissions before expiry,
255 changing-root rolling blocks, actual h2 root/count absence at tip258, the
typed Anchor rejection and unchanged all14 snapshot, refreshed old-note spend,
positive orphan-child admission before two rollbacks/replacement, a second typed
Anchor/all14 rejection, and final restored-spend admission. Counts are264 distinct
proofs/265 positive proof admissions,264 successful block admissions/four rollbacks,
two rejections and260 selected blocks. Full final head,261 bodies/cores,522 leaves,
516 nullifiers and canonical all14 state must match. Canonical comparison omits
only independent body_cache.catalog_id; retention/undo/anchors remain compared.

Native calls reuse Controller.native as an unbound method on an initialized
public-only Replay object. No Controller or Actor instance/private configuration
is constructed; actor is None. The existing held-FD/inode/hash invocation,
strict head/error decoding and first-wait4 recording remain active. Installation,
driver, runner and oracle are checked before/after execution.

The check-scan exception correctly uses common.run with the live parent's held
ELF descriptor, kept open until actual child completion/cleanup. It checks ELF
before/after, exact checked-scan fields against the newly observed selected head,
exit0/no stderr/no timeout, output size and exact scan/check bytes. Source confirms
check_scan writes original checked inner bytes with uniquely encoded lengths.
This public process path is distinct from the isolated wallet boundary; no claim
is made that a wallet can reach the controller's descriptor. Both calls and guards
must succeed in the actual clean environment.

No remaining source blocker was found. Root must still provide an outer execution
guard covering installation pre/post hashing and construction: the driver's900s
timer starts after initial installation loading, and postflight hashing is outside
its final replay guard. The native check-scan timeout is narrowed to remaining
whole seconds, with a post-observation guard; regular native calls retain the
reviewed watchdog/cleanup loop. This is bounded experiment supervision, not a
hard real-time guarantee.

The actual clean replay result remains required. Public replay cannot demonstrate
private journal restoration or secret lifecycle by itself; it complements reviewed
full01 private evidence and a new independently executed isolated small5 cycle.
