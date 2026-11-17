# Independent local-witness bridge contract review

Reviewed author contract SHA256:
`0b966fe0eff564d79c12d54d9e122e73051bce9df65d05d99bdc37a5088e7afa`.
Scope: source/design review against current `recovery.mjs`, `keys.mjs`,
`payments.mjs`, `private_prover.mjs`, `cycle.mjs`, receipt/hash adapters, native
hash helper, ledger tree framing and `wallet-witness/stream.py`. No native job,
new proof, private fixture or repeat of closed controls was executed.

Disposition: the bridge is a technically coherent implementation direction,
conditional on actual Gate2 retention. It is not ready to claim atomic rewind
or oracle-free acceptance until the following precise requirements are closed.
Root owns any prototype correction; this review does not modify implementation.

## Material findings and smallest corrections

**B1 — Deep selected-branch rewind does not currently revoke stale state.**
`WalletWitnesses.rewind` searches its journal and raises `ReplayRequired` before
aborting `active_epoch` or changing `revision`. Concrete source counterexample:
with R=1, commit H1 then H2, start/apply an epoch for old-branch H3, then select
genesis as the replacement common prefix. Genesis is outside the journal;
`rewind(genesis)` raises, but that epoch still has the current revision and can
`finish()` successfully. Even without an epoch, the old committed witness/spend
view remains callable. This is a concrete integration hazard, not a challenge
to the selective-frontier hash algorithm. Root has acknowledged the finding and
owns its small public structural reproduction.

On an authenticated selected-branch change, revoke the old revision, active
epoch and borrowed spend capability before journal lookup. If replay is needed,
mark the joint wallet **not spendable / replay required**; incrementing revision
alone is insufficient. Preserve key inventory for fresh authenticated replay,
but publish no replacement view until both opening map and frontier finish.
An old draft can be explicitly revalidated against the newly selected state
when its common-prefix funds/anchor remain eligible; it is not automatically
valid merely because its prior epoch completed.

**B2 — No-DB acceptance must demonstrate a capability boundary.**
Removing `config.database` and `inputsFor(client.membership)` is necessary, but
does not by itself detect a forgotten fallback that opens a known or discovered
database elsewhere in the shared filesystem. Require the wallet and its
descendants to lack readable ledger/oracle/fixture DBs and inherited DB handles,
and lack any owned-index/membership service route. Reuse the existing namespace
approach: read back the actual wallet process boundary and attempt the forbidden
fallback through it before the acceptance sequence. Permit only common-history
input/public endpoints and bounded local private bridge messages. The separate
admission/oracle controller must never send paths or selection maps back.

This does not require removing approved prover/helper source/runtime or their
public output directories. The current private-prover bridge does not need a
ledger DB; the approved installation's pin filenames contain no `.sqlite`,
`.sqlite3`, `.db`, `-wal` or `-shm` entries. That filename observation is not an
executed isolation check. Actual attempted fallback denial remains required.

**B3 — Inventory binding needs an explicit mutation rule.**
The contract says `beginJoint` binds key inventory, while `keys.mjs` currently
allows `rotateReceivingKey` to replace its key array/version and `disposeWallet`
to invalidate it. A future asynchronous Python/helper call can span that change.
Prepared recipients from the old inventory could otherwise publish a view
labelled as current while omitting receipts for an added key. Capture wallet
identity/version/inventory basis; either forbid rotation/disposal while the
candidate/borrow exists, or revoke and restart on mutation. Publication and
spend borrow must check that exact binding. The backup's independently supplied
inventory premise remains conditional; no later random key is derivable.

## Required implementation clarifications

Journal the complete applied public parser cursor together with the owned map:
height, exact ID, count, root, fees and liabilities. Python `Head` intentionally
omits the last two, but current recovery's `position()` retains them and empty
block checks need them after rewind/resume. Alternatively recover those fields
from the common-prefix header authenticated by its exact selected ID. Do not
reuse orphan parser lookahead or reinitialize fees/liabilities from genesis at
a non-genesis resume point.

Scope duplicate checks precisely. Per-block duplicates, pending discoveries,
live owned notes and bounded journals are bounded. A global set of all historical
occurrences/nullifiers would contradict the proposed memory bound. Global ledger
validity remains delegated to the independently selected validating endpoint;
the wallet must not silently claim full omitted-proof/state verification.

## Confirmed feasible boundaries

The actual parser already distinguishes lookahead from applied order and applies
nullifiers before discoveries **within each block**. The proposed internal hook
can register targets before their leaves arrive without a second pass or a full
leaf vector. Existing receiving operations check KEM/KDF/KC/AEAD, plaintext,
owner and commitment; retaining them avoids a fixture-opening shortcut.

Joint publication must keep the frontier owner private until exact EOF, endpoint,
resource cleanup and source/runtime checks succeed. Spent openings need bounded
journal references instead of current immediate wiping; release only after all
committed/candidate/journal/borrow references end. `preparePayment` copies the
private packet before returning, so temporary witness/opening borrows can then
end. Proof failure does not advance owned spentness. These rules support the
stated O((R+1)(D+KD+A+K*openingBytes)) bound plus bounded intake/keys/IPC, provided
old view handles and failed epochs cannot accumulate. This is not an RSS or
memory-erasure result.

The helper gap is real: opcodes1..5 provide no tree leaf/node operations. Proposed
LEAF role4 with16 field words and NODE role5 with17 field words exactly match
existing fixed framing; the bounded new native interface still needs source,
installation and genuine correspondence checks. No per-node subprocess cost is
assumed cheap. Current witness API supplies current-head paths only; historical
draft paths require the separately bounded saved borrow and eligibility check.

Independent endpoint/root/count selection and exact common-prefix identity are
essential. Hash-linked reduced history does not establish validity, freshness,
availability or fork choice. The lab may supply that validating-source context,
but must keep its delegation label. With B1–B3 and cursor/duplicate scopes made
explicit, no further structural contradiction was found that prevents the
bounded bridge from being implemented and tested after the resource gate.

## Follow-up: exact prototype correction and revised contract

The preceding sections preserve the initial findings. The latest contract
reviewed here is SHA256
`41ac77e6326a318343f6ac9ea5fc7c046344173157a827b1a85054788cd88107`.
It explicitly adopts inventory leases, actual DB/FD/proc/network capability
denial and attempted fallback controls, pre-lookup branch revocation with a
blocked-spend state, full applied cursor journaling/reset, and bounded duplicate
scopes. These are adequate **requirements for later implementation**. B2/B3,
joint opening-map publication and process isolation have not become implemented
or accepted merely because the text now specifies them.

Root's preserved actual SOURCE02 counterexample used R=0: H1 committed, H2
active/applied, then selected genesis. `ReplayRequired` was raised while the
old witness remained accessible and the old epoch actually finished.
`wallet-witness/evidence/deep-rewind-counterexample01.json` records this observed
failure; it is stronger evidence than this review's initial source counterexample.

Prototype SOURCE03 SHA256
`b0dcf037a98a7f0a4f8f6611088d63e3d652f950c5da8df9c38016781b44792a`
now aborts its active epoch and advances revision before lookup. A missing prefix
sets `replay_required`, releases current state/history and rejects witness,
anchor/draft eligibility and both ordinary/direct epoch construction. The old
object cannot reactivate its journal; a fresh object must replay selected
history. The exact five source pins matched during independent readback.

The `controls.py` changes separate two fixtures that were deliberately poisoned
by deep rewind before unrelated assertions. They retain the rejected unknown
prefix and legacy empty-block assertions; they do not weaken those checks.
Root's existing25-control PASS is reused, not rerun by this reviewer.

The reviewer independently executed only the newly authorized tiny regression:

```sh
/usr/bin/taskset -c 3 /usr/bin/timeout --signal=TERM --kill-after=2s 10s \
  /usr/bin/python3 -I experiments/network-feasibility/wallet-witness/deep_rewind_control.py \
  --output experiments/network-feasibility/review/DEEP_REWIND_INDEPENDENT01.json
```

Actual exit0, all14 public structural controls PASS. Result SHA256:
`0af3389f0ce82779e91f67320baa75e7368e2a721c09f4a58372a013dc2e63ca`.
The recorded stream SHA matches SOURCE03. This uses diagnostic hashes and public
tokens only; it is no native/CP03 proof, no private receipt, no wallet opening
journal, no isolation measurement and no Gate3 result. The prior live producer
and canonical runtime inputs were untouched.

The component correction closes B1's concrete outside-journal stale-epoch bug.
The future opaque bridge must still enforce selection revocation until the
replacement endpoint is jointly published, including inside-journal rewinds;
the tree prototype's public Python state is not itself that capability boundary.
No additional material source issue was found in this narrow correction.

Updated disposition: GO for **later bounded bridge implementation**, conditional
on the actual resource/retention decision and Root allocation. No full96x8 Gate2
PASS is assumed. Actual inventory mutation, atomic opening lifetime, forbidden
fallback, helper correspondence and genuine Gate3 sequences remain acceptance
work, not resolved implementation findings.
