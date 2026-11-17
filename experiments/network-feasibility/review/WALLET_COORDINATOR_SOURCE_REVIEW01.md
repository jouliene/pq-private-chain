# Joint wallet coordinator: initial source review

Status: source-only review of the early, not-yet-frozen candidate. No native,
wallet/proof, isolation or acceptance run was executed by this reviewer.

Reviewed identities:

- `keys.mjs`: `04e8447b92e1d3c9f544d455a54d10d3412d87f8ba6555c5c57a6fc7e09a7a7c`
- `recovery.mjs`: `e31adf14869dfd411147da01f139a314a94bc0a252a69db93a22bf36662de013`
- `local_witnesses.mjs`: `3575832d057f96376b96a9b57fcf714f053c9ff99829f1af7b295611709b6674`

## Material finding W1: untracked prepared packet on callback failure

`withLocalWitnesses` assigns
`prepared = synchronous(operation({anchor, inputs}))`. An ordinary function
(not an `AsyncFunction`) can call the genuine `preparePayment` then return
`Promise.resolve(payment)`. `synchronous` rejects the promise before assignment;
the coordinator has no payment handle to dispose in its `finally`. Likewise,
preparing a payment and then throwing loses its handle to the coordinator.
Wiping borrowed input copies does not wipe the separate encoded packet owned by
that prepared payment. A caller can retain it outside the failed borrow.

This is a concrete mismatch with the advertised single prepared-packet ownership
and failure cleanup, not a forged-proof attack or a claim of robust isolation
against arbitrary malicious in-process code. The author acknowledged it.

Smallest robust correction: have the coordinator call unchanged `preparePayment`
itself using caller-provided output descriptions/options. Keep openings and paths
inside that call; do not delegate packet allocation to an external operation
callback. Metadata-only synchronous selection can remain, since it receives no
opening/path and cannot allocate the selected-input packet through this boundary.
Preserve final revision/lease/statement checks and dispose any coordinator-owned
prepared result on failure. Review the resulting source and a discriminating
failure control before source GO.

## Checked source properties and remaining gates

The shared parser refactor preserves the former canonical block/body/genesis
parsing and its bounds. It keeps separate parsed/applied cursors, whole-block
windows bounded by256 blocks/statements, exact target/EOF, stable input identity
and close-before-return. Legacy recovery retains its real context/digest/opening
operations, nullifiers-before-discovery order and empty-window handling. This
inspection is not a runtime compatibility result.

The coordinator uses the same public parser, independently supplied full target
cursor and actual receipt adapter. It re-parses the complete common prefix even
when applying only the suffix; those bytes/time must remain priced. Target
tokens originate locally at incoming occurrences; index derives from ordered
records. Candidate and rewind states deep-copy openings, frontier, selected paths,
full cursor and anchors. Spent candidate openings can be wiped because permitted
checkpoints own copies. Native outputs remain private until exact EOF, cursor
checks and recipient cleanup. No Ledger/membership import appears in this module.

Branch selection revokes the current view/revision before journal lookup; an
absent prefix clears the committed state and throws replay-required. A retained
prefix is only a private replay base until the selected target publishes.
Inventory-invalid cleanup clears the state. The entire session holds an exclusive
inventory lease; supported rotate/dispose APIs reject while leased, and actual
public inventory is compared on each lease use. Existing internal `withWallet`
is trusted implementation access, not a hostile-code sandbox.

The initial forget-order concern is resolved by the native wrapper contract:
it sorts a private copy and rejects duplicate handles before canonical wire
serialization. Coordinator public-nullifier order need not itself be lexical.
Actual wrapper/native source correspondence remains to be reviewed.

`localDraftEligible` checks current owned nullifiers and eligible selected anchor
root/count. Acceptance code must call it at the actual proof/submission boundary;
its existence alone does not revoke externally retained prepared/public drafts.
The forthcoming controlled path must demonstrate stale/double-used/expired draft
failure and valid refresh under genuine proof/admission, not only a boolean test.

Root's separate process-isolation pilot is useful prerequisite evidence. It is
not execution of this coordinator/helper/prover hierarchy. The genuine wallet
acceptance still needs actual no-DB/FD/proc/socket fallback denial, frozen source
and installation postchecks before its outward result, backup-only fresh-process
reconstruction, branch/expiry cases and measured bounds.

Disposition at these exact candidate hashes: **W1 requires correction before
source GO**. No additional structural contradiction was found in the inspected
parser/journal/lease design; native implementation and focused controls remain
separate required review steps.

## W1 correction: direct preparation and tracked retirement

Reviewed successor `payments.mjs`
`268f9397c9138470c19d77abdfb67ebf9b9c462dac6effeca96e6cabec31af48`
and `local_witnesses.mjs`
`91189647d71b80a1e2854cbb8997949af21788b5c53db76dc99c9e2a59cb9ad1`;
keys/recovery retain the hashes above. **W1 is resolved in source.**

The external operation callback is removed. The coordinator calls unchanged
payment construction itself, tracks its returned handle before handing it out,
and checks revision/lease/anchor/NFs. A second unused or actively consuming
packet is rejected. Metadata-only selection receives no note/path/key.

Payment lifecycle now distinguishes used, inFlight and retired. Retirement of an
unused packet wipes/deletes immediately. Retirement of an active packet marks
it non-submittable without wiping bytes under its running consumer; the existing
awaited operation/finally performs wipe/delete/settlement after the approved
Parent has terminated. Direct disposal rejects an active consumer. Session
disposal revokes logical authority immediately, then awaits settlement before
releasing its key lease. This closes the specific lifetime hole without replacing
the private Parent or claiming general asynchronous child cancellation.

No new source blocker was found. **Source GO for Root's fresh build and bounded
controls**, not an executed lifecycle or Gate3 PASS. Actual joint controls must
cover supported lease mutation, callback refusal, the pending slot, selected
branch/deep replay unavailability and consumed-packet retirement.

## Gate3 actor/profile source review

Read Root's draft `wallet-integration/wallet.mjs` and `GATE3_PROFILE.json`.
The five-proof small and264-proof full totals are consistent. The full fixture
retains receiver note index4, spends its other original note index5 at height3,
and makes255 further changing-root blocks through height258. The height2 root
is then outside the256-entry anchor ring. The1B rolling credit covers255 rolling
fees and the additional replacement fee; the100M independent payer credit is
not accidentally used as the rolling budget.

At orphan height259, the refreshed old-note spend leaves the earlier receiver
change plus the new branch-only receiver output. Selecting receiver index-order
position1 chooses that new output. Rollback to258 and a replacement rolling block
restore the original old note and remove that branch-only receipt. Fresh restore
selects index-order position0, the reinstated oldest note. Backup is made after
receiving-key rotation and before receipt; original sessions/wallets are disposed
before backup handoff. The controller must still establish actual original process
termination before starting the new one, and pass only backup plus declared public
context, never an opening/index/path map.

Two controller/acceptance requirements remain explicit:

1. Freshly public-verify every generated proof, including the orphan-child body.
   Its expected later `Anchor` admission rejection precedes proof verification
   and cannot alone establish fresh proof validity. The actor's installed private
   prover explicitly reports that fresh public verification is still required.
2. Invoke real joint lifecycle/deep-replay controls on these actual installed
   handles. The draft actor does not yet import `joint_controls.mjs`; historical
   Python-only controls do not establish the new joint implementation behavior.

Neither requires another proof campaign. The positive stale-draft admit/rollback
controls and later actual Anchor/all14-table rejection remain necessary and must
be checked by the public controller, not inferred from a local eligibility flag.

## Actor wiring follow-up

Root's successor actor now invokes the real inventory lease, synchronous
inspection, external-operation refusal and single-pending-packet assertions on
its actual receiver session. It positively admits and rolls back the genuine
orphan-child body before abandoning its parent branch, so later early Anchor
rejection is not its sole public validity check. It also selects genesis outside
the retained joint journal, requires typed replay-required, checks old view and
draft authority unavailable, then fully replays selected history and checks the
original reserve amount restored. These source changes resolve the two wiring
requirements above without changing the264/5-proof counts. Actual execution and
controller evidence remain pending.

The inspected `isolation.py` constructs a new allowlisted root, independent
PID/mount/network namespaces, a fixed x86-64 socket/escape syscall filter and
closed inherited descriptors. It permits fresh run-owned public/evidence overlays
at the Parent's fixed source paths without mounting a host root or ledger tree.
`isolation_probe.py` checks forbidden existing DB paths, inherited device/inode
identities, socket creation denial and host process-root exclusion; its pilot
also checks a descendant. These are useful prerequisite source/control boundaries,
not proof that the actual wallet/prover hierarchy has already run inside them.
The new runner must instantiate only the approved mounts, verify actual wallet
Node PID/namespace/FD denials, preserve backup solely in bounded RAM, observe
original process termination before restore, and account for native/helper/prover
work separately from the bwrap leader. Final runner source and actual evidence
remain a separate gate.
