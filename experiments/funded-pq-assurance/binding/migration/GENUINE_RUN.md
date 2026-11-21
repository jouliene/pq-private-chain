# Genuine-run contract and completed execution

This was the execution contract for `run_genuine.py`.  Author attempt 05
completed it.  The public, secret-free result is in
[`evidence-author05`](evidence-author05), the measured summary is
[RESULTS.md](RESULTS.md), and the diagnostic attempt history is
[ATTEMPTS.md](ATTEMPTS.md).  The contract below remains the specification used
to judge the run; it is not itself cryptographic evidence.

## Inputs and secret boundary

Public inputs:

- an authenticated C block archive and selected prefix tip at the funding
  height;
- the approved C verifier/runtime, key directory and their build manifests;
- the registered bridge binary/VK and the registered N7P2 binary/VK;
- the C network identifier, activation height and expected funded tree count;
  and
- Node.js 24.22.1/OpenSSL 3.5.9 for the pinned N7 receipt role.

Private inputs, all regular `0600` files under one disposable `/tmp` run root:

- the original 32-byte C backup of the funded owner;
- transient C output openings returned by the private exporter;
- the derived 48-byte N7 backup, successor note plaintexts, bridge witness and
  onward N7 witness; and
- generated proof files until only their public hashes/sizes are recorded.

The harness must set umask `077`, reject symlinks, never print a seed, opening,
plaintext receipt or witness, and recursively inspect the requested public
output before writing it. A private file is never a reproduction dependency.
The private opening exporter is not a consensus binary; its generated MNG3 VK
must byte-match the checked-in approved C VK.

## Fresh C authorization

The harness creates a fresh isolated C home, copies only the approved
deployment, replays authenticated selected blocks through H25, and restores a
wallet from the original backup. It records the verifier-owned H25 anchor ID,
height, funded count and derived depth from the node state. The owner sends a
self-payment under C for candidate H26. This produces a new MNG3 packet whose
inputs are the funded H25 note(s), whose two output CMs are transient, and
whose fee is exactly three. The packet is read from the node's pending pool
but is not sent to the accepted bridge branch. An independent node with the
same H25 prefix and no pending packet mines an empty H26. Its exact block ID,
height and spent page are the parent context for the candidate-H27 bridge.

The approved C verifier is invoked in a fresh process. Its parsed anchor,
height, depth and fee must match the independently captured selected-branch
view; its input NFs must be absent from the authenticated selected H25 spent
page captured independently from the packet. The packet hash must
not name any archived creator packet. The private exporter then decrypts the
two receipts with the same seed-owning wallet and emits only a private sidecar.
It does not export `ask` or `nk`; the standard wallet derived them from the C
seed and MNG3 constrained them.

## Same-network successor and equality proof

No N7 genesis is created. The 48-byte successor network and key scope are
domain-separated derivations of the 32-byte C network, activation height and
activation anchor. The 48-byte N7 backup is

```text
SHAKE256("C2N7/N7-backup/v1\0" || C_network || u32(activation) || C_seed, 48)
```

The two transient C values map to two N7 notes controlled by that derived
owner. Four little-endian 63-bit C asset words become eight `u32` words. The
N7 receipts bind the derived successor network, output slot and 56-byte CM.
The harness independently recomputes both C and N7 commitments, derives the
verifier-owned bridge context, asks the bridge binary to derive the same
statement, proves it, and verifies it in a fresh public-only process.
Context version 3 binds the exact H26 parent block ID and height as well as
candidate height, so an H25-only state cannot be described as an H27 branch.

The canonical bundle codec retains exactly one complete C packet (including
its two C receipts), one canonical JSON statement, one equality proof and two
1,744-byte N7 receipts. It rejects alternate JSON/framing and reports component
bytes separately from the optional 16-byte C-receipt offset index.

## Atomic and negative controls

`ledger.py` receives actual callbacks:

- `verify_c_packet(packet) -> CEffect` launches the approved C verifier; and
- `verify_equality(statement, proof)` launches the registered bridge verifier
  with temporary public files.

Admission at activation H27 checks the selected anchor/depth/window, exact fee,
and each NF through a verifier-owned callback over that authenticated C spent
page, plus all statement/context fields and both receipt hashes before one SQL
commit. Tests then use copies of the real public artifacts to reject changed
native, token and asset witnesses as unsatisfied proving assignments; changed
C CM, N7 CM or context; corrupted equality proof; invalid C proof; wrong
anchor/depth; changed successor receipt; replay; and a competing ordinary C
spend. The same fresh verified packet is mined on a legacy-control branch at
H26; the resulting authenticated spent page makes its H27 bridge fail. In the
reverse ordering, H27 standalone MNG3 is rejected by the activation schedule.
Snapshot equality is
checked after every rejection. Rollback removes fee, both C NFs, both N7 CMs
and bundle; byte-identical reinclusion restores them. The N7 tree never
contains a transient C CM.

## Backup-only onward N7 spend

A new process receives only the original 32-byte backup, approved public C and
bridge verifiers, and authenticated public activation/bridge history. It
replays the C prefix and empty H26 parent, re-verifies the MNG3 proof,
recomputes context and current spentness, and re-verifies the equality proof
before using any receipt. It then rederives the 48-byte backup, owner and
KEM key, trial-decrypts the two public N7 receipts, recomputes each CM, and
rebuilds the ordered depth-40 activation tree. It receives no note sidecar,
balance database, wallet cache or transient C opening. From one recovered
positive note it constructs the exact path/NF, a domain-separated padding NF,
two conserving successor notes and receipts, and a verifier-owned same-network
statement. It generates an ordinary N7P2 transfer header and packet whose
context is exactly `SHA3-384("N7P2/proof-context\0" || activation_id ||
header)`. The activation ID binds this C network, activation anchor and H26
parent; it is not a separately funded genesis. The successor ledger checks
root/count, existing outputs, exact fee, proof and spentness, then atomically
appends both new CMs and advances root/count. The packet, statement, proof and
receipts remain public. Changed statement/proof and replay fail without state
change; rollback and byte-identical reinclusion restore the transition.

## Executable entry points

`run_genuine.py preflight` validates public lineage, executable role paths,
the private seed's metadata (not contents), and the H25/H26/H27 schedule.
`run` performs the allocated private/heavy phases; `recover-spend` is invoked
only as a fresh child process by `run`.

Required inputs are the retained deployment, authenticated membership archive
and manifest, original owner seed, private exporter, registered bridge and N7
binaries, pinned Node binary and `advancing-note/lab/crypto.mjs`, plus a fresh
private directory below `/tmp` and a separate fresh public-output directory. The exporter and N7 binary
must be built before preflight; their absence is a real prerequisite.

## Resource phases

Every Cargo phase uses explicit `/tmp/funded-pq-*` `CARGO_HOME` and
`CARGO_TARGET_DIR`, offline/locked inputs, `-j2` and two Rayon threads. Private
proof witnesses enter on stdin and `/usr/bin/time -v` writes only resource
fields to a private temp file. The public result separates:

- C wallet setup/prover wall, CPU and peak RSS;
- bridge setup/prover and fresh verifier wall, CPU and peak RSS;
- recovery scan/restore wall, CPU and peak RSS;
- N7 setup/prover and fresh verifier wall, CPU and peak RSS; and
- C packet, registered VK, equality proof, canonical bundle, N7 proof and both
  receipt-set bytes.

Only one heavy process runs at a time.

## Public result manifest

`RUN.json` contains no private bytes. It records source/VK/binary hashes,
selected public block/anchor IDs, activation/version rule, proof and bundle
hashes/sizes, verifier verdicts, state counts/fee deltas, negative-control
reason labels, rollback/reinclusion equality, backup-only process inputs by
type/size, and the resource measurements above. It also records the C build
provenance pins and the bridge/N7 registered VK digests. Reproduction rebuilds
all binaries from pinned public source; no `/tmp` path is a dependency.

The retained `private_dependency: false` field means that **public verification
of the released artifacts** has no private dependency.  It does not mean that
another party can regenerate the exact authorization, equality proof or backup-
recovery action: those operations require the historical 32-byte backup and
private witnesses, which are intentionally absent from the release.
