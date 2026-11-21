# C-to-N7 atomic bridge light gate

## Exact composition

The authorization proof is a fresh, ordinary MNG3 transfer proof. It consumes
one or two funded C notes under the original C spending seed and produces two
C output commitments. The wallet derives `ask` and `nk` from the seed; the
circuit receives only those private derived values and constrains
`ask -> ak -> pk` plus the historical nullifier equation. MNG3 already proves
ownership, exact funded membership, the real/dummy nullifiers, native and
token conservation, and the fixed three-unit fee. The bridge equality proof does not repeat those
constraints. It privately opens the two newly produced C outputs, recomputes
their C commitments, recomputes two N7 commitments and equates each output's
native amount, token amount and exact asset bytes. Four 63-bit C asset limbs
are mapped to eight little-endian N7 `u32` limbs.

The statement names the MNG3 **input** nullifiers, its two **transient C
outputs**, the two successor commitments and a 384-bit `bridge_context`.
The node recomputes that context from its own network, exact selected parent
block ID/height and candidate height,
the complete C packet, parsed C effect, successor commitments, embedded C
receipts and the two N7 receipts. The full packet hash binds the MNG3 proof,
anchor, public effects and ciphertext digest. A producer-supplied context is
never trusted.

Admission independently checks the approved MNG3 verifier, selected-branch
anchor identifier/height/depth, the eight-block eligibility window, each input
NF through a verifier-owned callback backed by the authenticated selected C
spent page (not merely the bridge database), fee `3`, every statement equality, both successor receipt
hashes and the equality proof. One database transaction then:

1. credits exactly the C fee once;
2. inserts both C input nullifiers into the existing common spent set;
3. inserts only the two N7 commitments into the successor accumulator; and
4. retains one canonical C packet, the statement, equality proof and two N7
   receipts.

The two C receipts are already inside the retained C packet and are not stored
again. An optional index records their offsets/hashes separately. Rollback
removes fee, both nullifiers, both N7 outputs and the complete bundle; replay
reconstructs them. No transient C commitment is ever a funded leaf.

## Version and network rules

Standalone MNG3 admission is retired at the bridge activation height. MNG3 is
accepted after activation only as the embedded authorization component of a
bridge bundle. Otherwise an attacker can strip the equality proof and race the
same C packet as a downgrade/denial-of-service transaction. The common
nullifiers prevent inflation, but they do not prevent that race. Tests cover a
pre-activation C spend followed by a conflicting post-activation bridge and a
post-activation standalone rejection. A production alternative is a dedicated
MNG4 migration suite with a distinct transcript and packet tag.

The N7 tree is not a separate genesis. It is an activation-height accumulator
inside the same C network and selected branch. The activation header commits
the carried C root/count, empty N7 root/count and version schedule; later
headers commit both. The bridge context includes the C network and candidate
height, and the N7 receipts use that same network plus an explicit N7 version
domain. The onward spend uses the ordinary N7P2 transfer header and proof
context. Its activation ID binds the same C network, activation height, C
anchor and exact H26 parent; it is not an independently funded genesis.

## Integration boundary

This milestone implements the transition in a branch-aware atomic prototype
ledger and authenticates its C parent with the live devnet implementation.  It
does not add the bridge bundle to `devnet/chain.py`, the peer protocol or the
ordinary block codec.  The measured 412,886-byte bundle exceeds the current
262,144-byte packet limit by 150,742 bytes.  A deployable activation therefore
needs a versioned migration frame/block rule plus measured relay, validation,
memory and denial-of-service limits.  Raising a frame limit is only a transport
change and does not improve proof knowledge or privacy.

## Destination authority limitation

The equality relation proves knowledge of transient C openings, which is
enough to choose N7 destinations. In the bounded run both transient outputs
pay back to the migration owner, the standard C wallet creates them, and the
same owner process immediately creates the equality witness. No opening is
published or delegated. This demonstrates atomic conversion, not a safe
third-party proving service.

Production should use MNG4 (preferred) to bind a 384-bit digest of the ordered
successor owners/commitments and migration context inside the C authorization
proof, then require equality with the bridge statement. An alternative is one
monolithic migration relation that directly constrains the N7 destinations.
Both cost a new registered C-family verifier and a fresh build/prove/verify
measurement; neither cost can be inferred from MNG3 or the equality circuit.

## Backup-only recovery gate

The bounded run starts with the owner's original 32-byte C backup. The N7
backup is deterministically derived as 48 bytes with
`SHAKE256("C2N7/N7-backup/v1\0" || network || activation_height || C_seed)`.
This is a versioned derivation, not a note export. A fresh successor process
receives only the original backup and authenticated public bridge/history. It
derives the N7 receiving key, discovers and decrypts its N7 receipt, recomputes
the commitment, reconstructs membership from the activation N7 tree and
produces a genuine onward N7 proof. Passing a note opening, balance database,
wallet cache or transient C opening to that process fails the recovery gate.

## Required negative controls

- changed native/token/asset fails the equality relation;
- changed C output, N7 output or bridge context, and corrupted equality proof,
  fail public verification;
- invalid C proof, wrong/ineligible anchor or depth, changed receipt and wrong
  fee fail admission without state change;
- replayed nullifier and bridge-versus-ordinary-C orderings fail atomically;
- rollback removes old spentness, N7 outputs, fee and artifacts, and
  reinclusion restores them; and
- backup-only discovery and onward N7 spending work in a fresh process.

The Python ledger tests exercise atomic/state semantics with explicit fake
verifier callbacks. They are not proof evidence. The genuine run separately
replaced both callbacks with the approved C verifier and public bridge verifier.
The bounded offline release compile and source-level unit tests are recorded in
[BUILD_CHECK.json](BUILD_CHECK.json). Two later public-only generations
produced byte-identical registrations; [VK_CHECK.json](VK_CHECK.json) records
their size, digest and resources. The first 1,764-byte registration now resides
at `bridge/registered.vk`, and a fresh clean release rebuild plus tests passed
with that exact `include_bytes!` input.  The final author run generated and
publicly verified a 225,660-byte equality proof and retained it in a canonical
412,886-byte bundle.  See [RESULTS.md](RESULTS.md) for the measured integration
result and its security boundary.
