# Smallest coherent wider note/tree alternative

## Result

Five Goldilocks words are the smallest integer width that clears a 128-bit
*ideal multi-target preimage* query exponent in every checked 20-year scenario.
They are not enough for a 128-bit arbitrary-collision benchmark. Six words are
also insufficient under the exact field order: `log2(p^6)/3` is just below
128 because `p = 2^64 - 2^32 + 1 < 2^64`. Seven words are therefore the
smallest whole-Goldilocks-limb output with an ideal BHT collision exponent
strictly above 128. See [RESULTS.json](RESULTS.json). This is a parameter
comparison, not an unconditional monetary minimum: a protocol must first
justify that arbitrary collision resistance is the applicable obligation and
compose it with proof knowledge, authority, admission and lifetime state.

That arithmetic result is not a reason to append three words to the existing
hash. The released sponge has only four capacity words, untagged parent
compression and a four-word output. Squeezing more words from the same state
would not establish seven-word collision resistance. A candidate needs a new
versioned construction with enough capacity, explicit input length and
separate domains for authority, note, real nullifier, dummy nullifier, reward,
leaf and every tree level.

The already implemented N7P2 sponge is the smallest local seven-word reference:
width 12, five absorbed message words, seven capacity words, domain and length
injection, and a two-permutation seven-word output. Its ordered depth-40 tree
uses a distinct parent tag at every level. The exact code is
[`advancing-note/proof/src/sponge.rs`](../../advancing-note/proof/src/sponge.rs)
and [`note.rs`](../../advancing-note/proof/src/note.rs). This is implementation
evidence, not cryptanalysis or a qualification of those parameters. The
primary permutation design is
[Poseidon2, IACR ePrint 2023/323](https://eprint.iacr.org/2023/323).

## Minimal coherent D profile

A minimal funded successor should reuse the N7P2 seven-word sponge shape while
retaining the current asset and two-input/two-output monetary semantics. It
must widen every binding-critical link, not only the public root:

- seven-word owner derivation and receiving public key;
- seven-word typed note randomness, note commitment and real/dummy nullifiers;
- seven-word tree children/root with a leaf domain and level-specific parent
  domains;
- a public authenticated leaf count and a constrained occupied position (or a
  separately justified seven-word set-membership relation);
- seven-word reward commitments and all header fields that authenticate the
  new root/count; and
- versioned receipt context, proof statement and wire framing that carry the
  56-byte commitment and owner key without truncation.

Keeping a four-word inner owner or typed-note digest would leave Game US and
Game IN reducible to that narrower collision/preimage game. Keeping a 32-byte
new-note nullifier would keep the lifetime XV bound at the old width. Existing
32-byte asset IDs may remain immutable names for historical assets, but new
issuance identifiers and registry authorization digests need a separate
binding analysis; widening the note tree does not repair issuer identity or
signature failures.

This candidate changes proof geometry, public statement width, receipts,
headers, database keys, wallet backup derivation and archive bytes. The exact
bridge source passed a bounded offline release build and tests, and its
1,764-byte registered VK was reproduced byte-for-byte in two independent
temporary paths before a clean registration-linked rebuild.  The genuine run
then generated and publicly verified a 225,660-byte equality proof.  Its
canonical bundle, including the fresh 182,863-byte C packet and both successor
receipts, was 412,886 bytes.  See
[the measured result](migration/RESULTS.md).  Those measurements qualify this
specific bridge only; they do not transfer to another C/D relation or establish
proof-system security.

## Migration without a second spend identity

1. **Replay first.** Validate every pre-activation block under its original
   A/B/C candidate-height rule. Do not reinterpret old proofs, commitments or
   nullifiers as seven-word objects.
2. **Freeze and carry the legacy accumulator.** At activation, commit the
   selected legacy root and count into the new header and carry them unchanged
   in every D header. This gives old notes a current eligible anchor after the
   ordinary eight-block window without rewriting their leaves. Current
   spentness remains live. A one-time activation root that later becomes
   ineligible would strand unmigrated wallets.
3. **Use an atomic legacy-to-D bridge bundle.** The bounded prototype composes
   a fresh canonical C spend proof with an equality proof. The C proof's
   inputs are the funded notes, so it proves their exact authority, historical
   nullifiers and membership and charges the fee. Its two C outputs are
   transient conservation witnesses. The equality proof opens those outputs
   and maps them exactly to D outputs. The node inserts the C proof's input
   nullifiers and D commitments, never the transient C commitments, and
   updates fee, artifacts and both accumulators in one branch transaction.
   Standalone C admission retires at activation so the embedded packet cannot
   be stripped and raced as a downgrade transaction. See
   [migration/DESIGN.md](migration/DESIGN.md).
4. **Make all new value D-only.** After activation, ordinary outputs, swap
   outputs, issuance outputs and rewards enter only the D tree. D inputs use
   seven-word nullifiers. A mixed transaction may consume legacy and D inputs
   only if one registered relation binds both openings to one conservation
   equation; composing two independent proofs in the node is insufficient
   without an exact shared-value/fee argument.
5. **Version recovery.** Backups derive both legacy and D receiving keys with
   explicit version domains. Recovery scans legacy receipts with the legacy
   codec and D receipts with the D codec, then performs a real bridge spend for
   legacy holdings. No public migration can recreate a private opening from a
   commitment alone.
6. **Reorg atomically.** A fork crossing activation restores the correct
   version schedule, both roots/counts, both nullifier namespaces, registry,
   rewards and fees together. A fork cannot keep D outputs while dropping the
   legacy debit.

The bridge leaves the historical four-word assumptions in the authorization
of legacy value until that value is spent. It prevents a protocol-created
second identity; it does not upgrade the past or prove that a maliciously
generated legacy collision never existed. A finite migration deadline would
convert remaining old money into confiscation and is a product decision, not a
cryptographic repair.

## Integration threshold

N7P2 was initially only a materially wider comparator because its earlier
evidence started from a different genesis.  The C-to-N7 run now satisfies the
bounded funded-successor experiment below on the existing C network:

1. fund a legacy C note, restore its original owner and produce a **fresh** C
   migration spend at an eligible selected-branch anchor;
2. admit its C authorization and equality proof atomically, consuming the
   fresh packet's exact input nullifier(s) and creating only D funded notes;
3. reject a competing ordinary C spend and a second bridge of the old note;
4. restore the D recipient from the declared original 32-byte backup through
   the versioned derivation plus authenticated public bridge/history, with no
   note or balance import; and
5. create and publicly verify a fresh D spend, including rollback/reinclusion
   of the whole bridge transition.

All five checks passed in the author run, including both conflict orderings,
rollback/reinclusion and an original-backup-only restored spend.  This validates
compatibility and state semantics, not 128-bit proof knowledge or whole-view
privacy.  The 412,886-byte bridge also requires a dedicated versioned migration
frame rather than the ordinary 262,144-byte payment frame.
