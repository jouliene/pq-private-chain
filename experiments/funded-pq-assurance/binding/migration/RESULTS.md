# Funded C-to-N7 migration result

## Outcome

Author attempt 05 completed the registered migration experiment.  A fresh MNG3
payment spent two funded C inputs at the eligible H25 anchor.  The accepted
branch advanced through an unrelated empty H26, then one versioned H27 bridge
was admitted in the separate prototype migration ledger.  The bridge retained
the legacy input nullifiers, inserted only two N7 commitments and credited the
three-unit fee once.  A competing branch spent the
same C inputs ordinarily at H26 and caused the bridge to fail against the
authenticated selected spent set.  Reversing the order caused the stripped
standalone C packet to fail the activation schedule.

A new process then received the original 32-byte C backup as its only private
input.  It replayed authenticated public history, reverified the C and equality
proofs, rediscovered both N7 receipts, built the two-leaf depth-40 membership
state and admitted a new ordinary N7P2 spend.  No note opening, balance database,
wallet cache or witness was transferred to that process.

No current `devnet/chain.py` block or ordinary packet codec admits the bridge
bundle: at 412,886 bytes it exceeds `MAX_PACKET=262144`.  The experiment joins
an authenticated real C branch to a branch-aware atomic prototype ledger; it is
not an integrated PoW-block migration.  Production activation needs an explicit
versioned migration frame/block limit and a measurement of its relay, validation
and resource effects.

The complete public author evidence is in
[`evidence-author05`](evidence-author05).  `PUBLIC_MANIFEST.json` binds its eight
data files.  The author harness and independent public verifier are separate
implementations.

## Measured bytes and resources

| Role or artifact | Result |
| --- | ---: |
| Fresh MNG3 authorization packet | 182,863 B |
| Equality proof | 225,660 B |
| Bridge statement | 847 B |
| Two successor receipts | 3,488 B |
| Canonical bridge framing | 28 B |
| Canonical bridge bundle | 412,886 B |
| Bridge excess over 262,144-B ordinary frame | 150,742 B (57.5%) |
| Equality proving | 7.65 s wall; 12.71 s user; 1,853,652 KiB peak RSS |
| Equality verification | 11.98 ms operation; 5,816 KiB peak RSS |
| Restored N7P2 proof | 230,805 B |
| Complete restored N7P2 packet | 234,646 B |
| Restored N7P2 proving | 7.84 s wall; 13.05 s user; 1,866,336 KiB peak RSS |
| Restored N7P2 verification | 11.90 ms operation; 5,968 KiB peak RSS |
| Fresh recovery child, including proof | 20.39 s wall; 1,866,336 KiB peak RSS |

The C wallet measured 10.01 s wall for the fresh authorization, including
9.68 s of proving, 18.77 prover CPU-s and 887,112 KiB peak prover RSS.  These
are single-host observations.  They are not confidence intervals, capacity
claims or production bounds.  The bridge requires a dedicated versioned
migration frame; increasing that limit would address transport only, not the
cryptographic gaps.

## Controls

The run rejected changed native amount, token amount and asset before a proof
could be produced.  Public verification rejected changed C commitment, N7
commitment and bridge context, a corrupted equality proof, a corrupted N7 proof
and a changed N7 statement.  Admission rejected an invalid C proof, wrong anchor,
wrong depth, changed successor receipt, replay and both C/bridge conflict orders
without partial state.  Rollback and byte-identical reinclusion restored the
fee, two legacy spent identities, two successor outputs and retained artifacts.
Transient C outputs never became funded leaves.

## What this establishes

The run establishes an executable out-of-band compatibility result: funded C
authorization,
exact value/asset carry-over, one-spend state semantics, branch-relative
spentness, atomic rollback and original-backup recovery can be composed into a
versioned successor transition.

It does **not** establish 128-bit post-quantum knowledge security, security of
historical C value, instantiated Poseidon/Poseidon2 collision bounds, adaptive
whole-payment zero knowledge, receipt anonymity, safe delegated destination
selection or integration into the current PoW packet/block codec.  Both the
equality relation and N7P2 still use the same broad
Plonky2/FRI family whose exact quantum knowledge/HVZK correspondence is open.
Production migration should bind the ordered successor destinations and context
inside a dedicated legacy-owner authorization relation rather than expose a
general self-payment opening to a separate prover.
