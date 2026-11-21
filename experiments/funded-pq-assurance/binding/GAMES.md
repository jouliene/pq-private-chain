# Funded binding and monetary security games

## Status and scope

These games describe the prospective MNG3/SLG3 rule and all historical
MNG1/SLG1 and MNG2/SLG2 money that it inherits. They are definitions and a
conditional reduction map, not proofs that the registered PLONK/FRI system or
the funded Poseidon2 instantiation meets a numerical security target.

Let a selected branch state contain an ordered funded occurrence sequence
`F`, a branch-local spent-nullifier set `S`, the native issuance counter, and
the per-asset registry. An occurrence is a position in `F`, even though the
released quaternary accumulator authenticates only set membership within each
sorted quartet. For a canonical private opening `o` and authority secret `a`,
let `CM(o,a)`, `NF(o,a)`, its native value and its typed asset/value be the
exact functions in the funded relation. A *legitimate authorization* for
occurrence `j` requires all of the following at the selected eligible anchor:

1. `F[j] = CM(o,a)` and the occurrence is occupied;
2. `a` derives the owner key committed by `o`;
3. the published real nullifier is exactly `NF(o,a)`;
4. the hidden typed value is the one bound by `o`; and
5. `NF(o,a)` is absent from current selected spentness immediately before the
   candidate transition.

The equality is about the full opening, not merely equality of a 32-byte leaf.
An alternate opening of the same leaf is therefore an attack, not a second
description of the legitimate note.

## Game US: unauthorized funded spend

The challenger initializes an honestly validated branch, gives the adversary
the public history and registered verifiers, and permits adaptive creation of
accounts, funded outputs, ordinary payments, supply operations, swaps, forks,
failed proposals and proof-verification queries. The adversary may corrupt any
owners except an owner designated uncorrupted before the challenged debit. It
may choose payers, recipients, ciphertexts and candidate statements. Reorgs
and the normal eight-anchor window are processed by the real branch rules.

The adversary wins when a candidate is admitted to the selected branch and a
positive real input has no legitimate authorization at its selected anchor.
This includes either a ghost positive input with no funded occurrence, or an
alternate opening/authority for an occupied victim occurrence. Spending an
adversary-owned funded note, denial of service from a colliding nullifier, and
a transaction that is valid only on a detached competing branch are not wins.

For C, a conditional proof decomposes into these failure events:

- extraction or direct monetary soundness of the exact registered proof fails;
- the public header does not bind the selected branch root, height and count;
- the node accepts a depth other than the depth derived from that anchor;
- a nonzero exact-depth path reaches something other than an occupied leaf
  without a parent-compression collision;
- the occupied commitment has a second canonical note/value opening;
- the owner key has an unauthorized opening, or the proof does not bind that
  opening to the same note and nullifier; or
- admission uses stale branch membership or stale current spentness.

The C depth and nonzero rules remove the known variable-shape inference; they
do not establish the remaining cryptographic premises. A reduction must also
state whether the adversary is seeking a second preimage for a fixed victim
note or may first fund one side of an adversarially generated collision.

## Game XV: cross-version double spend

The challenger runs one selected branch with the historical candidate-height
dispatch and one spent set. The adversary may obtain or create valid A, B and C
proofs and may submit them around activation boundaries and reorgs.

The adversary wins if two admitted, simultaneously retained transitions debit
the same funded economic occurrence and both effects remain in the selected
state. The two debits may use different proof versions or operation routes.
They must not merely be spends on mutually exclusive forks. Because selected
spentness rejects an already present identifier, a successful win necessarily
uses two distinct accepted nullifiers for the same occurrence or bypasses the
atomic spent-set update.

A/B/C use the same real-nullifier equation. Subject to proof extraction and
unique binding of note and authority, two openings of the same occurrence
therefore yield the same nullifier and the second admission fails. The
remaining failure cases are:

- an alternate opening of one funded commitment yields a different accepted
  nullifier;
- a version or operation route omits or changes the lifetime identifier;
- activation dispatch admits a retired debit route at the candidate height;
- a swap leg or supply route checks or records spentness outside the common
  atomic transition; or
- rollback/replay leaves spentness inconsistent with the selected effects.

An accidental collision between two genuinely different notes' nullifiers is
an availability failure, not a double spend. Any future wide profile must keep
the exact legacy nullifier for a legacy input. Assigning a new wide nullifier
to the same old occurrence would win this game without breaking a hash.

## Game IN: accepted inflation

Define the hidden monetary audit of a selected branch using the creation-side
opening of each occurrence in `F`. In the game, this is the witness used by an
honest creator or extracted from the accepted creation proof. A later debit
must use that same full opening and authority, not merely another opening with
the same commitment bytes. If extraction is unavailable, existence and
cross-proof consistency of these openings are theorem obligations, not an
auditor assumption. For each admitted ordinary leg, its
bounded native inputs must equal native outputs plus its fee; its per-asset
inputs plus an authorized supply delta must equal its outputs. For the selected
branch as a whole:

- native rewards add exactly the subsidy and recycle each included fee once;
- fixed issuance occurs once under its derived asset identity;
- managed register/mint is authorized by the registered issuer and sequence;
- burns cannot reduce the registry below zero;
- every value, registry, nullifier, commitment, fee and receipt effect of one
  logical transition is committed or rolled back together.

The adversary wins if the node admits a selected transition after which any of
those equalities or authorization rules is false. This game deliberately
overlaps Game US: a ghost positive input is also inflation when its value is
carried into outputs. Additional independent failure cases include a false
conservation proof, an issuer-signature forgery, a collision in an issuance or
registry identity, arithmetic overflow, fee duplication, partial swap
settlement, partial database commit, and inconsistent reorg rollback.

For colliding openings the audit is deliberately non-existential. Suppose an
occurrence was created with `o_create` but a debit proof uses distinct
`o_spend` with `CM(o_create) = CM(o_spend)`. The audit follows
`o_create` into the funded state and requires the debit value/asset and
nullifier to agree with it. It does not choose whichever opening makes the
post-hoc equations balance. The adversary wins Game IN if the accepted debit
credits value or supply available only under `o_spend`, or if two retained
transitions require inconsistent openings for the same occurrence. If the
alternate opening changes authority but not value, it is a Game US win; if it
changes the lifetime nullifier and enables two retained debits, it is also a
Game XV win. A collision that only strands one of two honest notes is an
availability event and is not silently counted as inflation.

A precise idealized collision-to-inflation experiment uses two disjoint
canonical note domains. Fix native value `v0 = 4` in the first and `v1 = 5` in
the second; let the adversary choose valid `ask`, `nk`, `rho`, `raw` and other
canonical fields. A cross-value claw is a pair
`CM(o0) = CM(o1)` with `o0` in the `v0` domain and `o1` in the `v1` domain.
The adversary funds `o0`, then proves the same leaf opening as `o1` and carries
the extra unit into outputs. Under proof extraction, authority and atomic-state
premises, acceptance wins Game IN. Because the typed opening enters the
historical nullifier, the pair may also yield distinct nullifiers and threaten
Game XV. The openings must satisfy every field-canonicality, 62-bit amount,
63-bit asset-limb and zero-asset/zero-token rule; an arbitrary digest collision
does not suffice.

BHT Theorem 4 gives an ideal claw-finding query algorithm at the collision
scale for two functions with equal-size ranges. Applying that theorem here
requires modelling the two constrained encodings as suitable random functions
and showing the output claw has the required authority/funding semantics. No
such reduction or concrete Poseidon2 attack is established. Conversely, Game
US for a preselected victim is a fixed-target second-preimage/multi-target
search problem, not this chosen cross-value claw game.

Historical inflation, if any, is inherited state: C cannot retroactively
repair it. A launch claim therefore needs either assurance for every historical
admission rule or an explicitly trusted/checkpointed supply premise.

## Quantitative composition obligation

If `epsilon_proof`, `epsilon_header`, `epsilon_parent`, `epsilon_note`,
`epsilon_owner`, `epsilon_nf`, `epsilon_signature` and `epsilon_state` are
conditional bounds for one adaptive attempt, a conservative per-attempt bound
adds the applicable terms. A lifetime claim over `R` adaptively chosen
attempts may then apply `min(1, R * epsilon_attempt)` only when each term is
proved conditioned on the complete prior transcript. A fixed-statement
estimate cannot silently be multiplied by a transaction count.

The generic hash calculations in [RESULTS.json](RESULTS.json) price ideal
multi-target search and arbitrary collision queries only. They are not values
for any epsilon above. The primary algorithmic sources are Boyer, Brassard,
Hoyer and Tapp's multiple-solution search analysis
([arXiv:quant-ph/9605034](https://arxiv.org/abs/quant-ph/9605034)) and Brassard,
Hoyer and Tapp's quantum collision algorithm
([arXiv:quant-ph/9705002](https://arxiv.org/abs/quant-ph/9705002)). The actual
permutation design source is the Poseidon2 paper
([IACR ePrint 2023/323](https://eprint.iacr.org/2023/323)); that paper does not
by itself analyze this application's sponge, encodings or monetary games.
