# Funded profile C: post-quantum monetary-assurance decision

## Decision

**Do not make a 128-bit post-quantum monetary-security or complete-payment
privacy claim for profile C.**  Keep C executable as the funded research/devnet
reference and, conditionally, as the authorization layer for migrating legacy
value.  For a mainnet-target profile, change both the binding-critical
note/tree/owner/nullifier construction and the proof backend, unless an exact
source-matched theorem and simulator are supplied for the registered proof.

This is not a claim that a practical attack on C has been implemented.  It is
a refusal to promote parameter names, finite tests or an unrelated theorem
into a quantitative protocol guarantee.  The decisive results are:

1. A chosen cross-value claw in the four-word note commitment would give
   accepted inflation.  In the ideal-function model, the four-word BHT screen
   is about `2^85.33` queries/table entries and the separate no-qRAM CNS screen
   is soft-`O(2^102.4)` time/queries.  Neither is a concrete Poseidon2 attack,
   but neither supports a 128-bit claim.
2. The exact registered Plonky2/FRI transcript has no demonstrated
   source-matched adaptive quantum knowledge theorem, concrete FRI/list bound,
   QROM compiler loss or complete HVZK simulator.  Increasing the visible
   parameters to the calculated S64 profile does not close that correspondence.
3. The public retry/fork trace links competing authorizations by identical
   nullifiers.  Honest recovery and receipt opening work, but no theorem
   composes proof zero knowledge, receipt anonymity/robustness, retries and
   later spends.
4. A coherent seven-word successor clears the checked ideal cross-value-claw
   screen, but it still uses the same broad proof family.  A funded migration
   can establish compatibility and one-spend state semantics; it cannot
   upgrade historical C assumptions or qualify the successor for mainnet.

The global private PoW blockchain objective remains active.  This decision
concerns the funded spend profile only.

## Target, adversary and claim convention

The intended launch target is at least 128 bits against an adaptive quantum
adversary observing the complete public chain, proof transcripts, receipt
envelopes, retries, forks and later spends.  The adversary may create accounts,
fund its own notes, choose recipients and ciphertexts, submit proofs, corrupt
participants other than a designated victim, and adapt to every prior result.
It may not silently obtain an honest wallet's uncompromised secret.

A constant-success query exponent is an attack screen, not a probability
bound.  A lifetime failure statement of at most `2^-128` needs conditional
per-attempt bounds that remain valid after the entire prior transcript.  For
example, even a genuine per-attempt `2^-128` bound union-bounded over 4.4
billion attempts is only about `2^-95.97`.  The 20-year mix and the assumption
that all 4.4 billion occurrences are usable targets are researcher scenarios;
the owner's only workload input is 100 million offered payments per year.

## What the money property requires

The exact games are in [GAMES.md](binding/GAMES.md), and the implementation map
is in [CODE_MAP.md](binding/CODE_MAP.md).  They deliberately distinguish three
outcomes.

### Unauthorized funded spend (US)

Every positive input must bind one owner-authorized canonical opening to an
occupied occurrence under an eligible selected-branch root.  The same opening
must determine the value, asset and real nullifier.  Current selected spentness
must be checked immediately before atomic admission.

C supplies useful structural checks: candidate-height verifier dispatch,
verifier-owned anchor/depth comparison, exact nonzero path shape, current
spentness, duplicate-effect rejection and branch-atomic state changes.  The
argument remains conditional on proof extraction/direct monetary soundness,
header binding, parent/note binding, owner binding and consistent commitment/
nullifier openings.

A fixed uncorrupted victim is not the generic collision game.  In the ideal
four-word range, one fixed-target quantum search is about `2^128` queries; the
researcher 4.4-billion-target query-only scenario is about `2^111.98`, assuming
a coherent target-membership oracle over a 140.8 GB digest list.  Oracle
construction, qRAM, reversible lookup and fault correction are not priced.

### Cross-version double spend (XV)

A/B/C retain one real-nullifier equation and one selected spent set.  Subject
to a unique extracted opening, an A, B or C retry of the same funded occurrence
publishes the same nullifier and only one selected transition survives.

The property fails if an alternate accepted opening yields another nullifier,
an operation route omits the lifetime identity, activation admits a retired
route, a swap/supply path records spentness outside the atomic transition, or
rollback leaves spentness inconsistent.  A successor must consume a legacy
occurrence under its **legacy nullifier**.  Assigning a new wide nullifier to
old value would create a protocol-level double spend without breaking a hash.

### Unauthorized inflation (IN)

The hidden audit is defined by the opening used when an occurrence was funded,
or by a witness extracted from that accepted creation transition.  A later
debit must use the same monetary opening.  The audit does not select whichever
colliding opening makes post-hoc equations balance.

The concrete chosen-collision hypothesis fixes two disjoint canonical note
domains with native values four and five.  The adversary chooses valid owner
and randomness fields, finds a claw `CM(o4) = CM(o5)`, funds `o4`, then proves a
debit using `o5`.  Under extraction, authority and atomic-state premises, the
extra unit reaches accepted outputs and wins IN.  If the two openings yield
different real nullifiers, admitting both also threatens XV.  This is a
cross-value claw, not the assertion that every arbitrary collision is money.

The primary generic references are BHT's claw result
([Theorem 4](https://arxiv.org/abs/quant-ph/9705002)), BBHT's multiple-target
search bounds ([paper](https://arxiv.org/abs/quant-ph/9605034)), and the
separate no-qRAM CNS collision algorithm
([IACR ePrint 2017/847](https://eprint.iacr.org/2017/847)).  Applying their
random-function models to the constrained note encodings is an explicit
hypothesis.  It is not an analysis of the instantiated Poseidon2 permutation.

## Quantitative binding screens

The reproducible calculator and assumptions are in
[binding/RESULTS.json](binding/RESULTS.json).  The principal results are:

| Idealized game/model | Four words | Seven words | Boundary |
| --- | ---: | ---: | --- |
| Fixed target, Grover scale | `2^128` queries | `2^224` | Query only. |
| 4.4B usable targets | `2^111.98` queries | `2^207.98` | Unit-cost coherent target recognition. |
| BHT cross-value claw | `2^85.33` queries and table entries | `2^149.33` | Black-box, qRAM-like membership not physically priced. |
| Raw digest-list lower bound | `2^90.33` bytes | `2^155.14` bytes | Excludes indexes and fault tolerance. |
| CNS no-qRAM collision screen | soft-`O(2^102.4)` | soft-`O(2^179.2)` | Random-function inference; polynomial factors omitted. |

Seven whole Goldilocks words are the first width strictly above 128 query bits
for the checked ideal cross-value-claw game.  Five words suffice for the
checked target-search scenarios.  Seven is therefore a defensible engineering
screen for the selected collision obligation, not an unconditional theorem or
minimum for all monetary games.

## Exact noninteractive proof

The source and registered verifier geometry are mapped in
[proof/ASSURANCE.md](proof/ASSURANCE.md) and reproduced by
[proof/PARAMETERS.json](proof/PARAMETERS.json).  Profile C uses Goldilocks
`Fp2`, two PLONK challenge repetitions, 32 FRI queries, rate 1/32, cap height
four, five arity-four reductions and no grinding.  The registered MNG3 proof
is 179,264 bytes and its ordinary frame is 182,863 bytes.  A complete SLG3
swap is about 400,165 bytes in the measured funded fixture.

Published FRI, Plonky-like and Fiat--Shamir results do not automatically apply
to these bytes.  The missing correspondence includes the actual repeated
permutation/copy argument, quotient chunks, selector filtering, batched
two-point openings, fixed-statement gate, list/proximity theorem, transcript
compiler and adaptive many-proof composition.  No supplied result gives a
simulator for the complete hidden witness and receipt-correlated view.

The smallest parameter-only change examined is S64: three PLONK repetitions,
64 FRI queries and the same relation.  It calculates to a 391,551-byte ordinary
frame and about 817,541 bytes for a two-leg swap.  The smallest substituted
OPlonky expression is about 110.83 bits, but that substitution has no proved
index map to this implementation.  It is neither an upper bound nor an attack.
S64 therefore fails to certify the claim and exceeds the current 262,144-byte
frame; increasing the frame would solve only the transport condition.

## Joint payment privacy

The public-only analysis is in [privacy/PRIVACY.md](privacy/PRIVACY.md).  It is
strictly bound to the 59-file released archive.  The supported statements are:

- competing legacy/C retries of the same funding share both public nullifiers
  and are linked with certainty;
- suite, operation class, packet length, anchor/depth, fee, commitments,
  receipt framing and swap roles/expiry remain public;
- all 42 observed receipt envelopes and components are byte-distinct; and
- two labelled later spends have no direct public byte equality with their
  source commitments or receipts.

The last two are finite observations, not anonymity proofs.  Receipt
confidentiality remains conditional on the exact ML-KEM-1024/KDF/
ChaCha20-Poly1305 composition and uncompromised keys.  No result supplied here
establishes recipient/key anonymity, cross-key robustness, adaptive related-
statement proof ZK, later-spend unlinkability or post-backup-compromise privacy.
A complete 32-byte backup intentionally regenerates historical receiving and
spending material, so its compromise retrospectively links and opens receipts.

## Smallest coherent successor

The implemented N7P2 format is the local comparator.  It jointly widens owner,
note commitment, nullifier and ordered depth-40 tree digests to seven field
words, injects length and domain separation, authenticates count/position and
uses 56-byte successor commitments.  Merely squeezing three more words from
C's four-capacity-word sponge would not establish a seven-word binding claim.

The successor still leaves separate obligations:

- its Plonky2/FRI proof is not qualified for 128-bit adaptive quantum
  knowledge security;
- historical 32-byte asset and issuer identities require their own monetary
  analysis or widening for new issuance;
- receipts need a whole-view privacy argument; and
- historical C value remains authorized under C assumptions until consumed.

The funded bridge design in [migration/DESIGN.md](binding/migration/DESIGN.md)
uses a fresh canonical MNG3 payment as authorization and a second proof to
equate its two transient output openings with two N7 outputs.  The prototype
ledger keeps
the MNG3 input nullifiers, never inserts the transient C outputs, inserts only
the N7 commitments and charges the fee once.  Standalone C is retired at the
bridge activation height so the embedded packet cannot be stripped and raced.
This transition is not integrated into the current PoW block/packet codec.

### Migration evidence

The final measured migration table and public artifact identities are recorded
in the [author evidence](binding/migration/evidence-author05/RUN.json).  The
genuine run succeeded and establishes only the following bounded facts:

- the old funded inputs were authorized by a fresh MNG3 proof at an eligible
  selected-branch anchor;
- exact native/token/asset values were carried into the wider notes;
- selected current spentness and both conflict orderings were checked;
- fee, legacy nullifiers, successor outputs and retained proofs rolled back and
  re-applied atomically;
- a fresh process used the original 32-byte backup plus authenticated public
  history to recover the successor note and make a publicly verified N7 spend;
  and
- complete retained bytes and role resources were measured.

The fresh C packet was 182,863 bytes.  The equality proof was 225,660 bytes,
and the canonical migration bundle was 412,886 bytes: 150,742 bytes (57.5%)
over the 262,144-byte ordinary frame limit.  Equality proving took 7.65 s wall
and 1,853,652 KiB peak RSS; its warm public verification took 11.98 ms and
5,816 KiB.  The restored successor spend was a 234,646-byte N7P2 packet with a
230,805-byte proof; proving took 7.84 s wall and 1,866,336 KiB peak RSS, while
warm verification took 11.90 ms and 5,968 KiB.  These are one-host
measurements, not production bounds.

The bridge was admitted by the separate atomic migration ledger, not by
`devnet/chain.py`.  Its 412,886 bytes exceed the current 262,144-byte packet
limit, so a production activation needs an explicit versioned migration
frame/block rule and a new relay/validation/resource measurement.  Fitting such
a frame would not repair the proof or privacy assumptions.

The migration selected the prior milestone's independently generated H25 branch
with tip `0000028c...`; the older author privacy fixture has a different H25 tip
and cannot replay that branch.  Independent review caught the initial archive
mismatch.  Publication therefore pins the exact migration lineage separately
instead of treating either valid historical fixture as interchangeable.

It does not repair past C assumptions, prove either proof system secure,
establish joint privacy, or show that every holder should migrate.  The
production form should use a dedicated MNG4 relation binding the successor
destination/context under the legacy owner's authorization, rather than rely
on a general self-payment's transient output openings.

## Retain/change matrix

| Component | Decision | Qualification |
| --- | --- | --- |
| Candidate-height version dispatch and historical replay | Retain | Must remain branch-relative and cover every debit/supply/swap route. |
| Eligible anchor, verifier-owned depth/count and current spentness | Retain | Proof extraction and hash binding remain assumptions. |
| Common A/B/C lifetime spent set and atomic rollback | Retain | A successor bridge must insert the exact legacy input identities. |
| Bounded arithmetic, fee and per-asset conservation semantics | Retain | Re-express and prove them in every new relation. |
| Wallet backup and offline receipt workflow | Retain as interface | Change versioned key/note derivations; no forward secrecy claim. |
| Four-word owner/note/nullifier/tree binding | Replace | Conditional ideal monetary screens are below target. |
| Four-word new asset/issuer identities | Reassess or widen | A wide note alone does not repair issuance identity games. |
| Registered 32-query proof | Replace or externally qualify | Exact knowledge, FRI/QROM and HVZK correspondence is missing. |
| ML-KEM receipt hedge | Retain conditionally | Functional and confidentiality evidence is not recipient anonymity. |
| C-funded money | Preserve through explicit migration | No reinterpretation or second nullifier; historical risk remains. |

## Mainnet gate and next decision-changing work

Before a 128-bit mainnet claim, an external cryptographic review must answer
two exact questions:

1. For the selected new relation and noninteractive transcript, what theorem
   gives adaptive quantum knowledge/direct monetary soundness and zero
   knowledge with concrete losses for the implemented field, PCS/FRI,
   transcript, public binding and lifetime proof count?
2. For the selected wide commitment/tree/nullifier/issuer constructions, what
   instantiated assumptions imply Games US, XV and IN, including the chosen
   cross-value-claw game and all remaining narrow identities?

The next executable experiment should not add more C parameter heuristics.  It
should register one complete wide-note payment relation in a proof system for
which source, construction and theorem correspond exactly, then measure a
funded two-input payment, public verification, offline receipt/recovery and a
two-owner swap.  If no such theorem-backed backend fits a home-node profile,
the result must remain an explicit architectural blocker rather than a reduced
security claim.
