# Fresh-genesis private spend decision

**Hold integration. Change the representation of private membership inside the proof.**
Two wallet-created constructions were priced for the same two-input user-asset
payment. VOLE-in-the-Head has the smaller projected packet. Its verifier would
receive 10,751,268 bytes per ordinary payment. The Picnic-UR port would need
424,891,726 bytes. Both also have open questions about quantum extraction for
the deployed transcript. Use the funded C software for monetary conformance
and the existing N7P2 implementation for wide-note comparisons.

## What was tested

The starting public commit was `7d5887842ba513c254128bbb5818bbd6617ce3fc`.
The shared relation uses two private paths in one ordered depth-40 tree. Each
funded occurrence has its own identity. An opening carries a private owner,
native amount, optional private asset and quantity, and salt. The same spend
key binds the opened note and its nullifier. One native and one asset
balance equation per leg use bounded integers. A first-time recipient can
spend one funded note with the second slot inactive. Both swap owners would
check their incoming receipt before signing the same ordered pair. Consensus
would charge both legs together and check spentness at inclusion.

The experiments exercised the monetary relation in cleartext, the receiving
codec and two real cryptographic components. The acceptance path used the
owner's preintegration stopping condition. Full new-genesis proof generation,
node admission, a mined swap and a fresh-wallet spend with the candidate proof
are consequently outstanding. C-to-N7 remains available through its
[existing reproduction](../funded-pq-assurance/README.md).

The wallet test creates 17 native units in a trusted test grant and issues
60 units of a fresh fixed-supply asset under a real issuer signature. The
proposed transfer sends 25 tokens and 8 native units to the offline owner,
returns 35 tokens and 6 native units to the sender, and pays 3 native units.
With only its 64-byte backup as private input, a fresh receipt process opened
the selected public row. The recovered note supplied the sole active input
of the onward clear assignment, paying 20 tokens and 4 native units and
keeping 5 tokens and 1 native unit after another fee of 3. The driver supplied
the history row and locally constructed path. Fresh re-encryption changed
both receipts and authorization while repeating both original nullifiers.
The onward nullifiers differed in this run. The separate swap tests exercise
the two balance equations and signing primitive. Full joint settlement is
outside this evidence. [Monetary oracle](binding/RELATION.md) · [Security games and lifetime calculations](binding/GAMES.md)

| Per two-input payment unless indicated | Generic binary VOLE, EM-256s | ZKB++ with the modified Unruh transform |
|---|---:|---:|
| Full relation AND gates / private input bits | 3,854,992 / 49,233 | 3,854,992 / 49,233 |
| Proof alone, derived | 10,747,278 B | 424,887,736 B |
| Complete ordinary packet, derived | 10,751,268 B | 424,891,726 B |
| Complete signed leg, derived | 10,781,196 B | 424,921,654 B |
| Complete two-owner swap, derived | 21,562,412 B | 849,843,328 B |
| Actual calibration | One committed funded-leaf hash, 119,056 B proof | LowMC L5-UR, 209,506 B signature |

These geometries include the private membership positions, the owner checks,
ordered commitments, two 1,792-byte receipts per leg and swap approvals. VOLE
uses a canonical bit-wire circuit and its proof-size API. Picnic pricing
assumes a versioned wider response-length encoding in hash inputs. The stock
implementation cannot serialize the generalized transcript as specified for
LowMC. Its long response hashes have costs comparable to the opened views.

For comparison the funded C ordinary frame measured 182,863 B, with about
400,165 B for its measured swap. Six C proving samples had a median 9.85 s
wall, 19.09 s CPU and 887,112 KiB peak RSS. Three warm ordinary verifications
had a median 8.78 ms wall. The restored N7P2 ordinary packet measured 234,646 B,
7.84 s proving with 1,866,336 KiB peak RSS and 11.90 ms warm verification.
Full source-matched 128-bit monetary assurance remains open for both references.
[Funded reference decision](../funded-pq-assurance/DECISION.md) · [C measurements](../funded-pq-assurance/proof/PARAMETERS.json)

## Independent-node cost

At 100M **included** operations/year, 90% ordinary and 10% two-owner swaps,
one copy of just the proposed packet bodies projects to 1.183 PB/year (VOLE)
or 46.739 PB/year (Picnic), in decimal units. Equivalently a single receiving
full validator would need 300 Mbps or 11.85 Gbps sustained just to receive one
complete copy over 365.25 days. The research comparison is a two-core node
with 100 Mbps down and 20 Mbps up. Block framing, fork data, interruptions,
TCP and redundant relay increase those costs. Offered traffic is the owner's
sizing input. This particular inclusion rate and load mix are research
assumptions. The participation finding follows even if future blocks support
much larger frames.

The VOLE leaf calibration measures wallet and fresh verifier work for **one**
SHAKE permutation with its own transcript startup. Multiplying either time by
99 would repeat fixed costs and overlook memory pressure. The proposed binary
payment's raw simultaneous prover allocation floor exceeds 4.37 GB for this
single-worker implementation. The Picnic stock wallet operates on LowMC. Its
payment verifier would replay one AND consistency equation per gate per
round, over 1.68 billion at 438 rounds, plus the affine logic, view hashes,
authorization and ledger checks. Full candidate peak RSS, durable admission
and wallet wall time have no measurements.

The binary VOLE source schedules 29.98 GB of verifier leaf-generator output
per complete EM-256s leg. Its faster EM-256f profile reduces the schedule to
3.48 GB and increases ordinary bytes to 15,633,690. Those are local generator
work bytes, additional to network traffic. For the proposed streaming Picnic
port, measured kernels give 4.99–5.09 s CPU per verification and 9.20–9.37 s
per proof before end-to-end overhead. The hypothetical buffers of about 3
and 3.5 MB respectively exclude the full wire packet and ledger. At 20 Mbps
upstream a lone sender would need at least 4.30 s for one VOLE ordinary packet
or 169.96 s for one Picnic packet. A pruned node still verifies incoming
packets. A restoring wallet needs the common authenticated history and
encrypted receipt rows. Physical pruned storage, wallet scan traffic and
block-level overhead for a future integration have no measured values.
[VOLE source schedules](proof/SIZES.json) · [Picnic work model](wallet/PRICE.json)

## Why changing the tree arity alone is insufficient

For a fixed 64-byte digest and three-byte parent prefix, each node of arity
`a` consumes `floor((3+64a)/136)+1` SHAKE256 absorptions. A dynamic program
over power-of-two arities from 2 to 256, with total capacity exactly
`2^40`, prices any sequence of such levels. Both binary and quaternary
trees attain the minimum of 40 permutations per path. Two paths therefore
require 3,072,000 Keccak chi ANDs even before child selection and the other
monetary checks. With unshared private paths this alone costs at least
8,448,000 VOLE bytes or 336,384,000 Picnic bytes. Changing the digest,
sharing paths under additional constraints, or compressing internal traces
would require a new calculation. [Calculator](membership_cost.py)

One native byte-field option also admits an inexpensive exclusion. At the
reviewed Talos revision a single fixed-block 512-bit Grøstl parent uses
5,376 witness bytes for its internal S-box data. Even ignoring every
multiplication slot, order switch and final opening, 80 parents and the
22 copies of the VOLE correction/witness vector cost at least 9,461,760
bytes. This is a sensitivity calculation for this particular implementation.
[Node implementation](https://github.com/TalosLogic/libtalos_voleith/blob/255f1a995b8542de453efef57db7aa47a09f3a03/circuits/grostl_gf8_circuit.c)
· [Byte-field serializer](https://github.com/TalosLogic/libtalos_voleith/blob/255f1a995b8542de453efef57db7aa47a09f3a03/proof/gf8_proof.c)

## Security and next decision

The target is resistance to a constant-success monetary violation at work
below `2^128` by an adaptive quantum attacker with classical access to wallets.
Any stronger claim on lifetime failure probability also needs a query budget,
corruption policy and concrete adaptive composition. For example Picnic's
design Lemma 5.9 contributes at most
`2(q_H+1)(2/3)^(t/2)` in its game. At `q_H=2^128` and `t=438` this
part alone gives a vacuous bound. Increasing repetitions reduces this term
while increasing bandwidth. The complete extraction argument includes more
terms. FAEST v2 Theorem 9.42 quantifies signature unforgeability for its
specified signing interface. Applying it to a generic circuit with branch
state, a new prover interface and correlated public receipts requires a
different correspondence argument. [Picnic design §5.3](https://github.com/microsoft/Picnic/blob/192cc046744a04d884a99940f92cfe443fda6081/spec/design-v2.2.pdf)
· [FAEST v2 §9](https://faest.info/faest-spec-v2.0.pdf)

Fresh notes use wide separate domains for owner, leaf, parent, nullifier
and issuance. Their strength still depends on the instantiated sponge,
key entropy and the exact witness extractor. An observer sees the same
nullifiers on competing spends, ample public size and timing information,
the branch anchor and fee, and paired swap approvals. Offline receipt opening
and seed recovery are functional conditions. Adaptive recipient hiding with
the entire proof, ciphertexts and later spends still needs a joint simulator.

The smallest next test is a pair of **linked** hidden parent hashes. Prove
that the first hidden digest occupies the secret left/right child of the
second, bind the resulting root to the verifier's statement, and reject an
inconsistent intermediate digest even when both individual permutations are
correct. Price the copy, selector and blinding overhead at 99 permutations.
Feneuil, Provin and Rivain report 63 KB for 100 Keccak permutations with
SmallWood+. Their batching mechanism gives a concrete reason to test this
specific link. That published number prices neither our fund ownership nor
the privately wired paths. Before any funding test, ask which source revision
implements the precise sum-check compiler and which QROM extraction and
adaptive ZK losses cover its hiding and terminal openings at our query budget.
[Authors' preprint, November 2026](https://eprint.iacr.org/2026/2880)

## Reproduction

Run from the public checkout on x86-64 Linux with Python 3.11+, GCC, GNU
make and time, CMake, OpenSSL development headers, curl, tar, xz and
sha256sum. Allow public HTTPS downloads and pass a new scratch path. The
runner checks the Node, Picnic and Talos source archive digests. Third-party
licenses travel in those archives. The experiment links Talos under
AGPL-3.0-only and builds Microsoft's MIT-licensed Picnic reference.

```sh
bash experiments/fresh-spend/reproduce.sh /tmp/fresh-spend-qualification
```

This runs the fresh funding/receipt/onward clear-relation checks, genuine
component proof and signature verification in separate processes, byte
calculations and membership sensitivity. A fresh clone generates new keys,
test notes and proofs. Repeated runs should agree in byte counts, while
timing and randomized public artifacts vary.
