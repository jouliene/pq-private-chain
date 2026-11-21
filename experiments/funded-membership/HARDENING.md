# Funded membership and migration

This source review covers the public funded A/B release at
`415280581a07d3d246a5408ad32b7e3e922041e7` and its pinned Qnero commit
`f04c91307837c0231668383bec76ba98d89d2652`. It separates the exact relation
of a positive-value real input from the assumptions used to interpret that
relation as inclusion in the funded ledger.

## Components of the registered relation

| Component | Binding in A and B |
|---|---|
| Private opening and authority | The circuit derives the receiving public key from the input authorizing and nullifier keys, opens the typed note, computes its commitment and derives its real nullifier using the same nullifier key, rho and note opening. |
| Path | Each of two slots gets up to 20 quaternary levels, three private sibling digests per level and a range-checked position from 0 to 3. A single private depth controls the active levels of both slots. |
| Anchor | For each real slot the circuit equates all four final root limbs with the private header's tree-root limbs. The circuit hashes the header and binds the result and block number to public inputs. At admission the node compares the public anchor hash at that height to the eligible branch and checks current spentness. |
| Padding | A boolean dummy flag gates input membership. Dummy native and token amounts are zero. Real and dummy nullifiers have separate domain tags. Swap legs require a real first input. |
| Hashing | Each parent hashes the 16 field words of its four children with Poseidon2. The circuit inserts the running hash at the supplied rank and hashes the resulting order. The honest node and wallet sort child digests lexicographically by their canonical 32-byte encodings before hashing. |
| Issuance and swaps | Ordinary and swap-leg relations both call Qnero's common spend constraints. The typed ordinary relation also enforces its issuance/burn arithmetic. The swap leg binds its authorization key and output openings. A/B use distinct managed and swap verifier registrations. |

The wallet locally identifies its opened note at an append position, updates
the siblings along that position and calls `MerklePath::from_unsorted` with the
note commitment. The adapter sorts each quartet, supplies the running digest's
rank and recomputes the root. Private input decoding checks depth 1–20,
positive native or token value, and equality to the supplied anchor's tree
root. The public verifier does not call this private decoder. Its registered
circuit independently enforces the real-input root equation. [Wallet input
decoder](../user-assets/native/wallet.rs) · [Upstream Merkle gadget, path
adapter and frontier](https://github.com/DigitalGuards/qnero/blob/f04c91307837c0231668383bec76ba98d89d2652/crates/qnero-circuit/src/merkle.rs)
· [Upstream spend constraints](https://github.com/DigitalGuards/qnero/blob/f04c91307837c0231668383bec76ba98d89d2652/crates/qnero-circuit/src/circuit.rs)

A and B implement the same funded note and path relation. B changes the FRI
query count and proof tags. Each approved key remains bound to its own role.
Their public statement has 31 field words for managed operations and 34 for
swap legs. The funded nullifier is independent of an append index. [Managed
profile](../managed-assets/native/profile.rs) · [Swap profile](../atomic-swap/native/profile.rs)
· [B source transformation](../funded-upgrade/build.py)

## What the current statement establishes

The path's private depth is range-checked up to 20. Its equality to the
particular funded anchor's minimal tree depth is not a verifier equation.
The verifier also has no authenticated public count, chronological leaf index
or canonical child-order comparison. A position in a locally sorted quartet
records hash rank, which differs from the ledger's chronological append
position. Exact root equality is present and is meaningful independently of
those stronger properties. Inferring actual funded set membership from this
construction requires an argument for the variable-depth tree, padding, the
note-to-leaf commitment, parent compression and public header binding.
A missing structural equation does not by itself demonstrate a forged
payment. [Merkle gadget](https://github.com/DigitalGuards/qnero/blob/f04c91307837c0231668383bec76ba98d89d2652/crates/qnero-circuit/src/merkle.rs)
· [Header constraint](https://github.com/DigitalGuards/qnero/blob/f04c91307837c0231668383bec76ba98d89d2652/crates/qnero-circuit/src/header.rs)

N7P2 has a different network and note format. It uses 40 binary levels,
a constrained private index below an authenticated count, chronological
orientation obtained from the index bits, seven-word hashes and a
level-specific parent domain. Its nullifier also commits to the index and
note commitment. Its registered statement carries the common root and count.
Transferring this nullifier formula to A/B would create a second consumption
identity for the same funded note. [N7P2 relation](../advancing-note/proof/src/relation.rs)
· [N7P2 decision](../advancing-note/DECISION.md)

## Registered C relation

MNG3 and SLG3 retain the two B circuits' 32-query FRI profile and monetary
semantics. Each registers one additional public field element. It is wired
directly to the existing, range-constrained depth target and must be nonzero.
For each real input, the circuit requires its selected child digest to be
nonzero at every active compression, starting with the note commitment. It
also requires the selected final root to be nonzero. Empty siblings are
allowed. Old note commitments, real and dummy nullifier tags, output receipt
bytes, swap authorization keys and issuer signatures keep their funded
interpretations. [Common constraints](hardening.patch) · [Registered role
builder](build_c.py)

The native ordinary effect row appends the verified 32nd public word as one
canonical depth byte in 1–20. The swap role does the same with its 35th word.
For census purposes a funded block's anchor count includes every appended
reward and each transaction output, including zero-value outputs. The node
must compare the verified byte with the minimal quaternary depth derived from
the **referenced eligible anchor's own count**. For n>0 this is
`max(1, ((n - 1).bit_length() + 1) // 2)`. The node must reject an empty
anchor. Existing branch eligibility, current spentness, fixed fees and supply
authorization still apply.

For a real input under this rule, start from the authenticated funded root
and follow the proof's selected child down the exact number of tree levels.
If a claimed 16-word child tuple differs from the recorded tuple but gives
the same parent, the two tuples constitute a collision in the parent
compression. Otherwise the selected child is one of the recorded children.
Its constrained nonzero value excludes an absent position. Repeating the
argument at each level ends at an occupied commitment. This conditional
argument also requires header binding, commitment binding and knowledge
soundness of the entire profile. It proves no chronological index, and no
quantum-security level follows from this construction analysis.

Replaying historical A/B blocks at their original candidate heights preserves
their encodings and branch economics. At activation H25, all future supported
consuming operations require the C registration. This includes fixed issue,
managed register, mint and burn, both signed swap legs and ordinary payments.
The old nonzero-supply admission exception would defeat a universal
post-activation depth rule. Keeping the same real nullifier and chain-wide
spent set lets an original backup consume an old funded note once under C.
The stronger N7P2 chronological design would separately require a new ordered
accumulator over historical commitments. The current funded set-membership
decision does not require that migration. [Earlier dispatch and exception](../funded-upgrade/upgrade_rules.py)

## Build and wire costs

From a checkout containing the public pins, run the following with the same
pristine upstream and Cargo target accepted by the funded-upgrade build.

```sh
python3 -IB experiments/funded-membership/build_c.py NEW_ROLE_DIRECTORY UPSTREAM TARGET
python3 -IB experiments/funded-membership/profile.py | cmp - experiments/funded-membership/PROFILE.json
```

The builder uses the released native-role source generators, patches only a
temporary copy of the two checksummed upstream files and compiles the same
pinned Rust toolchain and locked dependency graph. Registration emission
precedes byte comparison with the reviewed role keys. The manifest records
the author's executable identities and generated source hashes. Installed
executables use the deployment's approval mechanism. A SHA of the old base
profile description identifies the input to the generator. The C constraints
are defined above and in the pinned patch and builder.

| Registered C object | Proof bytes | Complete bytes |
|---|---:|---:|
| Ordinary transfer | 179,264 | 182,863 |
| Issuer-signed managed envelope | 179,264 | 200,023 |
| One signed swap frame | 179,288 | 200,076 |
| Full signed swap, including both frames and framing | 358,576 | 400,165 |

Both role keys are 1,481 bytes and both blinded traces have 8,192 rows.
Relative to B the extra public depth adds eight bytes to each proof. These
fixed encoding sizes are derived from the registered keys. Fresh proof and
admission measurements belong to the integration run. [Decoded C parameters](PROFILE.json)
· [Source and registrations](registry/BUILD.json)
