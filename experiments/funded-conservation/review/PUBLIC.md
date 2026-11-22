# Independent reproduction of funded C conservation

The Lean proof and funded wallet walkthrough passed at `8b4928140d5da645dcf209fded42f5edfa5c6ab0`. I cloned the public HTTPS origin into an empty directory with system/global Git configuration, prompts and credentials disabled, then detached at the observed `origin/main`. The checkout had no object alternates and descended from `6b0e56f`. I ran the command below with fresh wallet stores and the default public downloads. [Tested source](https://github.com/jouliene/pq-private-chain/tree/8b4928140d5da645dcf209fded42f5edfa5c6ab0/experiments/funded-conservation)

```sh
bash experiments/funded-conservation/reproduce.sh "$(mktemp -d)/case"
```

## What the proof establishes

The native and token premises are modular equations and per-slot bounds. Lean derives the natural-number equalities. The largest intermediate for two outputs plus the fee is 9,223,372,036,854,775,809, below the Goldilocks modulus of 18,446,744,069,414,584,321. A positive token quantity uses the transaction's private four-limb asset ID. Quantifying over each currency preserves the distinction between IDs and accounts for unrelated assets. State holdings count selected openings whose real nullifier is absent from the current spent set. In the block theorem the transactions debit their fees before one reward credits the subsidy and their sum. [Proof](../Conservation.lean) · [Source correspondence](../MAPPING.md)

I checked the kernel-reported assumptions for all 35 named theorems in the published model with Lean 4.19.0. Their combined dependencies were `propext`, `Classical.choice` and `Quot.sound`. The independent example constructs both `Gates` and `Admission` for a mixed-value real input in the second slot, a first-slot dummy, an unrelated asset differing only in the fourth limb, and an old spent note. Its live native total goes from 21 to 18 at settlement and to 121 after crediting the miner. The two token holdings stay at 9 and 19. Separate checks rule out a missing fee, changed fourth limb and differently encoded retry, and show that crediting the fee twice would break the block total. [Reviewer examples](Examples.lean) · [Recorded identities and results](observations.json)

## Correspondence to funded payments

The published command matched all twelve generated-source pins from Qnero revision `f04c913`, reproduced the released verifier key by running the approved executable, and checked five reward vectors. The MNG3 registration had 548 gates before blinding, 32 public words and degree bits 13. This checks pinned sources and the functioning released binary. The run used the prebuilt native executable. [Registration evidence](observations.json)

| Observation | Published H25 transaction | Independently funded H40 transaction |
|---|---:|---:|
| Anchor height / output count / depth | 24 / 44 / 3 | 39 / 83 / 4 |
| Confirmed inputs to the spent index | 2 | 2 |
| User outputs / miner notes | 2 / 1 | 2 / 1 |
| Packet size | 182,863 B | 182,863 B |
| Cumulative fees | 27 → 30 | 60 → 63 |
| Fee / subsidy / miner credit | 3 / 100 / 103 | 3 / 100 / 103 |

At H25 I verified the published packet, public proof, selected anchor, receipt bytes, spentness, zero issuance delta and resulting reward. Its individual hidden amounts come from the original owners' disclosure. At H40 two independently seeded wallet roles opened four notes. In native/asset units the two inputs were (20, 12) and (14, 16), the recipient got (28, 25) and change was (3, 3). Both funded input paths matched the selected tree. A separate wire reader reconciled the original blocks and selected databases on three nodes through H40, including 86 output commitments, 46 spent identifiers and five asset supplies. The fresh transaction, asset and block identifiers appear in the public observations. [Original owner disclosure](../original.json) · [Independent observations](observations.json)

**Verdict.** The result establishes ordinary transfer conservation for the modeled, opened face values under the stated admission and cryptographic premises. Going from arbitrary accepted proof bytes to a satisfying witness, binding each real input to one authorized funded occurrence, and excluding hidden output or dummy nullifier aliases remain assumptions. Recipient access to an opening, issuance, burns, swaps, privacy, quantum security and whole-node refinement remain outside the theorem. The H40 run checks correspondence for one genuine funded payment.
