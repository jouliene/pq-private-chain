# Independent public reproduction of funded C swaps

I reproduced both funded exchanges at `d16943a92b6c6b0e5efef14b4a6dd6d1680a3d93`. I cloned the public HTTPS URL into an empty directory. Git credentials, system and global Git configuration, local transport and object alternates were absent. The clone's initial `origin/main` and detached checkout identified that exact revision. I checked its ancestry from the Phase 1D handoff `773c6a7c6062a43c6488d489ad546d2927b14538`. The following command exited successfully with a new case, four checksum-verified public downloads and a fresh fetch of the pinned Qnero commit. The checkout stayed clean. [Tested source](https://github.com/jouliene/pq-private-chain/tree/d16943a92b6c6b0e5efef14b4a6dd6d1680a3d93/experiments/swap-occurrence)

```sh
bash experiments/swap-occurrence/reproduce.sh "$(mktemp -d)/case"
```

## Funded exchange and rejection

Two buyers each received 50 A for 5 B and paid a native fee of 3. I decoded the two selected blocks independently and recomputed both ordered authorization digests. In four owner-journal entries, the key, signed leg, digest and signature matched the physical frames. The seller initially consumed 90 A. In the second fill I queried the actual debits by spending frame and recovered both an older 10 A input and the exact 40 A change commitment from the first seller frame. Each frame's real debits had a corresponding proof-emitted nullifier. Both newly signed pairs and both selected block bodies differed from the author's run.

The three selected SQLite stores agreed on the eight spent marks and eight user outputs across the two blocks. Each block credited one miner reward of 103 and wrote zero registry events. The published run rejected a first-only pool submission, a sealed first-only block, a block with the pair repeated and a spent bundle. I separately restarted the local validators and submitted the **second frame alone** over the live RPC. The node returned `incomplete atomic swap`. All persistent tables matched a snapshot taken immediately before submission, and the pool was empty. This covers the observed rejection paths. Process crashes and concurrent SQL schedules require separate evidence. [Observed aggregate](../observed.json)

## Proof scope

The pinned role reproduced its verifier key and all six expected outcomes of the prove-and-verify controls. The public worker verified the two real proofs and two authorizations on the second exchange. Lean reconstructed the byte-exact queries for those four replies and checked their effects against the selected store. The replay also rejected altered ordering, a lone frame, an absent authorization verdict and a conflicting current mark. Lean 4.19.0 audited 34 named results using only `propext`, `Classical.choice` and `Quot.sound` where axioms were needed. [Wire replay](../Replay.lean) · [Kernel audit](../kernel.py)

I checked whether the history theorem already assumed the private pairing or the post-swap invariant. Each real slot instead supplies local wire equations, an eligible header and an occupied path. Under scoped header, tree, body and owner-key binding, chronological commitment uniqueness locates one birth. Any earlier real debit of it would have emitted the same nullifier and contradict current public freshness. The ordered public cardinality checks provide cross-item uniqueness. The fold obtains each successive block's consistency from the preceding one and accounts for the fee once. The effective output opening includes the signing key. The later input uses that committed value directly. A faithful imported prefix and the exact registered proof's satisfying-witness interpretation remain premises. The derivation covers committed face value; malicious-prover extraction, joint receipt privacy and universal recoverability remain open. [Packet refinement](../Bridge.lean) · [Selected-history induction](../Swap.lean) · [Source correspondence](../MAPPING.md)

## Public evidence

I downloaded the completed swap workflow's artifact separately using GitHub CLI. It contained exactly the three files below. All three matched the independently regenerated files byte for byte. The wallet observation also matched the tested commit's checked-in reference. [Swap conservation CI](https://github.com/jouliene/pq-private-chain/actions/runs/45027938773)

| Public file | SHA-256 |
|---|---|
| `case/observed.json` | `48ccaf2b35dae5e698f696dcb5f8efd79845f2f816f2d94c437fba95c2d98434` |
| `kernel-result.json` | `6da90cdb5d6b66f7d4f647b4c4c8610541d198b5c5a8c4aa097808ce9957dbc8` |
| `source-result.json` | `9d50b4d921c0ee029212ac77eae734234ac331b1a7be884ea7b403eb8c2e26e5` |

I checked the public GitHub API for all three applicable push runs. Each reported head SHA `d16943a92b6c6b0e5efef14b4a6dd6d1680a3d93` and conclusion `success`. [Funded C atomic swap conservation](https://github.com/jouliene/pq-private-chain/actions/runs/45027938773) · [Research payment smoke](https://github.com/jouliene/pq-private-chain/actions/runs/45027938716) · [Local proof-of-work devnet](https://github.com/jouliene/pq-private-chain/actions/runs/45027938721)
