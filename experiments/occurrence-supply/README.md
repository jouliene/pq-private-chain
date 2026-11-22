# Phase 1D decision — account for selected output occurrences

**Retain the deployed profile C rules for this accounting property.** Starting at a faithfully represented selected prefix, the public outstanding quantity for each registered asset equals the face value in its unconsumed output occurrences after every covered step. An output immediately contributes the value bound to its commitment. The mathematical account does not need a recipient spending secret or a real nullifier for that output at creation. No node, packet, wallet or consensus rule changed. [Lean history induction](Occurrence.lean) · [Assumptions and implementation mapping](ASSUMPTIONS.md)

## Why a private input identifies one funded birth

1. The branch supplies an eligible height, count and header. The proof exhibits a header at the same height and anchor hash. Binding of those two normalized header preimages fixes the tree root. The circuit's depth matches the selected count. A nonzero chosen child at each level excludes padding. Binding between the witness's four-child hash preimage and the selected level's preimages yields membership in the chronological prefix. Sorting the children does not authenticate a chronological index. [Sorted-path theorem](Anchored.lean) · [Header and slot bridge](Member.lean)
2. The selected ledger rejects repeated output commitments. The prefix member therefore has precisely one chronological position. Equality of the note commitments fixes the native and typed token openings there, under the local CM, NOTE and OPEN binding assumptions. This step identifies the value to debit. No position is added to the public statement. [`selected_position` and `funded_opening`](Occurrence.lean)
3. If that position had already been debited, both authorized openings would have the same recipient digest, `rho` and typed randomness. Owner-digest binding fixes their `nk`. The real nullifier is deterministic in those three arguments. It would already be in the selected spent set, contradicting the node's freshness check. Two real slots in one payment cannot debit the same position either. A dummy publishes a mark, contributes zero input value and acquires no position. Unrelated marks need not be globally collision-free for this conservation argument. [`same_spend_nf`, `fresh_nf_implies_unused_position` and `distinct_real_indices`](Occurrence.lean)

## What the induction covers

| Selected action | Occurrence and registry effects |
|---|---|
| Ordinary transfer | Real funded input values equal new output values for each token. Registry rows stay fixed. The native debit exceeds the outputs by the fee of 3. |
| Fixed registration | A previously absent ID gains exactly its positive issued amount, all in new outputs. |
| Managed registration | The same equality holds with a verified issuer authorization and a new immutable managed policy. |
| Managed mint | The selected managed row increases by the authorized amount within the ceiling. Its predecessor and revision must match. All other asset quantities are unchanged. |
| Holder burn | Funded token input value equals the token change plus the public decrement. Full burn may reach zero while keeping the registration. |
| Miner reward | The single reward creates zero tokens. For a covered block of up to four packets its native value is the subsidy of 100 plus 3 for each included packet. |

The new proof reuses the exact integer lifts and policy transitions of Phases 1A–1C. `selected_parent_block` derives the slot freshness checks from the selected public parent and matching anchor count. `checked_mixed_block` starts from the same parent registry and eligible birth prefixes for every packet, checks the block-wide NF, CM and supply-event-ID guards, and folds the modeled SQL writes in order. `selected_invariant` constructs the real debit book one step at a time. Its empty-prefix corollary is for the modeled operations. Applying it to the deployed H42 fixture requires a consistent inherited interpretation of the A/B/C and swap prefix. Public replay does not recover those private links. [History and block theorems](Occurrence.lean) · [Four-opcode packet mapping](../supply-refinement/OBLIGATIONS.md)

Where every historical birth *does* have an opened real-NF label, those labels are distinct, the previous real and dummy marks are faithfully classified, and dummies avoid those labels, Lean proves equality with Phase 1B for native and each token. These stronger inputs are needed only for the comparison. [Agreement theorem](Agreement.lean)

## Reproduction

On x86-64 Linux use Bash, Git, curl, GNU tar, zstd, Python 3.10+ and working unprivileged bubblewrap namespaces. From this checkout run one command in a directory with space for the pinned Lean release and three disposable nodes. It creates a new private directory, obtains checksummed public fixtures, checks the registered C runtime/key and generates fresh wallet keys.

```bash
bash experiments/occurrence-supply/reproduce.sh "$(mktemp -d)/case"
```

The kernel checks the induction, the membership derivation, the earlier arithmetic, the Phase 1B agreement and two finite controls. One control creates an output carrying 17 tokens for a digest outside a toy owner function's image. A separately authored control exhibits an occurrence worth 7 tokens with no compatible owner witness at all; an admissible dummy marks its own identifier and leaves that occurrence intact. Neither example makes a claim about finding preimages of the deployed hash. [Independent control](review/Boundary.lean)

The funded run replays 42 original selected blocks on three nodes. A miner creates a fixed asset with supply 40, then pays a previously disconnected fresh address. A fresh wallet process restores its seed, finds one note with 19 tokens and 9 native units and spends it. Independent verification of the real onward proof, private reopening, the authenticated prefix, and the confirmed outputs checks 7 tokens to the payee and 12 change; 4 native to the payee, 2 change and a fee of 3. Two fresh public marks enter the database for one real input. The three nodes agree at H48 with cumulative fees of 78. The three test balances sum to 40. The runtime additionally recomputes the actual normalized header hash and every selected Merkle level in Lean, checks the private path and compares every relevant witness parent preimage to the finite selected tree. [Observed aggregate counts](observed.json) · [Fresh wallet experiment](wallet.py) · [Executable path check](AnchorCheck.lean)

A non-author repeated the public command with fresh keys and independently reconciled the restored wallet with three selected ledgers. The three public summaries matched the developer and Phase 1D CI outputs byte for byte. [Independent reproduction and hashes](review/PUBLIC.md)

Only `wallet-result.json`, `kernel-result.json` and `source-result.json` are public summaries. The reproduction directory also contains backups, witness data, databases and correlations. Keep it private. The deployed validator and the public artifacts receive no private input-to-output mapping from the experiment.

## Assurance boundary

The Lean kernel checks statements about the defined transition system. Source inspection maps its checks to the pinned binary, circuit and selected ledger. A funded run tests one implementation instance. General application assumes soundness for the exact registered statement and collision exclusions on the concrete header, tree, body and owner preimages used by that history. Issuer authorization also requires the registered signature and key assumptions. There is no machine-verified binary refinement or quantitative post-quantum reduction for these joint premises. The sum measures face value, including outputs whose owner may never recover them. Wallet recoverability under arbitrary funding, privacy of proofs together with receipts and retries, and operations outside this induction remain separate obligations. [Audited premise list](ASSUMPTIONS.md)
