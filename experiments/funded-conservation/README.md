# Monetary conservation for an ordinary funded C transfer

**Decision. Close the phase-1 arithmetic and selected-ledger accounting requirement for ordinary C transfers under the stated opening and proof assumptions.** Retain the funded C reference. The kernel-checked result starts with local MNG3 equations and selected spent identifiers. For any user asset, live committed face value is identical before and after the transfer. Native face value decreases by exactly three units until the miner receives them. In a block containing this transfer alone, the net new native value is the scheduled subsidy of 100.

## What Lean checks

1. Each of the two input and two output slots contains a native amount and a token quantity in `[0, 2^62−1]`. Local gates connect modular sums and a public fee of 3. The largest sum of two amounts is 9,223,372,036,854,775,806. Even two maximal outputs plus the fee reach only 9,223,372,036,854,775,809, below the Goldilocks modulus 18,446,744,069,414,584,321. Thus intermediate field reductions preserve the natural-number equations. The maximum valid assignment and the first out-of-range quantity have concrete kernel checks.
2. Each positive token quantity in the witness uses one common private four-limb asset ID. A zero quantity contributes zero for every queried ID. Consequently `local_conservation` quantifies over **every** ID, including IDs differing only in the last limb. The dummy selectors enforce zero value. The positive ordinary fee requires at least one real input.
3. `selected_conservation` projects the selected branch's append-only notes onto openings whose real nullifiers are still unspent. It derives the debit from distinct, current, previously funded inputs and credits both outputs. The node keeps historical commitments after a spend. Summing the entire commitments table would count spent money again. The theorem covers one or two real inputs, either dummy slot and any unaffected notes. Reusing one of the consumed nullifiers on the same branch fails even if the rest of the transaction changes.
4. `ordinary_block` adds the fees of the included ordinary payments to **one** reward with zero token value. It proves that native holdings rise by exactly 100, and holdings of each asset stay constant. The node separately accumulates fees for historical accounting. This counter creates no additional note. Lean also bounds the ordinary-only cumulative counters over the 32-bit height range. The formal model sums face values in arbitrary list order. The network authenticates chronological append order and validates block-wide uniqueness before its atomic write.

The generic proof uses Lean 4.19.0 and its standard library. The runner compiles source, checks the axiom dependencies of the four main results, and accepts only standard kernel axioms (`propext`, `Classical.choice`, `Quot.sound`). The independent review supplies a mixed-asset model state satisfying the premises, a dummy slot, a pre-spent note and a mined block. Its negative controls cover an omitted fee, a fee credited twice, a wrong fourth asset limb and reuse of a consumed input. [Lean derivation](Conservation.lean) · [Reviewer examples](review/Examples.lean)

## What the funded implementation did

The historical MSP3 ordinary payment was selected at H25 against H24, with 44 funded commitments and tree depth 3. A new public verifier checked the original 182,863-byte packet. In the separate owner check, fresh wallet processes used the original two private test backups and selected ciphertexts. The registered wallet recomputed each successful opening's commitment; the two derived input nullifiers matched the packet, and both source commitments had paths to the independently reconstructed H24 root. The table records intentionally disclosed test amounts.

| Opened note or public credit | Native units | Units of the user asset |
|---|---:|---:|
| First funded input | 20 | 12 |
| Second funded input | 14 | 16 |
| Recipient output | 28 | 25 |
| Sender change | 3 | 3 |
| Fee included in the miner's reward | 3 | 0 |

Native inputs total 34, exactly 31 in user outputs plus 3 in fees. The 28 token units reappear in full. The block appended two user outputs, consumed both input nullifiers and appended one miner reward of 103. The reward commitment checked against the independent funded-note hash reference. The fee counter rose from 27 to 30 and the asset registry recorded no supply event. [H25 evidence](original.json) · [Historical wallet observations](../funded-membership/evidence/OWNERS.json)

The public reproduction replays the original public H25 proof and block inside the released 33-block prefix. It then mines new rewards, registers a fresh user asset, funds two new notes, and makes the same ordinary transfer at H40 using normal wallet commands. It opens all four notes with newly generated independent keys, compares selected balances, and instantiates the Lean theorem with the decoded values and asset limbs. The new parent contained 83 leaves at depth 4. The three validators selected the new block. H40's fee counter rose from 60 to 63. Public replay verifies the original H25 effects; its historical private amounts are owner disclosures. H40 supplies the independently repeatable private-opening check without distributing the original backups. [Fresh director run](fresh.json) · [Fixture driver](funded.py) · [Opening and block checker](audit.py) · [Ground Lean instances](ground.py)

## Where the argument depends on cryptography

The deployed ordinary verifier must accept only statements with corresponding satisfying witnesses. A real input's opened commitment and owner-derived nullifier must designate the same funded note on the eligible branch. Typed note, owner, header and tree binding, real/dummy separation, and absence of relevant nullifier aliases link the model to money. The node can compare public nullifiers with its selected spent set. It cannot inspect every new output's future true nullifier, its recipient's secret or the entire network's private inventory. The ledger theorem assumes a consistent, non-aliasing assignment of these openings. Currency conservation on witness values alone does not give every recipient a decryptable or collectible output. The fresh case checks actual decryptability for its two wallets.

The selected prefix's earlier issuance, A/B transitions and swaps supply initial inventory. This proof covers the ordinary transition only. Source regeneration, re-registering a key and verifying genuine packets test implementation correspondence. They are separate from a verified compiler, a Rust-to-Lean refinement, a 128-bit quantum knowledge bound and joint proof/receipt privacy. [Premise-by-premise source map](MAPPING.md) · [Funded C cryptographic assessment](../funded-pq-assurance/DECISION.md)

## Reproduce

On Linux x86-64, use Bash, Git, Python 3.10 or newer, curl, GNU tar, zstd, sha256sum and bubblewrap with working unprivileged namespaces. The run needs loopback sockets for three isolated devnet nodes and storage for the extracted Lean distribution. No Rust build is required. Run from the checkout root in a new private directory.

```sh
bash experiments/funded-conservation/reproduce.sh "$(mktemp -d)/case"
```

The command pins the Lean binary distribution by SHA-256 and its compiler Git revision, two published project archives by SHA-256 and the upstream source by Git commit. It regenerates all 12 pinned managed source files, compares the registered key, checks five actual reward commitments, replays the membership vectors, and runs the funded and Lean checks. The scratch directory contains test wallet backups. Only the summaries `result.json` and `source-result.json` are designed for publication. Inspect `sources/` for the generated circuit and staged node lines in the mapping. To repeat only the Lean checks after a run, issue `python3 -IB experiments/funded-conservation/ground.py "$case/lean-4.19.0-linux/bin/lean" "$case"` with `case` set to that run's directory. [Pinned commands and checksums](reproduce.sh) · [Official Lean release](https://github.com/leanprover/lean4/releases/tag/v4.19.0)
