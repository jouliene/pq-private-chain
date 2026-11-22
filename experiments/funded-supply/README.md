# Phase 1B — outstanding token supply on the selected C ledger

**Decision. The funded C registration, mint and burn rules preserve the per-asset supply invariant from a consistent selected state, subject to the funded-opening and proof assumptions below.** For every possible asset ID, the latest public outstanding quantity equals the sum of the token face values of its unspent funded notes. An ID absent from the registry has outstanding zero. A registered asset burned to zero retains its row, authority and revision.

## Derivation

Let `I` and `O` be the two input and two output token sums, and let `q` be the magnitude of the public supply word. Its bit 62 selects burning. The circuit rejects a burn flag with zero magnitude. The public ID equals the private typed-note ID for an active supply operation. For a satisfying witness the circuit equates `I + mint` and `O + burn` in the Goldilocks field. Each of the three possible addends on either side is at most `2^62−1`. Even their sum, 13,835,058,055,282,163,709, is below the modulus 18,446,744,069,414,584,321. The equality therefore lifts to natural numbers.

A registration or additional mint forces the two input token quantities to zero and credits exactly `q` to the outputs. A burn debits exactly `q` from holder-controlled funded inputs net of outputs. Both operations debit the usual 3 native units for the fee. A native miner reward has zero token quantity. The node binds the ordinary fee charge and block reward to the selected ledger. The supply theorem's conclusion concerns token holdings.

| Operation | Registry authorization | Change of live notes and public supply |
|---|---|---|
| Fixed registration | New network-derived ID bound to the first real input nullifier | `+q`, immutable fixed policy |
| Managed registration | New ID bound to network, issuer key and first real input nullifier, signature at initial revision | `+q`, persistent issuer key |
| Managed mint | Same issuer, signature for the exact inner packet and current event revision and predecessor | `+q`, bounded by the outstanding ceiling |
| Voluntary managed burn | Proof of a holder's eligible unspent notes, sufficient outstanding quantity | `−q`, issuer key retained and revision advanced |

`selected_supply` derives the change to live note value. `registry_delta` independently derives the change to the latest row. `preserve_supply` combines them, including unrelated IDs. `consistent_path` composes admissible supply events, ordinary C transfers and token-neutral miner rewards. Its starting state may already contain fixed and managed assets. The Lean file imports the previously checked funded-note and spentness model. Concrete checks cover the ceiling, full burn, burn with token change, a wrong fourth ID limb, a stale signed mint and a fixed-asset burn. [Machine-checked invariant](Supply.lean) · [Reviewer controls](review/Examples.lean) · [Exact circuit, node and cryptographic mapping](MAPPING.md)

## Reused funded evidence

The published graph contains 33 blocks on the winning branch and a competing H25 block. The director restored all eight original test-wallet keys in separate native wallet roles and opened **all 40 distinct encrypted receipt commitments** across both branches. At every block in each of the ten published checkpoint histories, the checker removed spent note identities, added newly opened notes and compared each live token sum against its accumulated public events. It also compared all ten checkpoint registries against the original wire replay and wallet disclosures. Public reward notes carry zero tokens.

| C block | Event | Opened token inputs | Opened token outputs | Outstanding before → after |
|---|---|---:|---:|---:|
| 28 | Additional managed mint | 0 | 6 | 107 → 113 |
| 29 | Fixed registration | 0 | 13 | 0 → 13 |
| 30 | Managed registration | 0 | 15 | 0 → 15 |
| 32 | Holder burn | 16 | 0 | 113 → 97 |

Final outstanding quantities were 80 and 13 for the two fixed IDs, and 97 and 15 for the two managed IDs. The published workflow validates the original mined packets, public states and disclosed totals. Decrypting the historical receipts again requires their owners' private backups. The archived A/B prefix and swaps are executed by the registered node during replay. They supply tested history outside the induction over C supply operations and ordinary transfers. [Original opening observations](original.json) · [Receipt and branch reconciliation](openings.py)

## Missing boundaries tested with fresh wallets

The H33 fixture contained neither a full burn nor a managed asset at the ceiling. Two new wallet owners extended that same chain. Their registered ordinary proofs, issuer signatures, note openings and mined blocks were checked under the existing network rules.

| Selected state | New asset outstanding | Observation |
|---|---:|---|
| H38 | 4,611,686,018,427,387,903 | Managed registration at the ceiling |
| H39 | 4,611,686,018,427,387,903 | A different holder received all tokens and 3 native units |
| H40 on the first branch | 0 | Holder burned the entire receipt, paying the native fee. The managed row and key remained at revision 2 |
| H41 on the first branch | 1 | The issuer minted one unit from the zero-supply row, at revision 3 |
| H42 on the heavier branch from H39 | 4,611,686,018,427,387,903 | Both supply changes detached. The holder recovered the full amount and the registry returned to revision 1 |

The same genuine signed one-unit mint was rejected at H39 for exceeding the ceiling and after the burn for referring to the old revision. Both rejections left the selected tip, registry, spent-set digest, fee total and pending pool intact. The H42 branch contained three empty replacement blocks. A fourth validator started with an empty database, received only the winning originals and validated from genesis. Its selected commitments, spent set, registry revisions and fees matched the reorganized validator and an independent wire reader. The losing fees totalled 63 and the winning fees 57. The two supply events' six native fee units were rolled back. [Funded experiment](campaign.py) · [Director's observations](fresh.json)

## Assumptions and scope

The arithmetic is kernel-checked. The correspondence from an accepted public packet to these transitions assumes sound verification for its bound statement, unique funded note and owner openings, correct real/dummy nullifier identity and current selected spentness. Issuer authorization also relies on SLH-DSA verification, key control, hash binding of the signed bytes and registration IDs, and correct verifier registration. These conditions are identified separately from ledger-enforced comparisons. The invariant concerns committed face value. A recipient also needs a usable key and a decryptable receipt to spend. This milestone provides neither a quantitative end-to-end quantum bound nor a joint privacy theorem. [Source mapping and assumptions](MAPPING.md)

## Reproduction

Use Linux x86-64 with Python 3.10+, Bash, Git, curl, GNU tar, zstd, sha256sum, patch, bubblewrap with user namespaces, and loopback access. Run from the checkout root. The pins cover Lean 4.19.0, the funded C release, the original public history and the exact upstream source revision for circuit regeneration.

```sh
bash experiments/funded-supply/reproduce.sh "$(mktemp -d)/case"
```

The private run directory contains the new wallet backups and databases. `result.json` and `source-result.json` are the public summaries. `kernel/axioms.txt` lists the proof dependencies. Only the standard Lean axioms are permitted. To repeat the original owner's additional check with separately authorized backups, use the following from the checkout root, substituting the downloaded public archive directory, release deployment and private original network home.

```sh
python3 -IB experiments/funded-supply/openings.py "$case/history/public" \
  --deployment "$case/network/deployment" --original "$original_owner_network"
```
