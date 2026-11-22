# Independent verification of funded C supply

The published walkthrough passed from an empty anonymous HTTPS clone at `41c2e794f947390a286ff3b42f48be610c6ef3c8`. The origin advertised that exact main commit, which descends from Phase 1A at `1483b6c`. Git had no system/global configuration, credential helper, prompt or alternate object store. I ran the command below with the default public downloads, a new private output directory and no cache overrides. All three archive SHA-256 checks passed. The source checker regenerated 12 source pins, matched the managed executable and registered MNG3 key, and passed five reward vectors. [Public observations](observations.json)

```sh
bash experiments/funded-supply/reproduce.sh "$(mktemp -d)/case"
```

## Kernel and assumptions

Lean 4.19.0 compiled the 39 supply theorems with warnings as errors. Their printed dependencies used only `propext`, `Classical.choice` and `Quot.sound`. Seven observed supply events also satisfied the concrete token and registry equations. My finite example constructs admission, gates, a policy step and a selected path for a full holder burn. The second live asset differs only in its fourth ID limb and retains all 13 units. The burned row persists at zero, and its old signed predecessor fails the next mint check. [Independent examples](Examples.lean)

The universal conclusion follows from consistent starting holdings, satisfying openings, admission that identifies the real eligible unspent inputs, and the modeled envelope and registry rules. None of these takes the final supply equality as a premise. Three 62-bit quantities fit below the Goldilocks modulus before integer lifting. The theorem abstracts signature verification, hash binding and the link from hostile proof bytes to satisfying openings. The selected path covers ordinary transfers, the four C supply operations and token-neutral rewards. Consensus fork choice and database rollback were exercised in the walkthrough. [Formal model](../Supply.lean) · [Source correspondence](../MAPPING.md)

## Fresh funded branch

The experiment issued a distinct asset with `MAX = 2^62 − 1` and a new H42 tip. Two restored wallet roles opened all eight fresh receipt commitments. The holder balance after burn, remint and reorganization was 0, 1 and MAX. The signed extra mint at the ceiling failed. After the burn, its previous revision was stale. Both rejections preserved the selected node state and pending pool observed by the runner. I read all four final SQLite stores, decoded the retained block bodies and checked selected wallet history, outputs, nullifiers, registry revisions, cumulative fees and reward amounts. The four inherited asset rows agreed at every measured stage. [Branch hashes and amounts](observations.json)

| Selected state | New asset quantity | Revision | Fees to date | Miner credits to date | Spent nullifiers |
|---|---:|---:|---:|---:|---:|
| H39 before fork | MAX | 1 | 57 | 3,957 | 42 |
| H40 full burn | 0 | 2 | 60 | 4,060 | 44 |
| H41 remint | 1 | 3 | 63 | 4,163 | 46 |
| H42 winning branch | MAX | 1 | 57 | 4,257 | 42 |

All four nodes selected the same H42. Its three descendants of H39 contained only rewards. The selected registry returned to the original issuer and registration transaction. A retained both displaced bodies among 45 mined blocks. D accepted exactly 42 winning bodies from genesis and matched A's selected state, including eight registry events and 84 output leaves. [Store readback](observations.json)

## Historical receipt provenance

Public H33 replay recovered the four C deltas of +6, +13, +15 and −16 at H28, H29, H30 and H32, respectively. Final quantities were 80 and 13 for the fixed assets and 97 and 15 for the managed assets. An outsider can replay the public registry, compare the published aggregates and generate fresh wallets for the full-burn case. [Historical aggregates](../original.json)

After the anonymous run, I separately used the eight original test-wallet backups privately supplied for this check. The committed receipt scanner matched all 40 distinct encrypted commitments and reconciled holdings across all eleven captured states, including the alternative H25. Its aggregate output matched the published historical file byte for byte, SHA-256 `7a876605cd38396cd75cbd16535b7e47a5c9cd7af74bd384f961ebacd0b7de77`. Repeating that historical decryption requires the original private backups. [Receipt scanner](../openings.py)
