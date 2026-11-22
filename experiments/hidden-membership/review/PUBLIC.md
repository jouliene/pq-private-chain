# Independent public reproduction

The reviewer wrote no prover, funding fixture, calculator or implementation change. Starting in a newly created empty directory, the reviewer cloned the public HTTPS repository with an empty environment, disabled system/global Git configuration, credential helpers and prompts, and disallowed local transport and object alternates. The fetched origin/main and detached tested HEAD both resolved to `9dc3ca8ad63a47efe8982942296cc34debc527cd`. The starting revision `51897f17bc9e564160066770083b3bb682bf4131` is its ancestor. The initial clone was clean. Three public dependency downloads passed their pinned checksums. The run used CPython 3.12.3, NumPy 1.26.4 and a fresh native build. [Tested source](https://github.com/jouliene/pq-private-chain/commit/9dc3ca8ad63a47efe8982942296cc34debc527cd)

```sh
d=$(mktemp -d) && git clone -q --no-checkout https://github.com/jouliene/pq-private-chain.git "$d/src" && git -C "$d/src" checkout -q --detach 9dc3ca8ad63a47efe8982942296cc34debc527cd && bash "$d/src/experiments/hidden-membership/reproduce.sh" "$d/run"
```

The published code produced fresh signed funding, private inputs and proofs locally. The separate verifier processes received public prefix records, nullifiers and proof bytes. Reproduction did not depend on the author's scratch history, private openings or any previously generated full path packet. Randomized proof hashes and wall times may differ.

| Independent component | Bytes | Prover s / peak KiB | Public verifier s / peak KiB |
|---|---:|---:|---:|
| Four two-parent GF(2^16) cases | 87,760 each | See runner output | See runner output |
| Two parents, single GF(2^256) | 6,926,976 | 22.361 / 361,244 | 2.934 / 98,228 |
| Two parents, mixed fields | 241,664 | 6.244 / 102,760 | 1.012 / 97,724 |
| Two funded forty-level paths, GF(2^16) | 3,730,382 | 52.72 / 798,836 | 24.15 / 680,748 |
| Two funded forty-level paths, mixed fields | 5,966,544 | 244.38 / 2,604,740 | 43.93 / 1,961,296 |
| EM-256f one-input global lookup | 949,316 | 0.54 / 94,132 | 0.47 / 76,620 |

The reviewer verified the checked-in public calibration proof. Both VOLE outer orientations produced 228,902 B and rejected modified roots, proofs and detached witnesses. The new 53/64 table gave 231,954 ANDs and 2,182 private input bits. The public packet including NF had 949,380 B. Six public mutations and nine private opening failures were rejected. The all-index tests and 330 branch updates passed. The source matched the published alternative pricing byte for byte. The linked tests rejected a fully encoded pair of individually correct parents with an inconsistent hidden edge. Mixed field basis tests, all private orderings in the shared GF16 relation, and the packed transition reference also passed.

The reviewer examined the signed-prefix pin, root reconstruction, range, distinctness and private copy constraints, masked trace and base/extension field conversion, ahead of the public execution. The VOLE control has a free private inner ordering and explicit outer selector. The structured packed reference is clear arithmetic. The full proof covers funded ownership and nullifier derivation only. Private transfer settlement, quantum knowledge extraction and joint privacy with the receipt stream remain outside the demonstrated guarantees.

The 16-bit calibration at full depth used 3,723,978 witness coordinates and 3,746,507 rows. The verifier reconstructed 13 eligible positions and rejected the independently valid alternate order of the two signed issues. The clear field-equation test located failures in both authorized-opening joins after exchanging two otherwise intact paths.

The full runner exited 0 with a clean checkout. On separately created funding, the mixed profile consumed 229.20 user + 15.16 system seconds to prove and 42.14 user + 1.78 system seconds to verify. Verification rejected the other eligible order in 33.53 s. The corresponding GF16 rejection took 24.46 s. Calculated complete transfers and swaps remain estimates. Neither exercise performed a new payment under these proof systems.

| Independently regenerated file | SHA-256 |
|---|---|
| Complete and annual COSTS.json | `9366a4fdf61b86d239279f330dd2a371e92cf820909e58196e0105125446daa2` |
| Alternative PRICES.json | `a2c39e2975998e40909ae326d5e4f55ea3f96dc9f574845001f77049bb30e61f` |
| Packed transition evidence | `d673a07cc097cb19ade37fdab09b66a12b8d24da2522362a0fa33f8a97ae6cc3` |
| Preserved VOLE baseline SIZES.json | `ad98169b1359189bde41e9e05ca0e8bd740bcd1326a204aabfa06d1c7a09ae85` |

The separate mixed byte calculator also matched its checked-in result byte for byte.

## GitHub Actions

All four push runs reported success on `9dc3ca8ad63a47efe8982942296cc34debc527cd`.

- [Fresh spend qualification](https://github.com/jouliene/pq-private-chain/actions/runs/44974644146)
- [Local proof-of-work devnet](https://github.com/jouliene/pq-private-chain/actions/runs/44974644158)
- [Research payment smoke](https://github.com/jouliene/pq-private-chain/actions/runs/44974644125)
- [Two hidden funded inputs](https://github.com/jouliene/pq-private-chain/actions/runs/44974644212)
