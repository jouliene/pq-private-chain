# AST1 wallet

The AST1 deployment stages the ordinary client, private SQLite cursor and sender journal from the base devnet sources. It uses separate AST1 database filenames. Genesis contains no funded note. Each mined reward funds native value. The seed-only restore reads the common selected-chain ranges and privately opens each receipt against the registered role. The local cursor records the native value, asset ID and asset quantity, maintains the funded paths for positive notes and atomically rewinds all holdings.

Run the following inside a configured AST1 network, with ALICE and BOB replaced by existing wallet names and HOME_DIR by the private lab directory. Funds in ALICE must cover the 3-unit native fee. Each issue needs one or two native-only inputs. A token-bearing note plus a native-only note can fund a transfer.

```sh
./pqd assets --home "$HOME_DIR" issue ALICE 70 --intent issue-70
./pqd assets --home "$HOME_DIR" resume ALICE issue-70 --wait 60
./pqd assets --home "$HOME_DIR" balance ALICE
./pqd assets --home "$HOME_DIR" send ALICE BOB 0 "$ASSET_ID" 16 --intent first-transfer
./pqd assets --home "$HOME_DIR" send ALICE BOB 2 native 0 --intent native-transfer
```

The issuer's receipt credits the requested supply, and its change receipt returns the remaining native value. The command reports the new lowercase hexadecimal `asset_id`; use it as `ASSET_ID` for a subsequent transfer. A wallet's `balance` field is its native balance. Its `assets` object maps each currently positive asset ID to its integer balance. Token transfer amounts must be positive when selecting an asset. A native-only send can consume a mixed note if the single asset balance returns in full to change.

An intent binds the recipient, native amount, exact asset selector, token amount and issuance supply. A lost reply is resumed with the same intent. The first transmissible packet atomically reserves its ordered real inputs. Reproving after expiry consumes those inputs again, yielding the same issuance ID. An explicit new intent permits a new equal-sized issuance if new eligible funding exists. The default intent is deterministic for a wallet, address and identical request. A backup restores on-chain funds; resuming an uncertain sender intent also requires the private journal.

The prover wall interval includes wallet setup if it runs lazily, private input preparation and the role call. `prover_cpu_s` samples the role process tree around that call. `prover_role_peak_rss_KiB` measures the largest per-process high-water mark seen in that tree at its end and covers the role lifetime. The native role also reports its instrumented setup and proving steps. Wallet command results and private database files disclose holdings and local intent details and stay outside the general public capture.

Run `python3 -IB experiments/user-assets/wallet/check.py` for the pure selection, fee accounting, identifier encoding, staged compilation and durable request binding checks. Live proof creation, verification, mining, reorganization and recovery are exercised in the top-level AST1 walkthrough.
