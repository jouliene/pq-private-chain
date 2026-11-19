# Ordinary wallet on a continuously mined PoW devnet

Starting revision `82c803961996864782a5dee050a02b60b4341c0e`. A wallet synchronized yesterday must check its balance and pay an offline recipient today by downloading only changes. Build atomic persistent APV2 wallet cursors, inventory, spentness and local membership paths. Support unchanged heads, bounded direct common-data suffixes, interruptible fixed-prefix seed recovery during mining, shallow and deeper-than-undo reorganizations and verified fresh spending. Export public addresses. Persist sender-only intent and packet state before exposure; all retry authorizations must be mutually exclusive on a selected chain. Reproduce lost replies, reconnection and stale anchors. Compare against full replay and measure warm balance, warm send and cold restore at two substantially different history sizes, with actual history payload, serving reads, memory and elapsed time. Preserve the historical consensus, fees and proofs. Independently reproduce from clean checkout and publish with passing CI. Archive economics, end-to-end PQ/privacy and versioned private assets and swaps stay open.

## Historical milestone

# First runnable local proof-of-work devnet

**Bounded local devnet milestone.** Starting from public revision `46932763d7a0e6d03ea848ae2e22ab65ef48d5df`, deliver a runnable three-peer local network, two independent CPU miners, branch-valid APV2 singleton payments, scheduled spendable rewards, exact fees, seed restoration followed by spending, deep archival reorganization, and fresh genesis sync. Acceptance includes a clean independent reproduction, a published revision and a CI exercise of the changed path. The global private post-quantum blockchain objective remains active. See [the decision](devnet/RESULTS.md) and STATUS.md for the executable delivery and acceptance record.

## Historical milestone

# Advancing-chain independent wallet payments

From published cc2d9b9e6b6e5d4cbcd7e241f0025dc20c84b963, demonstrate and independently reproduce a payment path for the first local PoW development network. Preserve executable CP03 and WHIR. Before proving, register the stronger native parameters and their privacy/security boundaries. Execute 1–4 real payments from independent wallets at retained branch anchors, incremental authenticated state, durable rollback/restart, competing branches, conflicting spends and recipient spending. Measure sparse and busy load, lone-payer delay, alternate submission, before/after-inclusion bytes, builder work, pruned and recovery obligations with the 100M/year and 1/5 TB comparison scenarios. Preserve a versioned private token/native-fee and indivisible two-party exchange path. Publish actual results, independent reproduction and an executable recommendation. Global blockchain development remains ACTIVE.

## Bounded result

The independently reproduced research decision selects direct APV2 wallet authorization for the first local PoW devnet at the finite tested 0.10 new offers/s service point. Source-built four-way aggregation verified but expired at the ninth independently clocked opportunity in both runs. The result includes independent clean keys and proofs, receipt-only spending after restoration, branch/current-spentness and durable crash checks, strong-profile and cost evidence, and a reproducible public handoff. See [decision](experiments/advancing-payments/DECISION.md), [instructions](experiments/advancing-payments/REPRODUCE.md) and STATUS.md for the release record. The global permissionless post-quantum private blockchain objective stays **ACTIVE**.
