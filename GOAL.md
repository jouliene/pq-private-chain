# WHIR for funded transfers and native-for-token swaps

Compare every released public word on identical funded openings, verify both new swap legs and a two-input transfer, reacquire both signatures, and test recipient recovery and spending. Price the security and resource profile before selecting retain, revise or replace. The live MNG1/SWP1 devnet remains the reference.

## Earlier milestone

# Stranger token-for-native exchange

Start from ccf62bf7b271f49f96efdc0cc49cab19e972fb44. A taker who has only 100 managed test dollars and network bootstrap information discovers two unrelated makers, privately obtains firm quotes, trades 20 dollars for 8 native with the maker paying 3, restores from seed and pays 5 plus the ordinary fee of 3. Use two independent short-lived advertisement relays, authenticated encrypted wallet transport, the original SWP1 consensus, separate observers and actual mined admission. Demonstrate loss of one relay, stale quote, identity substitution and maker disconnect. Account for discovery, negotiation, settlement, inclusion time and the absence of abandoned sessions from consensus history. Publish independent clean reproduction, topology and residual privacy and quantum assumptions.

Both the two-host author exchange and the non-author clean run settled the funded quotes. A restored wallet spent the winning 8-unit note alone. Both runs retained public history and separate traffic evidence. [Results and commands](experiments/stranger-swap/README.md) · [Independent verification](experiments/stranger-swap/review/REVIEW.md)

## Earlier milestone

# Pay a first native fee with the proceeds of a private swap

Start at 998b39809b4464a9901161530d60f670b9bfaa7a. A seller with 100 managed dollars and zero native exchanges 20 dollars for 8 native, with a single fee of 3 paid by the counterparty. Recover the seller from its 32-byte seed and send 5 native plus the ordinary fee of 3 from precisely that received note. Verify 80 managed and zero native, both fees and rollback. Exercise underpayment and currency substitution before consent, the published SLG1 verifier, and legacy token-for-token swaps. Publish a wallet walkthrough, public replay and independent clean reproduction. Offer discovery and the separate WHIR frontend remain queued.

The author and a non-implementing reviewer completed the scenario independently, including the exact note-to-spend check, old public verifier and reversal of both fees. [Walkthrough](experiments/atomic-swap/NATIVE_CURRENCY.md) · [Independent run](experiments/atomic-swap/review/NATIVE-CURRENCY.md)

## Earlier milestone

# Decide the spend-proof profile for funded payments and swaps

Evaluate the MNG1 and SWP1 spend proofs from 3f08bff0089096d7fb27279bc0d444006e9147ce. Reproduce a funded ordinary transfer and a two-owner swap, audit the implemented transcript, receipts and monetary relation, then compare decision-relevant alternatives under the preregistered [quantum target](experiments/spend-proof-decision/TARGET.md). Publish independently checked evidence, complete costs, funded-note implications, the decision and the next experiment. Token-for-native swaps are next in the product queue. The global blockchain objective remains active.

The bounded evaluation concludes with a retain decision for the live devnet. Both the signed K384 comparison and compact transport were independently reproduced. A limited WHIR frontend port established unchanged legacy parent-hash compatibility. Production selection remains open. [Final decision](experiments/spend-proof-decision/DECISION.md) · [Independent review](experiments/spend-proof-decision/review/REVIEW.md)

## Earlier milestone

# Native same-chain private atomic swap

Two independent wallets exchange 7 fixed units for 30 managed units and pay one agreed native fee. Both check exact incoming spendable receipts before release and bind the same complete joint terms to both leg authorizations. Exercise incomplete offers, changed terms, expiry, conflicting ordinary spend, reorg and restored respend under real PoW. Measure both wallets, wire, block and verifier, then publish a fresh independent reproduction. The global blockchain objective remains active.

The clean independent build and mined two-wallet exercise have run. The [operator guide](experiments/atomic-swap/README.md), [non-author audit](experiments/atomic-swap/review/CLEAN.md) and [release readback](https://github.com/jouliene/pq-private-chain/releases/tag/private-atomic-swap-2026-11-20) record the bounded milestone and its verification boundary.

## Earlier milestone

# Managed supply and voluntary redemption

Starting at AST1 revision 006b8fb8d91a3e61dfb97b666e7bb6ca5748412d, deliver a live native managed asset while retaining existing funded fixed assets and private wallet transfers. Register 1,000 under a permanent issuer, mint 300 with different fee funding, privately pay and restore an offline holder, voluntarily return 200 to treasury and spend the returned note to burn it. Validate outstanding 1,100 from genesis. Require independent clean reproduction, negative monetary controls, reorganization across the burn, durable at-most-once simulated cash payout and an explicit account of outstanding obligations after a deep fork. Publish source, raw public evidence, measurements and reproduction commands. Swaps are deferred. The broader blockchain project remains active.

The author and independent reviewer reproduced the mined upgrade, supply changes, recovery, return, burn, deep reorganization and recovery of the simulated liability. Fresh-node replay agreed with the final supply and native fees. [Acceptance evidence](experiments/managed-assets/README.md) · [Independent results](experiments/managed-assets/review/CLEAN.md)

## Earlier milestone

# Permissionless fixed-supply user assets

Deliver ordinary wallet issuance and private transfer of multiple user-created fixed-supply assets on the same live PoW devnet from 2bac7cc7e53fb4b5ddbe999d1e634224ba937900. Each user can issue by spending native fee funds under the same verifier. Verify seed-only recovery, both assets and native change, subsequent spending, uniqueness, branch-local issuance, cold replay and independently reconciled balances. Measure complete costs and publish the clean independent reproduction. Retain TKN1. The global blockchain objective remains active.

The author and non-author both mined two branch-scoped issuances, ran offline recovery, paid both tags and re-spent the received outputs. The clean independent replay reconciled twelve selected payments and eleven wallet balances on a 104-block chain. Sources, public captures, separate verifier/prover costs and release readback are linked in the [research result](experiments/user-assets/README.md). Atomic swaps remain a separate milestone.

## Earlier milestone

# Live private-token PoW devnet

Deliver live TKN1 token-only receipt, separate mined native funding, seed recovery and subsequent spending on a separately identified local PoW network. Check fork selection, reward rollback, duplicate/retry linkage and monetary reconciliation. Compare a stronger complete proof profile on the same relation. Publish an independently reproduced decision.

The [live walkthrough and public replay](experiments/token-devnet/README.md) record the accepted local behavior, independent results and remaining security obligations. The broader blockchain objective stays active.

## Earlier milestone

# Private spend profile for one research token

Decide whether a registered spend relation supports two separately conserved private balances with ordinary offline receipt and a native fee. Compare a dedicated research profile with DLF1. Determine archival compatibility separately. Reproduce genuine funding, public verification, receipt and spending after seed restoration. Start from 9c21c2b4297657b8c4cca219c4c480910557d00e. Keep DLF1 and D8C1 executable and keep the global blockchain objective active.

The [architecture decision and measurements](experiments/token-profile/README.md) record the prototype selection and the separate limits on archival verification and cryptographic assurance.

## Earlier milestone

# Delayed DLF1 certificates for historical validation

Evaluate a real certificate over up to eight independently funded DLF1 payments across multiple PoW blocks from baseline d9e4114967302916354a7f75787ada2b5e2d27fe. Retain unilateral admission. Compare complete archival liability, builder capacity and public verification against 1/5 TB scenarios per 100M payments. If viable, require a versioned statement-committing core, independent peer-only genesis verification after destructive pruning on disposable stores, missing-data pause/resume, atomic compaction, a boundary reorganization, offline seed recovery and a new spend. Publish a measured decision and independent reproduction. Global blockchain goal active.

## Earlier milestone

# Next complete payment-proof architecture

From published wallet/devnet commit `6502ebe7c01e174bcc8b9718130d7cb5f5dd8e63`, decide whether a compact wallet proof or a shared-proof design materially reduces total payment costs with public verification, unilateral direct inclusion, moving anchors, offline receipt and seed-only recovery. Test primary compact and aggregation approaches, pivot after rejection, and exercise a surviving complete 2×2 construction with fresh independent senders, conflict, reorganization and restored recipient spending. Include full channel, archive, retention, CPU and verifier budgets for 100M included per year under sparse/busy load. Examine security, public linkability, the separate hybrid receipt question, and extension to native assets and indivisible swaps. Complete with published exact source, measurements, independently reproduced decision and actionable next experiment. Retain the APV2 wallet baseline. Global blockchain objective active.

## Historical milestone

# Ordinary wallet on a continuously mined PoW devnet

Starting revision `82c803961996864782a5dee050a02b60b4341c0e`. A wallet synchronized yesterday must check its balance and pay an offline recipient today by downloading only changes. Build atomic persistent APV2 wallet cursors, inventory, spentness and local membership paths. Support unchanged heads, bounded direct common-data suffixes, interruptible fixed-prefix seed recovery during mining, shallow and deeper-than-undo reorganizations and verified fresh spending. Export public addresses. Persist sender-only intent and packet state before exposure; all retry authorizations must be mutually exclusive on a selected chain. Reproduce lost replies, reconnection and stale anchors. Compare against full replay and measure warm balance, warm send and cold restore at two substantially different history sizes, with actual history payload, serving reads, memory and elapsed time. Preserve the historical consensus, fees and proofs. Independently reproduce from clean checkout and publish with passing CI. Archive economics, end-to-end PQ/privacy and versioned private assets and swaps stay open.

## Acceptance record

The ordinary CLI, cost measurements, fault reproductions and scope are recorded in [the wallet decision](devnet/WALLET_RESULTS.md). The final exact public revision, separately observed CI results and independent final checkout are identified in the [release readback](https://github.com/jouliene/pq-private-chain/releases/tag/incremental-apv2-wallet-2026-11-19). The global permissionless private blockchain objective remains active.

## Historical milestone

# First runnable local proof-of-work devnet

**Bounded local devnet milestone.** Starting from public revision `46932763d7a0e6d03ea848ae2e22ab65ef48d5df`, deliver a runnable three-peer local network, two independent CPU miners, branch-valid APV2 singleton payments, scheduled spendable rewards, exact fees, seed restoration followed by spending, deep archival reorganization, and fresh genesis sync. Acceptance includes a clean independent reproduction, a published revision and a CI exercise of the changed path. The global private post-quantum blockchain objective remains active. See [the decision](devnet/RESULTS.md) and STATUS.md for the executable delivery and acceptance record.

## Historical milestone

# Advancing-chain independent wallet payments

From published cc2d9b9e6b6e5d4cbcd7e241f0025dc20c84b963, demonstrate and independently reproduce a payment path for the first local PoW development network. Preserve executable CP03 and WHIR. Before proving, register the stronger native parameters and their privacy/security boundaries. Execute 1–4 real payments from independent wallets at retained branch anchors, incremental authenticated state, durable rollback/restart, competing branches, conflicting spends and recipient spending. Measure sparse and busy load, lone-payer delay, alternate submission, before/after-inclusion bytes, builder work, pruned and recovery obligations with the 100M/year and 1/5 TB comparison scenarios. Preserve a versioned private token/native-fee and indivisible two-party exchange path. Publish actual results, independent reproduction and an executable recommendation. Global blockchain development remains ACTIVE.

## Bounded result

The independently reproduced research decision selects direct APV2 wallet authorization for the first local PoW devnet at the finite tested 0.10 new offers/s service point. Source-built four-way aggregation verified but expired at the ninth independently clocked opportunity in both runs. The result includes independent clean keys and proofs, receipt-only spending after restoration, branch/current-spentness and durable crash checks, strong-profile and cost evidence, and a reproducible public handoff. See [decision](experiments/advancing-payments/DECISION.md), [instructions](experiments/advancing-payments/REPRODUCE.md) and STATUS.md for the release record. The global permissionless post-quantum private blockchain objective stays **ACTIVE**.
