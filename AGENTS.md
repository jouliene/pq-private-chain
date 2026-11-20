# Native private atomic swaps

Use `./pqd swap --home NEW_PRIVATE_HOME native-walkthrough` for the token-for-native scenario. Load private agreement and wallet policy from the running checkout, and load public node rules, approved binaries and registered keys from the selected deployment. Preserve both the SWPTER01 commitment for legacy agreements and the released SLG1 verifier identity. [Instructions and fee accounting](experiments/atomic-swap/NATIVE_CURRENCY.md)

Run `./pqd swap --home NEW_PRIVATE_HOME walkthrough` for the SWP1 network. A swap occupies two adjacent bounded physical frames in the existing four-slot AST1 PoW format. Keep group admission, relay, fee credit and reorg handling atomic. Check the incoming note under its recipient spending key before either final authorization and keep wallet journals, private agreements and signing nonces out of published data. The historical MNG1, AST1 and ordinary transfer paths retain their approved verifiers. [Swap operator and validation guide](experiments/atomic-swap/README.md)

# Managed assets and redemption

Use a fresh private home and `./pqd managed --home HOME walkthrough`. The original AST1 software mines a funded prefix first. Upgraded validators must independently replay those same blocks and authorize new MNG1 transactions with their pinned verifier. Preserve canonical AST1 history bytes, fixed policy, native fees and current note domains. A managed registration pins its perpetual issuer key. Confirmations are a local simulated bank policy. Keep the bank and coordinator databases private and test ambiguous external payout outcomes with the bank ledger preserved. [Managed protocol and reproduction](experiments/managed-assets/README.md)

# Permissionless user assets

Run `./pqd assets --home NEW_PRIVATE_HOME walkthrough` for the AST1 local PoW network. Start from its empty genesis. The common registered verifier covers native-only payments, private asset transfers and public one-time issuance. Each role installation must match the registered AST1 key. Keep per-asset supply and canonical ID checks inside the same branch transition as fees, nullifiers and funded notes. Preserve the earlier TKN1 commands. Use the [operator and public evidence guide](experiments/user-assets/README.md) for clean setup, offline recovery, monetary reconciliation and measurements. Publish only public packets, blocks and explicitly disclosed test aggregates.

# Live fixed-token devnet

Use `./pqd token --home NEW_PRIVATE_HOME walkthrough` for the mined TKN1 network. Keep each lab's operator-approved founding digest and registered verifier separate from native-only devnets. The public capture contains the founding record, full blocks and packets, and disclosed numerical fixture results. Publish only allowlisted public evidence. A new home creates a new founding wallet and network identity. Verify existing captures with the independent monetary and cryptographic readers in [the operator guide](experiments/token-devnet/README.md). Changes to the bootstrapping path require a clean clone and new upstream build target.

# Incremental APV2 wallet

For changes to the ordinary wallet, run the acceptance command `./pqd wallet-walkthrough`, read devnet/WALLET_PROTOCOL.md and distinguish compact history bytes, SQLite file reads, complete wallet uploads and native proof costs. Preserve the private outbox's pinned real inputs across retry and reorg. Queries for public history must have identical parameters for different wallet holdings at the same cursor and target. Keep local seeds, owned rows, paths and the outbox outside publication.

# Local PoW devnet

Run `./pqd start` for persistent continuous mining and `./pqd walkthrough` for an isolated acceptance run. Read [the operator guide](devnet/README.md) and [the monetary and fork rules](devnet/CONSENSUS.md) before edits. Consensus owns work, ancestor validation, rewards and node-local chain selection. Never elect a branch in the test driver. The published evidence allowlist contains public packets, complete blocks, explicitly synthetic numerical results and timings. Keep seed backups and local databases outside Git. Use separate empty homes and preserve the registered native verifier and historical CP03/WHIR paths.

# Advancing-chain payments

The APV2 research path, local devnet decision and reproductions live in experiments/advancing-payments. Read its DECISION.md and REPRODUCE.md before running its isolated Rust roles. Use a new work and evidence directory for each run, the registered source/profile and one heavy job at a time. Keep producer-confirmation clocks independent of proof completion. Tests of receipt ownership must distinguish external funding from the payer's own change.

# Wallet-created payment decision

The bounded structured-wallet and two-owner native evidence belongs in experiments/wallet-created. Read its DECISION.md, GOAL.md at the repository root and STATUS.md. Keep fresh proof, receipt, ledger, publication and conditional security results distinct. Preserve CP03 as the executable reference.

# Prior independent-node validation decision

Read GOAL.md and STATUS.md for the current owner directive. In experiments/node-validation, evaluate one masked-sumcheck route and one public-proof aggregation fallback. Label component measurements, whole-payment results, estimated byte budgets, service assumptions and remaining assurance obligations. Preserve CP03 and the closed synchronization and proof-encoding milestones.

# Complete-payment proof-size experiment

Read GOAL.md and STATUS.md. The bounded experiment following the published
synchronization release is complete. See experiments/payment-size/RESULTS.md. CP03 is the preserved reference. Keep
candidate source, construction analysis and non-author review in their assigned
areas under experiments/payment-size. Execute one heavy job at a time.
The tenfold size target is a screening objective. Count complete ordinary
payments and disclose preprocessing and dependencies. For acceptance reproduce
three new private 2x2 payment proofs, public verification and semantic controls.
Retain the independent global blockchain objective.

# Completed authenticated incremental synchronization milestone

INCREMENTAL_WALLET_SYNC_GOAL.md is the preserved completed owner directive.
Its implementation, independent clean reproduction and actual public CI passed.
See STATUS.md and experiments/incremental-sync/PUBLICATION.json. Stop expanding
synchronization; the nominated next proof-size experiment has not started.
The global blockchain objective remains ACTIVE independently.
Canonical baseline:2b87d1e5fcb9090390c476138bbd174d6034a6a9. Preserve historical
NETWORK_FEASIBILITY_GOAL.md and all264/864 proof evidence; no closed campaign is
reopened absent a specific new defect. STATUS.md is the live queue/ownership map.
Actual direct-range serving, wallet-owned continuation, exact scaling, genuine
spending/recovery/branch tests and independent reproduction are accepted. Do not
turn this completed work into further wallet or CI tuning. Keep the global
blockchain objective separate and active.

# Public implementation working guidance

This is the selected public development checkout for the independent PQ-private
chain research implementation. Read README.md, BUILD.md, STATUS.md and
docs/DELIVERY.md before changing the published path. Technical artifacts and
code are English; communicate with the project owner in Russian.

One orchestrator owns shared contracts, Git, release identity and integration.
Assign separate areas to specialists, review their changes and run one heavy
build/proving campaign at a time. Do not nest agents or duplicate a live job.
Preserve actual failures, source/runtime pins and exact reproduction commands.

Genuine complete proof verification and atomic exact-value state transitions are
mandatory. No mocks, witness-as-proof, signature-only substitution, cached
verdicts or producer-selected verifier programs. Fresh public verification must
not read wallet secrets. Disposable private keys, backups and witnesses stay in
bounded private memory channels; never log, hash, commit or publish them.

Keep algorithm/profile identity separate from installation identity. Use the
reviewed runtime discovery/explicit approval mechanism when relocating trusted
Node/native dependencies. Never disable provider checks to make a build work.
Do not mutate a running source snapshot or regenerate evidence over an old label.

Edit the public canonical source, not generated .work installations. Research
journals and old experiments remain separate historical evidence. There is no
manual dual implementation or automatic import from the former research tree.
Do not change proof parameters, wire/fee/issuance semantics or add cell formats
without an explicit development decision and coherent producer/consumer tests.

The owner's sizing input is100M offered payments/year; no annual traffic cap was
set. Label researcher scenarios, measured results, projections and untested claims.
Functional smoke, role resource viability, formal PQ/privacy composition and
production readiness are separate conclusions.

At a completed development milestone follow docs/DELIVERY.md: exact reviewed
commit, relevant actual tests, public push without force/history rewrite, public
revision verification and full SHA/compare/command handoff. Do not claim secure,
audited or production-ready merely from publication or agent review. Keep current
STATUS accurate and brief; no old internal conversation/log export.
