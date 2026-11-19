# Live private-token PoW devnet

The separately identified TKN1 devnet supports live token-only receipt, seed recovery, independent native funding from mined rewards and a two-input private payment. The author selected H31, five payments, 3,100 native issuance and 240 tokens. Four orphan rewards totalling 403 disappeared at reconnection. A clean public clone of c78053fabf7e9944a27921a348cad6c3804284bd reproduced the wallet and fork at H44 with 4,400 native, 240 tokens, 15 fees and 603 detached native rewards removed. The earlier 3041fe96 clean build exposed a missing parent directory in the pristine upstream example tree. The corrected build creates the directory before compiling. All six full payments from each capture verified independently, including one shared-nullifier retry per run.

The stronger complete TKQ1 proof produced a 383,033-byte packet versus TKN1's 143,187 bytes. Keep TKN1 on the local fixed-token devnet. The next experiment is separately identified fixed-supply assets issued by two independent users under common rules. The global project remains active. External cryptographic assurance, archive cost, swaps, token archival certification and public-network hardening remain open. [Operator guide and evidence](experiments/token-devnet/README.md) · [Final commit and CI readback](https://github.com/jouliene/pq-private-chain/releases/tag/live-token-pow-2026-11-20)

## Earlier milestone

# Private token spend profile

Select TKN1 for the first fixed native-plus-one-token research prototype. Both lanes are privately committed and conserved. Each full 2×2 packet is 143,187 B. Four fresh transfers included two senders paying an offline recipient, seed-only receipt and respend, and a second restored recipient spending its only note. The founding supply of 400 native and 240 tokens finished with 388 spendable native, a 12-native fee sink, and 240 tokens. DLF1 remains the native-only reference. D8C1 remains optional only for DLF1 history. A separate typed archive would need a new recursive verifier.

Start revision 9c21c2b4297657b8c4cca219c4c480910557d00e. The [decision and commands](experiments/token-profile/README.md) link the monetary and privacy audits, source-derived parameters, actual timing and public fixtures. The independent reviewer rebuilt the candidate from public revision ee0da6c9ade4c4342203e63cb274e19efa6df5e9. Use the [release record](https://github.com/jouliene/pq-private-chain/releases/tag/token-spend-profile-2026-11-20) for final public SHA, CI outcomes and clean reproduction evidence.

The global permissionless private blockchain objective remains **active**. The next integration experiment is typed genesis, native fee/reward credit exactly once, and branch rollback/replay on the local PoW devnet. Mainnet assurance, archive cost, generalized issuance, two-owner swaps and multi-archivist endurance remain open.

## Earlier milestone

# Delayed DLF1 certificate decision

Adopt D8C1 as optional experimental historical evidence on a versioned PoW network. A real eight-payment certificate is 208,487 B; the same circuit with two real active slots is 186,983 B. Sparse/busy one-copy projections for full groups are 2.647/2.617 TB per 100M. Full coverage costs roughly 44 continuously busy CPU cores before headroom. Nine genuine independent payers across two PoW branches, destructive pruning on a disposable replica, a stopped original service, missing-evidence resume, rollback across a certified boundary, fresh cold verification and seed-only receipt followed by a new 250-unit spend were exercised. Seven of eight winning payments remained covered by the original full certificate. The global chain project remains active, including the open PQ/availability obligations, private native assets and atomic multi-owner swaps.

Start revision d9e4114967302916354a7f75787ada2b5e2d27fe. The single-command run, costs and decision are in [experiments/delayed-eight](experiments/delayed-eight/README.md). The [tagged release](https://github.com/jouliene/pq-private-chain/releases/tag/delayed-dlf1-eight-2026-11-19) records the exact public SHA, actual CI and clean non-author results. Use its attached readback to distinguish tests completed on that SHA from archived author measurements. Historical APV2 and DLF1 defaults are preserved.

## Earlier milestone

# Complete payment-proof architecture

Select DLF1 for the next direct-wallet research iteration. Keep APV2 as the executable local devnet baseline. The direct path was registered before proving, built from pinned Qnero source and verified from zero premine. At 143,187 B per complete payment, DLF1 reduced APV2 by 37.80%. Three separate wallets made direct 2×2 payments, an initially offline receiver restored its seed and spent again, and an alternative genuine spend lost a work-selected reorganization. In a separate trial four independent proofs overlapped a real empty block and occupied one full H10 block. Both programs retain current fee, nullifier, receipt, PoW and inventory checks in a separate network. The 1/5 TB archive scenarios and formal end-to-end PQ/privacy assurance remain open. [Decision](experiments/payment-architecture/DECISION.md) · [Reproduce](experiments/payment-architecture/README.md)

Starting commit `6502ebe7c01e174bcc8b9718130d7cb5f5dd8e63`. The compact MatRiCT+ experiment confirmed distinct funded outputs on reused receiving keys exposed the same two serials; trialled software also lacks the required positive-fee equation. A new cross-block aggregate verified, but authenticated omission of the original proofs requires an explicitly different PoW commitment. Next experiment: a detached eight-slot certificate over DLF1 wallets under that commitment, counting original availability, reorgs and empty slots. The exact released SHA, clean public-clone result and real CI readback are in the [release record](https://github.com/jouliene/pq-private-chain/releases/tag/payment-proof-architecture-2026-11-19). The global blockchain objective remains **active**.

## Historical milestone

# Ordinary wallet on a continuously mined devnet

The ordinary `pqd balance`, `send`, `restore` and `resume` paths now use private persistent wallet state and bounded public history. Start the network with `./pqd start`, or run `./pqd wallet-walkthrough` for a fresh isolated acceptance campaign. The global permissionless PQ/private blockchain project remains **ACTIVE**. [Operator commands](devnet/README.md) · [Measurements](devnet/WALLET_RESULTS.md) · [Security boundary](devnet/WALLET_PROTOCOL.md) · [Independent review](devnet/wallet-review/REVIEW.md)

- Starting public revision `82c803961996864782a5dee050a02b60b4341c0e`. The independently built candidate `2b6ae99f4f91135ef5974b69fbef987357336711` exercised real singletons, expiry, loss of a reply after admission, a 12-block detach, seed-only recovery during mining and recipient spending. At H4/H40 the unchanged history payload was zero. A one-block balance or send requested one 305-byte projected row and received 314 historical bytes at both sizes. Cold recovery received 1,229 / 12,227 bytes. The node's one-time migration and full payment admission have separate measurements.
- Revision `9e882b6a685eeb889ce4d2d086451ddd019adca1` adds the public replay checker and requires the final recipient spend to survive two observed successors. Revision `f87dd7292f80739fffcee91f1444358f189c47b6` atomically reserves real inputs with the first transmissible packet. Targeted first/replacement rollback checks passed.
- Release acceptance requires an actual clean public-clone walkthrough and both push CI checks on the released SHA. Read their results at the [wallet release](https://github.com/jouliene/pq-private-chain/releases/tag/incremental-apv2-wallet-2026-11-19). To verify the handoff, fetch its tag, compare the SHA to `delivery-result.json`, run `gh run list --commit "$(git rev-parse HEAD)"` and independently replay the public captures using the instructions in the release.
- Ordinary sync relies on the user's own validating node. A seed restores selected on-chain holdings. A sender needs its private outbox to resume an ambiguous off-chain intent. Full packet archive economics, end-to-end PQ/privacy, private assets and atomic swaps remain open.

## Historical milestone

# First runnable local PoW devnet

The source and local independent acceptance passed. Run `./pqd start` for continuous mining or `./pqd walkthrough` for a new reproducible network. The [operator guide](devnet/README.md), [decision and costs](devnet/RESULTS.md), [non-author review](devnet/review/REVIEW.md) and [hosted CI history](https://github.com/jouliene/pq-private-chain/actions/workflows/devnet.yml) provide the release record. The global private post-quantum blockchain objective remains **ACTIVE**.

- Base `46932763d7a0e6d03ea848ae2e22ab65ef48d5df`; independently rebuilt, tested node/wallet revision `8c4fb94334994ac98253348384050f23904d40a5`. The release adds tests, raw public evidence and operator documentation to this same implementation.
- Two CPU miners and a third validator agreed after partitions. The freshly seed-restored recipient spent again. After a ten-block detach, all three and a new fourth node agreed on the H15 tip, 1,500 issued units, 9 recycled fees and 6 nullifiers. H15 bodies totaled 693,960 B. Independent public-only branch replay and interrupted deep rollback matched.
- Under continuous mining a first proof expired. Its replacement entered H18, and the recipient observed 17 units. Live observations, submission costs and the cost of failure are in [LIVE.md](devnet/LIVE.md).
- The initial release push `7d9ad7dfa80b80f58e1a6f0d7d8908f9dd677ff9` tripped the unchanged CP03 integrity check on a new ignore pattern in its manifest-pinned root `.gitignore`. The correction restores the original bytes and locates the example backup outside the repository. The manifest, payment implementation, parameters and CI checks remain intact. [Initial CP03 run](https://github.com/jouliene/pq-private-chain/actions/runs/44457935797)
- Release verification: run `git rev-parse HEAD`, `git ls-remote origin refs/heads/main`, and `gh run list --commit "$(git rev-parse HEAD)"`. A successful **Local proof-of-work devnet** walkthrough and the existing **Research payment smoke** are the hosted checks. Re-run public evidence checks from the review with an independently built runtime. All release material excludes private wallets.
- Remaining work belongs to the global project. End-to-end PQ/privacy composition, network-level anonymity, conflict and propagation behavior beyond the local test, production PoW economics and archival affordability remain open. Native private assets and indivisible two-owner swaps remain proposed versioned extensions.

## Historical milestone

# Advancing payments for the first local PoW devnet

**Direct APV2 selected for local integration. Global blockchain objective ACTIVE.** The four independently controlled wallets, durable advancing state, fork and current-spentness controls, separate externally funded receiving/spending and direct failover were independently reproduced. The continuous two-second local clock included 12 of 12 new one-payer submissions at one every 10 s in both runs. A cryptographically valid four-way aggregate expired at prospective H9 in both independent-clock runs. The local research result supplies neither permissionless PoW consensus nor a quantified noninteractive PQ/privacy guarantee.

[Architecture decision](experiments/advancing-payments/DECISION.md) · [Fresh author and independent reproduction](experiments/advancing-payments/REPRODUCE.md) · [Non-author review and public evidence](experiments/advancing-payments/review/REVIEW.md) · [Role and archive costs](experiments/advancing-payments/costs/ROLE_COSTS.md)

## Tested revisions and release boundary

- Published starting reference `cc2d9b9e6b6e5d4cbcd7e241f0025dc20c84b963`. CP03, WHIR and completed synchronization source were preserved.
- The exact strengthened verifier was registered before wallet creation at `983799bfbe541331839dcf693541ac0983c238b5`. All fresh builds reproduced the registered profile SHA-256 `af88a0ac0caa5f0aa27d38d687b6cc39495a0aa2659ed4a7e5e74653724cc1b1`.
- Independent four-wallet execution and selected-branch state used `940c92159e3a85c2b82ea38bc3f6efa6ec29d408`. A launcher import and a tail audit import had previously interrupted two author attempts. Only the completed author run supplies performance evidence.
- Independent direct, four-way clock, externally funded receiver and mixed-FIFO worker tests used `e19adf88c6bc90becb5656651da4fd79bb0b6233`. The additional test caught and corrected a missing worker that could strand an earlier acknowledged payment ahead of a direct offer.
- The 12-intent profile was registered and run from `2aed1ee0abc04fe2d94cbb26b945f6b8f6150c81`; the independent run and expanded public checker used `247e9645a4c0abb4dfb544233db91924ec99fac7`. Subsequent changes contain results and review material. The immutable public handoff identifies the release SHA. The existing GitHub Actions smoke covers the CP03 reference. The APV2 results are the clean reproductions linked above.

The first devnet experiment should expose the direct producer pickup and validation path to separate local participants under actual mined block intervals, observing expiry and branch choice. For archival research, at continuous width four a 5 TB copy at 100M inclusions still needs a complete outer proof of at most 185,503 B with today's receipt and framing sizes. The owner has set no annual traffic or storage limit.
