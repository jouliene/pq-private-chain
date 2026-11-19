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
