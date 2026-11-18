# Independent-node payment validation

Global blockchain development is **ACTIVE**. The scoped recommendation is to defer both candidates and retain CP03 for research. The previous published baseline and closed encoding experiment are at `7c2d0fc8b68c566d13e3e341c1f49bacaad527f4`.

- Masked route: real registered 2x2 circuit dimensions, small genuine masked proofs, complete conditional wire budgets, actual matrix and first-stage transform costs. A 262,850-byte mean schedule fits block-only relay. The 0.245–0.261 CPU-second generic verifier component exceeds the chosen 0.12476-second catch-up allowance.
- Aggregate route: real CPU proof and public verification of one CP03 leaf's 67 Keccak permutations. A historical 96-payment workload needs at least 3,600,891 nonfixed tree permutations. The pinned outer profile and block-prover cost exclude integration.
- Code freeze `6efae8b29ed9a854768a5e5ec5d69fbceee216c0`. The existing ledger, wallet, old experiments and their requirements are preserved. No complete new-backend payment or aggregate was produced. [Complete decision](experiments/node-validation/DECISION.md), [role costing](experiments/node-validation/roles/README.md) and [reproduction](experiments/node-validation/README.md).

A non-implementing reviewer reproduced the public matrix outputs (0.2234–0.2286 CPU seconds), the real Keccak proof (15.50 seconds elapsed) and the 96-payment count from a separate clean checkout. Pinned reference and dependency builds were reused. Both candidates are deferred. [Review and exact rerun commands](experiments/node-validation/review/CLEAN_REPRODUCTION.md).

The next design-changing experiment is a source-equivalent structured evaluator for the folded full 2x2 public linear form, together with checking the guard's joint transcript assumptions. This goal does not start that experiment.
