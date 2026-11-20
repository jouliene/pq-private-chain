# Independent managed-supply review

Baseline `006b8fb8d91a3e61dfb97b666e7bb6ca5748412d` remains the executable AST1 fixed-supply reference. The managed-supply audit uses a clean detached checkout, a fresh local PoW home, newly initialized participants and a separate read-only public verifier.

| Boundary | Independent evidence |
|---|---|
| Asset registration | Recover the fixed/managed policy from admitted wire bytes. Verify its canonical asset identifier and initial supply, record the original authorization descriptor, and preserve it throughout each branch. A fixed descriptor must never acquire a mint authority on a later transition. |
| Public authorization | Reconstruct the exact authorization message from public fields and verify the signature against the authority previously accepted on that branch. Check the predecessor, successor, sequence, operation and amount as specified in the candidate. Check the binding to the actual funded outputs and associated receipt bytes. Count state commitments, proofs and signatures separately. |
| Monetary state | Replay each branch from genesis. For each asset reconcile initial supply plus admitted issuance less actual burns. Independently check closed integer ranges, native-only mining, fee debit/credit once, nullifier uniqueness, output commitment positions, roots, registry rows and fork selection. Compare the selected histories and balances of separately launched validating nodes. |
| Simulated external payment | Use explicit lab-disclosed quantities and a stable redemption identifier to follow the burn, confirmation, attempted payout, durable acknowledgement, detached burn, exposure and recovery. Compare independently computed selected on-chain supply and the one-way off-chain cash journal at each milestone. Count actual durable payout records as well as attempted calls; a stubbed Boolean success cannot establish exactly one simulated payout. |
| Controls | Distinguish wallet refusal, rejected proof, rejected issuer authorization, stale predecessor, rejected ledger transition and state rollback. Check idempotence after restart and compare the result of the actual reorganization with a clean winning-history replay. Preserve public or deliberately disclosed test artifacts only. |

Published monetary labels and payout amounts are deliberate laboratory disclosures. Private note ownership and real fiat solvency are separate questions. The review will report the tested reorganization depth, confirmation rule, persisted exposure, recovery mechanism, packet/proof sizes and execution costs from the actual run.
