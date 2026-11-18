# Independent-node validation decision in progress

Global blockchain objective **ACTIVE**. Current baseline and previous completed experiment are recorded in [GOAL.md](GOAL.md) and [the proof-size decision](experiments/payment-size/RESULTS.md). The CP03 and synchronization implementations remain the reference.

| Ownership | Evidence and pending action |
|---|---|
| Orchestrator | Real AIR to sparse R1CS lowering and public matrix contraction in `experiments/node-validation/dimensions`. Complete the public-input transparent Keccak cost test in `aggregate`, integrate findings, freeze, review and publish. |
| Construction | Source-correspondent masked reduction, public transcript and complete-byte parameter model in `primary`. Check the cheaper committed subfield mechanism and precise interactive versus compiled guarantees. |
| Roles | Measured baseline and projections for wallet, public mempool, block-only validation, pruned/archival storage and cold catch-up in `roles`. |
| Independent reviewer | Verify the complete transcript, conditional geometry, guarded inputs, alternate scheduling, accelerator obligations and non-author reproduction in `review`. |

The actual registered 2x2 AIR lowers to 614,387 base constraints. A direct EF5 lift checking every original trace word needs 19,587,059. The masked reduction runs on a small relation. It has no full payment result yet. The fallback build uses the pinned public RISC Zero v3.0.6 Keccak CPU circuit with the existing CP03 public payer data. One heavy job at a time.

To resume, inspect `git status`, the current Goal, and the four evidence directories. Check `/tmp/pq-risc0-nodeval-build.log` and the running Cargo job before starting another. After the library builds, run `python3 -I experiments/node-validation/aggregate/run.py /tmp/pq-risc0-nodeval-306 /tmp/pq-risc0-nodeval-target .work/nodeval-accelerator01` in this checkout. Review the full-size budgets, required verifier work and security correspondence before approving any complete proof job.
