# Next Goal: a usable private payment network slice

## Mission and baseline

We are building our own permissionless blockchain with private transactions and post-quantum security. Existing chains supply evidence and ideas, not a mandatory architecture. CP03 is the current research backend, not an irrevocable choice.

Start from the canonical repository `/home/neo/jouliene/pq-private-chain`. The independently reviewed public baseline is `d8f800037b5efbb76a5a1d6d4d3100e55f676a00`. Inspect HEAD, uncommitted work, active processes, AGENTS.md, BUILD.md, STATUS.md, docs/ARCHITECTURE.md and docs/SECURITY.md before proceeding. Preserve legitimate subsequent work. Do not restart the completed publication phase or recreate a second implementation tree.

**Goal:** deliver and independently reproduce a bounded network/payment slice that demonstrates the complete cost of transferring, validating and retaining genuine private payments, and lets a wallet recover and spend using locally constructed witnesses from common authenticated history. Use early measurements to retain, repair or replace the backend. The result must be running code and an explicit architecture decision, not another documentation-only milestone.

Standalone PoW remains the preferred consensus direction. This Goal does not implement a PoW/PoS hybrid or a full consensus engine. PoS would not remove payment-proof or history costs. Permissionless issuance and PoW integration follow the feasibility decision; the current synthetic issuer remains explicitly laboratory-only.

## Orchestration and priorities

Act as the single orchestrator. Assign specialists to transport/storage, wallet witnesses, cryptographic obligations and independent acceptance review. Give them distinct ownership and concrete deliverables. Use one heavy proof-generation/build campaign at a time. Review and integrate their work; do not merely collect reports. Do not create nested management layers.

Work autonomously through the gates below. Every experiment must answer a named architecture question. Before tuning a component, state which acceptance boundary the improvement could change. Millisecond improvements, repeated checksum campaigns and new harness frameworks are not goals in themselves. Reuse existing checks; add tests for changed invariants and actual failure modes.

Report briefly every 30 minutes of active work: what ran, what changed the decision, the current blocker and the next decisive experiment. Preserve restartable state after each meaningful checkpoint. Keep code and documents in English; communicate with the owner in Russian.

## Gate 1 — one complete, genuinely larger block

Implement the smallest versioned block/transport adapter needed to process **96 distinct ordinary private payments** with real proofs and valid, non-conflicting inputs. Generate funding separately and identify its costs. Do not count repeated delivery of the same transaction, synthetic padding, mocks or retained verifier verdicts as distinct payment throughput.

Changing the current 16-body restriction is a protocol-adapter change, not one constant. Review and test the corresponding framing, ledger, CLI, archive ordinal, cache and batch bounds. Keep an explicit encoded-byte cap as well as a count cap. The existing 0..128-body / 256 MiB / hypothetical 30-second profile is a research candidate, not a commitment or a measured capacity claim. Empty blocks, if needed for test history, must have explicit rules.

Run producer, archive and receiving validator as separate processes with actual bounded transport. Use fixed, declared bandwidth/latency and memory/disk assumptions. An initial local multi-process run is acceptable if labelled accurately; it is not WAN evidence. Do not give the receiving process direct access to the producer's database or fixtures. Keep correctness oracles outside measured processes.

Measure the complete destination obligation: receive and parse, real proof/state validation, atomic durable commit, and the chosen retention/export policy. If cache eviction relies on archival publication, finish that publication and account for its acknowledgement and availability assumptions. A growing pending-export queue is unfinished work. A destination which retains bodies instead must count that disk growth. External archives are provisioned roles with measured costs, not free storage.

Record wall time, CPU, peak RSS, real transferred/stored bytes, queue peaks, repeated verification and cache conditions by role. Corroborate equal canonical state. Exercise a malformed/invalid final payment, interrupted transfer and one relevant failure across the persistence/publication boundary; failures must not produce accepted partial state, silent loss or premature eviction.

**Review the result before generating a larger workload.** If a correctness defect or a decisive resource barrier appears, fix or pivot immediately. Do not build an extensive consensus layer around a failing payment path.

## Gate 2 — bounded offered load and an honest resource decision

Before running, declare the workload, admission schedule, burst, queue limits and observation end. Use 100 million offered payments per 365-day year (about 3.171/s) as a comparison scenario, not a protocol cap. After Gate 1, a finite series such as eight 96-payment batches is sufficient for a first queue experiment; extend only to resolve a specific uncertainty. Use distinct genuine payments. Pre-generated proofs may drive a node test, but report prover costs separately and do not call it live wallet throughput.

Account for the entire backlog and outstanding storage obligations. Show whether queues drain after a bounded burst, how backpressure behaves and whether a stopped/restarted role resumes without losing or double-applying accepted payments. A finite pass is not a year-long capacity result. Separate tiny-state observations from estimates at a larger state/history size.

Publish one concise cost table for ordinary validating node, archive, miner and wallet. Do not substitute miner costs for validator costs or count unimplemented mining as free. Preserve the visible baseline: approximately 1.75 MB per ordinary payment and 175 TB/year for one full-body copy at 100M payments. Pruning changes who stores history; it does not erase the system-wide obligation. Include bandwidth/fan-out assumptions, storage growth, wallet scan traffic and bootstrap costs. Label hypothetical hardware, archive replication and the earlier 90-day catch-up profile as research assumptions unless the owner actually adopted them.

Separate two decisions: (a) can this configuration service the declared workload, and (b) is its participation/storage model compatible with decentralized private money? Faster processing cannot by itself answer the second. State residual decisions for the owner explicitly instead of silently increasing hardware budgets or assigning a production PASS.

## Gate 3 — witnesses without disclosing owned-note indices

Start full wallet integration only after the resource review provisionally retains a backend for an explicit participation model. If the model is decisively rejected, run the targeted backend/storage pivot first. Cheap independent witness design work can continue in parallel; do not spend a large integration effort on a rejected configuration.

Integrate the selective witness idea into the actual wallet. Discover received notes and construct/refresh their membership paths locally from a common public history stream. Authenticate ordering and endpoints against the declared validating source/chain context. No wallet-owned index, unique subtree request or equivalent ownership hint may be sent to an external service. A local complete ledger may serve as a test oracle, but must not secretly supply the paths being attributed to the new algorithm.

Demonstrate receiving, witness construction, a fresh spend, backup recovery in a new process and another fresh spend. Keep private keys, backups and witnesses in bounded local memory/pipes; do not publish or hash secret fixtures.

Exercise actual accepted-anchor expiry beyond the current 256-block window, then refresh and successfully spend an old unspent note. Do not merely advance an unchanged root and assume expiry was tested. Exercise a controlled branch rewind and replacement history: undo orphaned discoveries/spentness and witnesses, reject a spend depending on orphan-only funding or an ineligible orphan anchor, and successfully spend valid retained funds on the selected branch. A transaction originating on the old branch may remain valid if its common-prefix anchor and inputs remain eligible; do not reject it solely for its origin. A test branch controller is allowed; it is not distributed fork choice or consensus evidence.

The existing fixed-endpoint probe rebuilds from accumulated leaves and compares with a full oracle. Its RSS is not evidence of a bounded streaming wallet. Measure the integrated algorithm separately, including any necessary second pass or funded-leaf spool. State what history and public key inventory recovery requires. Do not claim recovery from a mnemonic or a backup predating unknown random receiving-key rotations. Network/IP anonymity remains a separate unimplemented obligation.

## Pivot rules and cryptographic discipline

Preserve the complete same-witness payment relation, canonical verification, nullifier uniqueness, value conservation, source authorization and atomicity. Never pass a resource gate by weakening security parameters, trusting a producer-selected program, omitting verification or treating a signature as a private payment proof.

Maintain a short obligations map for the exact candidate: ML-KEM-1024 receiving; HKDF-SHA384/AES-256-GCM and key confirmation; laboratory ML-DSA-87 authority; Poseidon2 commitments/nullifiers/tree; hiding FRI/STARK payment proof. Distinguish standardized components from the experimental composition. Do not infer recipient anonymity from KEM confidentiality or assign the whole protocol a numerical PQ security level without a defensible analysis. Missing full formal assurance permits clearly labelled research; a concrete soundness, authorization or privacy failure blocks dependent integration.

If a configuration fails, identify the dominating cause and run a materially different, bounded experiment that directly addresses it. A single backend failure is not exhaustion of the design search. Repair avoidable repeated work for a CPU bottleneck; consider a different complete proof relation for dominant initial payment size. A checkpoint proof may help historical bootstrap but does not automatically remove initial data availability. Assess alternatives by the same complete relation and security requirements, with exact sources/parameters and an executable smallest decisive test. Do not rerun a previously invalid construction without repairing its specific defect.

Our own cell/DAG container inspired by TON is an available **representation hypothesis**, not TVM integration and not compulsory. No TON cell-size or reference limits are imposed. If testing it addresses the measured barrier, first compare ordinary compression and shared typed chunks on genuinely distinct data, including reference/dictionary overhead. Start with an exactly reversible transport/archive representation feeding the unchanged canonical verifier. Bound decoding resources and missing-dependency behavior. Do not add overlapping compression percentages, mistake a smaller Merkle inclusion proof for a smaller private payment proof, or introduce selective wallet fetches that leak ownership. Earlier small-fixture gains were modest; a codec rewrite requires measured benefit sufficient to change a decision.

Tokens, swaps, a general VM, UI, seed-phrase product design and full PoW issuance are retained backlog items. They must not delay these feasibility gates.

## Completion, review and handoff

Close this bounded Goal only when:

1. A chosen backend executes the complete separate-process payment/retention path with genuine distinct payments and relevant failure controls.
2. The declared finite workload has measured results, all backlog/retention obligations are accounted for, and a concrete backend is provisionally retained for an explicit, technically supportable resource/participation model. Owner acceptance of a proposed cost model remains separate; do not fabricate it. A rejected configuration alone is not the required retained direction.
3. The integrated wallet demonstrates private local witness construction, expiry refresh, controlled rewind, recovery and a new spend as specified above.
4. Cryptographic guarantees, known defects and unproved assumptions remain accurate. Any pivot has an executable result and a comparison against the same requirements.
5. A reviewer who did not implement the path independently reproduces the decisive final slice from a clean checkout. Repeat large campaigns only when changes or an unresolved finding justify them.
6. The reviewed code, concise decision, exact reproduction commands and safe evidence are committed and published to the existing GitHub repository. Provide the exact revision and CI result. Include automatic push/PR smoke coverage if this is a small change; do not turn CI maintenance into a new project.

Reports, a passing old smoke, a failed first candidate or a paper-only replacement do not satisfy these criteria. Continue with independent useful work when one task is blocked. If an essential external prerequisite or unresolved construction prevents completion, leave the Goal ACTIVE or explicitly BLOCKED, preserve the runnable work, and state the precise blocker plus the next falsifiable route. Do not claim universal impossibility or silently shrink the objective.

Keep three statuses separate: this experiment's completion; the architecture's provisional acceptance/rejection for a stated profile; and the global blockchain goal, which remains ACTIVE. The final handoff must say whether the next justified investment is permissionless PoW/issuance integration or a specific change to the payment/storage design.
