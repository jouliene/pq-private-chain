# Authenticated incremental wallet synchronization

Owner directive, 2026-11-18 (Australia/Perth). Preserve this scope independently
of the completed NETWORK_FEASIBILITY_GOAL.md.

Implement and independently reproduce authenticated incremental wallet synchronization for our private post-quantum blockchain. Eliminate repeated full-history downloads and authentication during ordinary wallet updates, while preserving private local witness construction, correct branch handling, recovery and genuine spending.

## Project and baseline

Canonical repository: /home/neo/jouliene/pq-private-chain
Public repository: https://github.com/jouliene/pq-private-chain
Last externally reviewed revision: 2b87d1e5fcb9090390c476138bbd174d6034a6a9

Inspect actual HEAD, uncommitted work, running processes, AGENTS.md and STATUS.md before starting. Preserve legitimate later work.

NETWORK_FEASIBILITY_GOAL.md is completed. Do not reopen or repeat its completed 264-proof and 864-proof campaigns without a specific newly discovered defect requiring it.

Read docs/network-feasibility/RESOURCE_DECISION.md,
experiments/network-feasibility/review/POST_GATE3_INVESTMENT_DECISION.md,
and the actual wallet recovery, local witness and history-serving implementation.

## Global objective

We are designing our own permissionless blockchain with private transactions and post-quantum security. CP03 remains a research candidate.
This milestone addresses wallet synchronization. It does not establish production readiness, complete PQ/privacy security, affordable annual operation or finished consensus.
Standalone PoW remains the preferred consensus direction. Full consensus, issuance, tokens, swaps, VM, mnemonic design and proof-system replacement are outside this milestone.

## Orchestration

Act as the single orchestrator. Launch specialists for:
1. History-serving and continuation format.
2. Wallet cursor, witness and branch-state integration.
3. Independent correctness/privacy review and reproduction.

Give each specialist explicit ownership. Integrate and review their work. Avoid nested orchestration and duplicate heavy jobs.
Report briefly every 30 minutes of active work: concrete result, remaining uncertainty, next decisive action. Code and documentation in English; owner-facing reports in Russian.

## Implementation objective

Currently the wallet updates its cryptographic state incrementally but receives and authenticates the complete history prefix again.
Implement a bounded, versioned common-history continuation starting from the wallet's OWN previously authenticated joint state.
The base must bind the relevant chain/genesis identity, height, block identity, root/count and accounting context. It must correspond to the wallet's committed receiving state, spentness and local witnesses.
An arbitrary peer-supplied checkpoint or caller-imported tree state must not become a trusted base.
Authenticate every continuation link and the exact endpoint. Preserve the existing explicit delegation of payment validity to the selected validating source. Do not present hash linkage as consensus, freshness or full payment verification.

Server requests must concern common public block ranges. They must not contain owned-note indices, recipient identifiers, selected subtrees or equivalent ownership-dependent hints. For the same synchronization state and target, changing the wallet's ownership must not change the requested public range.
Make the serving side retrieve the requested range directly. Do not generate/read the entire historical prefix and discard it before returning a small suffix.
Publish the new cursor, discovered notes, spentness and witnesses atomically after successful authentication. Failures must leave the previous committed state intact.

## Branches and recovery

- An unchanged selected head must not trigger a full-history reread.
- Ordinary append updates consume only new history plus bounded framing.
- A shallow reorganization restores an authenticated retained joint checkpoint and processes the replacement suffix.
- A deeper reorganization revokes stale views/drafts and explicitly performs full replay when required.
- Cold recovery in a new process may require one complete history scan. Measure and disclose it.
- Preserve accepted-anchor expiry and refresh.
- Reject orphan-only funding and ineligible anchors, while retaining otherwise valid common-prefix transactions.
- Preserve backup/key-inventory assumptions. Do not claim mnemonic recovery or recovery of unknown receiving keys.

## Validation

Reuse existing genuine public history for long-trace synchronization tests. Generate new proofs only for the small genuine wallet scenarios needed to validate the changed integration.
Demonstrate:
1. State equivalence with the existing full-replay reference, including cursor, discovered/unspent notes and membership witnesses.
2. Genuine receiving and spending after incremental updates.
3. Backup restoration in a new process followed by a newly proved and accepted spend.
4. Correct expiry refresh, shallow rewind and deep-replay behavior.
5. Atomic rejection of wrong-base, wrong-chain, wrong-endpoint, missing, reordered, duplicated and truncated continuation data.
6. Safe interruption and retry without early cursor advancement or duplicate application.
7. Revocation of stale wallet capabilities after a branch change.

Do not replace actual proving/admission with mocked verdicts, diagnostic hashes, signatures or stored success flags. Cheap model tests may supplement genuine integration tests, but must be labelled separately.

## Measure the architectural improvement

Use fixed genuine history prefixes of different lengths and repeated append updates.
Measure cumulative:
- requested and returned bytes;
- history bytes/records actually read by the serving side;
- blocks authenticated by the wallet;
- CPU, elapsed time, peak memory and retained journal/state.

Show linear cumulative append traffic and authentication work, subject to explicitly bounded framing and separately charged reorganization/recovery costs.
Use exact byte/record counts to establish the scaling behavior. Do not substitute noisy timing ratios or a smaller final response for evidence that the old prefix work has disappeared.
Keep correctness oracles and test-fixture preparation outside measured roles. Do not build a new general benchmarking framework.

## Security and scope

Preserve payment-proof parameters, complete value/ownership/membership constraints, canonical validation, nullifier rules, source authorization and atomic ledger behavior.
Do not weaken isolation, runtime checks or endpoint assumptions to make tests pass. Keep private keys, backups, notes and witnesses out of published logs and artifacts.
The current approximately 1.75 MB payment and 175 TB/year first-copy body projection remain visible. Incremental synchronization does not solve that storage problem, remote pruning, initial data availability or bootstrap.
Do not start cell-format redesign, remote pruning, recursive checkpoints, a new proof system or full PoW implementation within this milestone.

## Completion criteria

Mark this bounded Goal COMPLETE only after:
1. The continuation path is implemented in the actual history-serving and wallet code.
2. Ordinary updates no longer reread/authenticate the entire prefix, with measured byte/record evidence.
3. Genuine payment, recovery/new-spend and branch-handling scenarios pass.
4. Relevant adversarial controls pass without weakening checks.
5. A non-implementing reviewer independently reproduces the decisive changed path and a fresh genuine wallet cycle from a clean checkout.
6. Existing relevant automatic CI passes, and reviewed code, concise results and reproduction commands are committed and pushed to the existing public repository.

Provide the exact tested and published commit hashes, CI link, changed behavior, measured improvement and remaining limitations.
Do not close the Goal merely because a report, proposal or old smoke test passed. A failed attempt requires diagnosis and a targeted correction. If a genuine unresolved blocker prevents completion, preserve the runnable work and identify the exact blocker; do not relabel failure as COMPLETE.

## Stopping boundary and next priority

After this implementation and independent acceptance, stop expanding synchronization work. Do not turn the result into successive wallet or CI tuning milestones.
Update the architecture decision with the corrected wallet costs and unchanged full-payment storage costs. Name the next concrete experiment that directly addresses materially smaller complete payment proofs or the full storage/participation obligation.
Do not infer owner acceptance of the 175 TB/year model. Do not begin full consensus integration merely because synchronization passed.
Keep the global blockchain objective ACTIVE and explicitly separate from completion of this bounded milestone.
