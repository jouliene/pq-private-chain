# Bounded research backlog

These items are not features implemented or authorized by the publication Goal.
The next architecture integration is specified in ARCHITECTURE.md. This backlog
keeps alternatives and exploratory ideas from silently changing the protocol.

After the bounded synchronization acceptance, the next nominated discriminator is
the [complete-payment proof-size gate](../experiments/incremental-sync/NEXT_EXPERIMENT.md).
It is not started by this milestone. The retained directions below do not override
that priority or authorize successive wallet/CI tuning.

## Custom shared-cell representation

The owner proposes our own typed cell/DAG container inspired by TON shared cells,
not TVM integration. TON's1023-bit/four-reference limits are not requirements.
Choose cell sizes, references, hash profile and encoding for this protocol only
if a bounded comparison demonstrates a benefit.

The owner's external preliminary screen covered six public bodies from the older
CP03 audit package, not the newer32-proof workload. It reported6.50–7.48% ordinary
per-body Zstandard19 reduction,7.25% chronological combined reduction, exact byte
recovery, and about3.13% modeled typed-dictionary reduction for a supplied2x2proof.
A fixed public preprocessing opening section is roughly215KB/12.3% of that proof.
The dictionary is illustrative, not an implemented codec or universal bound.
These percentages overlap and must not be added. Existing shared-query multiproof
deduplication is already implemented and must not be counted as a new saving.
This preliminary screen is not a controlled CPU/memory/network benchmark and is
not independently rerun by the publication smoke.

A later experiment should compare ordinary compression against typed shared
chunks within and across genuinely distinct transactions. Count references,
dictionaries/preprocessing, decoded limits, CPU/RSS, streaming/random access,
missing dependencies and availability. Begin with a reversible transport/archive
container which reconstructs exact canonical bytes for the unchanged real
verifier. Enforce size/reference/depth bounds. Avoid selective wallet requests
that reveal owned notes. Compare state sharing separately against the existing
incremental store. Content hashes establish identity, not availability.

Owner-supplied primary references: https://docs.ton.org/foundations/serialization/boc
and https://docs.ton.org/foundations/serialization/cells . They motivate shared
representation, not a PQ guarantee or demonstrated saving for this protocol.

## Other retained directions

- Complete-public-verifier/state checkpoints if historical bootstrap dominates;
  initial data availability and receipt history remain separately necessary.
- Repaired native lattice relation if initial payment data dominates, after exact
  construction/source/verifier/target correspondence; no unchanged failed rerun.
- Versioned deterministic key derivation/mnemonic and discovery completeness,
  anonymous relay and live private witness recovery, each with its own obligations.
- Private tokens, swaps, a general VM and product UI are outside this publication.
