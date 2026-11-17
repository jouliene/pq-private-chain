# Fixed long-trace source review

2026-11-18. Independent non-implementing source review; no trace/native/proof run.

SOURCE GO at actual hashes:

- trace.py:9a1aceeeb8688dcbbd3815bef4723f42007da1d1d86d8a68162ce73f15e5e364
- trace.mjs:8b896e4fb7866e2638812d7f86e36d733e380c663a4c64795338b6956ef328f2

Read both entire files and their reused Controller.native/Actor boundary,
sampling, first-wait4 and cleanup seams. No concrete source blocker found.

The three prefixes32/128/260 perform420 real one-block common range operations.
The wallet derives each request from its own authenticated joint session; the
controller checks every request against the complete public base/target context.
Each server result is checked against separate actual frame/header/reduced-row
sizes, and each wallet result must authenticate exactly one block and its real
records. A ready same-head check emits no range request. A separate RAM-backed
reference session remains at genesis until its end-of-case full reconstruction;
comparison is semantic and private, with no serialized notes or hashes.

Zero owned notes are asserted in both wallets. This exercise validates public
history progression/frontier/root work and ownership-independent common ranges;
it does not substitute for S03 genuine receipt, owned paths, spend or recovery.
Old repeated-prefix byte/block/record values are explicitly arithmetic
counterfactuals, not an executed baseline timing measurement.

Fixture use is explicit: Root approves the prior independently verified public
replay dataset. Current genesis/head and all14 canonical hashes must agree, and
all14/database identity are checked again after the trace. No old ELF/verdict is
loaded as wallet authority. The clean reproduction recipe constructs one fresh
DB from the public release closure before this trace; oldDB-only dependence is
not an acceptable independent reproduction recipe.

All261 endpoint contexts, one full scan, prefix reference files and SQL oracles
are prepared outside measured roles. This is a fixed260-height DB for every
request: tip260 startup work is separately counted even for smaller targets.
It is not a growing-database, cold-disk or physical-IO experiment. Logical SQL
blob/row counts and zero selected-query FullscanStep must be checked against
actual records, not inferred from small response size. EXPECTED_COUNTS.json
provides an independently prepared analytical comparison, not executed results.

Private actors reuse reviewed mount/PID/network/seccomp/FD checks and their
finite external sampler. The DB stays outside wallet mounts, deliberately
inheritable denied FDs are probed, fixed parent output overlays must remain empty,
and no proofs are generated. Terminal handshake requires no remaining native
descendants before live Node cumulative CPU readback. Cleanup preserves actual
first-wait4 evidence and emits only fixed public failure stage/schema; raw streams
are wiped rather than persisted.

Resource scopes are explicit: binary436B request/response framing differs from
actual framed JSON/hex control-pipe bytes; history payload files are separate.
Sync wall/Node SELF and waited ticks are separate, not additive with whole-node
or parent metrics. Finite sync-bracket RSS includes baseline heap; it is not an
algorithm-only or guaranteed peak. Server startup/serving spans nest inside CLI
wall/CPU. Actual runtime/source postchecks, all output counts and clean reviewer
execution remain required after source approval.
