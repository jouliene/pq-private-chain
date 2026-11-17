# Genuine Network04 workload producer

This is the Gate1 funding/payment generator, derived from the previously reviewed
32-proof producer. It creates fresh disposable private keys and genuine CP03
complete proofs under the unchanged cryptographic profile. The new Network04
manifest and versioned ledger adapter govern the block/genesis limits.

The default run creates 96 distinct authorized laboratory credits, admits their
funding block, privately shuffles the records, and constructs 96 ordinary 2x2
payments spending 192 distinct funded occurrences at that authenticated anchor.
Each ordinary payment's two real outputs go to a fresh receiving wallet. No
input selection, credit-to-ordinary pairing, wallet key, opening or backup is
written or hashed. This generator's membership queries are to its own local
funding ledger, not a claim about Gate3's integrated private wallet witness path.

An explicit `--payments 2` mode creates four genuine proofs to test the changed
genesis/RETAIN/scan/recovery ABI before the expensive run. It is diagnostic only
and cannot satisfy the 96-payment gate. No larger campaign is implemented or
authorized by this generator; Gate2 follows review of actual Gate1 results.

## Run after the approved core installation

Root must first freeze/review the new adapter and build a new installation from
the public canonical source. Review its actual runtime/source identity as in
the root BUILD.md. Then approve this directory's exact SOURCE.json:

```sh
python3 -I experiments/network-feasibility/producer/run.py \
  --label diagnostic01 --payments 2 \
  --installation .work/network01/fresh/installation.json \
  --approve-installation ACTUAL_REVIEWED_INSTALLATION_SHA256 \
  --approve-source ACTUAL_REVIEWED_SOURCE_JSON_SHA256

# Only after the new ABI/adapter controls pass and Root allocates the run:
python3 -I experiments/network-feasibility/producer/run.py \
  --label gate1-96 --payments 96 \
  --installation .work/network01/fresh/installation.json \
  --approve-installation ACTUAL_REVIEWED_INSTALLATION_SHA256 \
  --approve-source ACTUAL_REVIEWED_SOURCE_JSON_SHA256
```

Labels are exclusive; preserve failures and public partial outputs. The supervisor
captures private worker streams in bounded RAM and recognizes only fixed typed
success/failure records. It does not log or hash those streams. Native proof
workers retain the reviewed private-parent pipeline and exact first-wait4/cleanup
receipts; no mock or cached verifier verdict is introduced. One CPU/4GiB AS and
180s diagnostic or 3600s Gate1 watchdogs are research allocations, not service
targets or a global study deadline. The existing per-proof watchdog remains120s.

Public workload output is `.work/LABEL.public/workload.json`: version4 genesis,
two ordered headers, canonical full bodies, exact byte identities and final
endpoint. Generator funding/current-state validation is not receiving-node
throughput; the separate transport experiment must still transfer and genuinely
validate these bytes without access to the generator's database or fixtures.

`proof-costs.json` separates public credit and ordinary entries. Worker wall/CPU/
peak-RSS come from actual private-parent first-wait4 receipts. Worker time includes
its genuine local verification. `private_proving_call_wall_seconds` includes the
private bridge pre/postflight, complete-body publication and Parent receipt read;
it is not isolated algebraic proving time. The producer ledger then verifies the
bodies again during block admission. The outer receipt includes complete producer
work and waited descendants; its peak is not a sum or simultaneous process-tree
RSS. No live wallet throughput, WAN result, complete node resource profile,
formal PQ/privacy assurance or Gate1 transport acceptance follows from generation.

Full funding amounts/fees remain checked. With 96 credits of100,000,000 atoms,
the two accepted blocks have384 leaves,192 current nullifiers, fee escrow
405,986,208 and zero unconsumed source liabilities. These are expected oracles;
actual public artifacts and an independent receiving ledger must corroborate them.
