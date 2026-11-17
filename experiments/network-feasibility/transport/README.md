# Network04 transport and retained-validator discriminator

Active implementation of Gate1 in NETWORK_FEASIBILITY_GOAL.md. No network
campaign or new proof generation has executed yet. Root owns the normative
CP_NETWORK_04 contract/manifest, source freezes and heavy allocations. Existing
legacy CP03 fixtures and proof/security parameters remain unchanged.

The additive adapter selects CPGEN004/schema3, CPBLOCK4/CPSBLK04/CPNET004 and a
separate fixed compiled manifest. It permits0..128 bodies with an independent
complete encoded256MiB cap, including228 fixed bytes,68 bytes/body overhead and
the exact full body bytes. Reduced scans recompute that full size from canonical
prefixes plus declared proof lengths. Old version3 encodings retain old limits.

Gate1 uses separately generated96 authorized credits and96 genuine nonconflicting
ordinary2x2 payments. Destination RETAIN is explicit persisted local policy:
all full bytes count against cache/disk, no required export queue exists, and
eviction/publication through the local managed-archive API is prohibited. This
finite policy is not an acceptable automatic175TB/year ordinary-node claim.
Managed archival policy remains available independently, with16-item operational
batches and64MiB segments; those are not block-count limits.

The separate archive role will store opaque bounded full-frame blobs with file
fsync, atomic publication and directory fsync before a durable-byte ACK. It does
not verify payment proofs or issue an admission verdict. The destination must
actually receive the frames and perform genuine verification/state/atomic commit.
A duplicate-delivery ACK is allowed only for an exact already-current canonical
header, never because an archive remembers an old branch or verifier result.

Declared initial links are100Mbit/s of cumulative application bytes, with40ms
RTT simulated once per RPC, not per chunk. This is paced separate-process local
loopback, not WAN evidence. Proposed CPU assignment is producer0/archive1/
validator2 after actual affinity readback, one CPU and4GiB AS per role. Root's
8GiB finite output ceiling per role is an experimental watchdog, not a production
storage budget. Byte/framing/retry/persistence costs will be recorded by role.

Bounded implementation queues: one producer in-flight frame; one validator full
frame at most256MiB plus bounded parser/admission copies; at most two archive
connections (one PUT and one GET),64KiB user-space chunks and requested kernel
buffers (actual buffer sizes read back), at most two incomplete256MiB spool files.
No unlimited application queue or assumed pipeline overlap is credited.

The receiving process will be filesystem-isolated from the actual producer
fixture/database subtree with bwrap and a private PID namespace/proc mount. The actual generated proof
public subtree is also masked, as are legacy fixture evidence areas when present.
The launcher probes the native host PID namespace and known forbidden files
through its actual root, not only the wrapper. This is a deny-listed read-only
host view, not an allow-list sandbox: unrelated host paths remain visible.
Trusted runtime/program/library paths, its own writable retained database and
network endpoints remain available. Correctness
snapshots and public state/file oracles run in the launcher outside measured
roles. Interrupted transfer, coherent-header invalid-last-proof and lost ACK
across durable archive publication will be exercised before a positive outcome.

Cheap tests in tests/schema04.py exercise only SQL structural trigger/accounting
invariants. They do not assert genuine proof or ledger admission success. Rust
codec unit controls are included in the shared history source for the next
reviewed build. No heavy build/proof is authorized by invoking this README.

## Implemented entry points (source-only checkpoint)

`build.py` builds the finite native validator from an explicitly approved public
installation, isolated Cargo target, exact finite vendor and frozen own source.
`campaign.py` checks the actual build receipt, transfers only public bytes, and
runs one finite lifecycle. `prepare.py` is the external public byte oracle: it
constructs exact CPNET004 frames and a coherent negative header with its last
opaque proof-commitment byte changed. Its repeated hashing and frame-copy disk
are launcher work, outside role timing; prepared frame storage and original
producer public storage are reported separately. No oracle supplies validity.

`sender.py` is the producer transfer process, reading one public object in64KiB
chunks. `archive.py` accepts at most two application connections, one PUT and one
GET (listen backlog requested2 is separately a kernel queue). A PUT's advertised
bytes cannot exceed256MiB. Archive SHA256 is byte integrity only. A file fsync,
link publication and directory fsync precede ACK. The explicit laboratory crash
request exits after durable full funding publication and before ACK; restart and
resend must identify the exact stored bytes. An interrupted PUT publishes no blob.
All successful, failed and retried application bytes are counted. TCP/IP headers,
retransmission and real WAN behaviour are outside this application-byte model.

The native validator's argv contains only its own DB, chain and archive address.
It downloads each object, checks bounded framing/public IDs and calls actual
`Ledger::apply_expected_block`. One frame and its body API copies are explicitly
priced; the256MiB wire limit is not a256MiB RSS claim. An already-current canonical
retry still receives, parses and hashes the whole object, then compares the exact
canonical header, without re-admitting it. It cannot reuse historical verdicts.
Producer and destination all14 SQL tables are externally compared, excluding
only the random local body_cache.catalog_id; actual caches and empty archive
tables remain compared. The all-table negative-control snapshots and final retained-byte checks are
external launcher SQL reads while the validator is paused between commands.

The lifecycle requires every body of the malformed ordinary candidate to reach
its real proof attempt, actual `Error::Proof` on the final proof, unchanged full
SQL state, and subsequent successful ordinary admission. Funding should cost N
proof and N source-signature attempts; after failed N and successful N ordinary
admissions, the physical counts should be3N/N, not2N/N. A fresh isolated process
reopens the durable result. These are checks to execute, not observed results.

Per-call native spans measure receive/identity, frame parsing/copy and real
admit/commit/retain. The additional inclusive command span covers these calls and
head/accounting readback; do not add it to nested stages. Process wall includes
external-oracle idle waits and cannot be divided by N as service time. Linux
self-I/O, waited-child CPU and cumulative peaks remain separate. The launcher
samples simultaneous role-tree RSS and disk for every live role while waiting;
short peaks may be missed. RLIMIT_AS4GiB applies per process, not a cgroup sum;
the observed tree ceiling is a sampled research watchdog. Disk ceiling8GiB is
also observed periodically, with logical and allocated bytes reported. This
qualification must remain visible in any resource conclusion.

After source review and Root allocation, use exclusive labels:

```sh
python3 -I experiments/network-feasibility/transport/build.py \
  --label build01 --installation .work/network01/fresh/installation.json \
  --approve-installation REVIEWED_SHA256 --approve-source SOURCE_JSON_SHA256
python3 -I experiments/network-feasibility/transport/campaign.py \
  --label diagnostic01 --build-label build01 --approve-build BUILD_JSON_SHA256 \
  --installation .work/network01/fresh/installation.json \
  --approve-installation REVIEWED_SHA256 --approve-source SOURCE_JSON_SHA256 \
  --workload experiments/network-feasibility/producer/.work/diagnostic01.public/workload.json \
  --approve-workload WORKLOAD_SHA256
```

An approved96 workload uses the same runner after diagnostic/source review. The
2-payment diagnostic does not satisfy Gate1. The512MiB local retain quota is
explicit and sufficient only for this Gate1's two bounded frames; Gate2 needs a
new explicit provisioned quota and reviewed observation/schedule. No larger
workload is generated or implicitly authorized by these commands.

Tiny `tests/source_controls.py` checks counted partial socket operations with a
local object, exact-table rejection and actual failed-child first-wait4 evidence
retention. Its three checks passed; it is not a native/payment or network run.

The launcher fsyncs the newly provisioned role/work directory ancestors before
starting roles; the archive also fsyncs its root and immediate parent at startup.
ACK promises use ordinary file/directory fsync semantics on that provisioned
local filesystem. Crash79 is a process-crash control, not a power-loss or faulty
hardware experiment. Prepared source-frame durability is a separate producer
obligation and is not inferred from an archive's ACK.


## SOURCE02 measurement correction

The real SOURCE01 diagnostic is retained in DIAGNOSTIC01.json and its exact
source under freezes/source01/. It passed the functional controls with2 ordinary
payments. Its observed bwrap leader wait4 CPU/RSS excluded the native validator;
those wrapper totals must never be used as complete native resource costs.

SOURCE02 adds a native terminal cumulative receipt after the command function
returns and drops Ledger/providers. It reports absolute getrusage SELF and
CHILDREN CPU, separate cumulative RSS peaks, self Linux I/O, block-I/O counters
and actual CPU affinity. It includes startup and completed command-loop work up
to sampling; final terminal JSON serialization/exit follows that sample. Its
main-lifetime wall includes external-oracle idle and is not a service-time sum.
The launcher still records bwrap's actual first wait4 but explicitly labels it
wrapper-only, and requires a successful native terminal receipt/CPU2 from both
the original validator and fresh reopen. Absolute native self/child CPU counters
must each cover the sum of corresponding nonoverlapping inclusive command
spans, allowing2microseconds for floating rounding. Nested stages are not added.
Never sum cumulative RSS maxima.

No protocol, canonical source, proof, acceptance or transport framing changed.
Corrected SOURCE02 must be reviewed/built and pass diagnostic2 before a96-payment
network campaign. Root's independent proof-generation allocation is separate.
