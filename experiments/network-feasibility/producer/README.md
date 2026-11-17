# Gate2 rolling Network04 workload producer

This source candidate creates fresh disposable keys and genuine complete CP03
proofs for the declared Gate2 workload. It is not authorized to execute until
Root reviews the source and assigns the sole heavy slot. The unchanged Network04
rules, fees, proof programs and private Parent pipeline remain active. There is
no reserve, backup, idle key-holder or Gate3 secret handoff.

The full profile has 96 authorized laboratory credits in one funding block,
followed by eight successive blocks of 96 distinct ordinary 2x2 payments. Each
ordinary batch uses the immediately preceding accepted block's root/count.
Each lane owns exactly two current notes; shuffle the 96 intact owner pairs
independently each batch, never pair notes across spending owners. Both outputs
of each payment go to one newly generated destination wallet, which becomes that
lane's owner for the next batch. Dispose the spent wallets after batch admission
and all remaining keys/payments on success or failure. There is no retained
private restart state; native KeyObjects/immutable JS strings have no erasure
proof, and process exit is part of the lifecycle.

The fixed diagnostic profile is two lanes and three ordinary batches: eight
complete proofs and four admitted blocks. It exercises receipt reuse, repeated
anchors, fees and conservation before the 864-proof full run. It is not the Gate2
service/load experiment. Labels are exclusive, including each Parent attempt;
failed labels and their partial public outputs are preserved, never retried.

## Bounded fixture receiving and membership

Every destination wallet is newly generated for that round and its descriptor
has been used only for the two outputs in the immediately preceding admitted
block. This controlled-fixture premise permits scanning only that latest block;
it would be false for general wallet recovery. One actual receipt-adapter
`contextsBatch` call derives the statement contexts once per batch. For every
lane wallet, `collectLocalCandidates` tries every latest envelope with its real
ML-KEM key: KDF, key confirmation, AES-GCM and canonical plaintext/owner/commitment
checks stay active. Recheck receipt digests against canonical parsed statements,
require exactly two candidates and the exact fee-derived balance. Derive their
indices from common public statement/output order, then require the installed
local ledger's membership origin/CM/index to match. Across the batch, the selected
indices must cover every latest funded occurrence exactly once.

This is generator-local fixture extraction with a public Ledger membership
oracle, not the selective witness algorithm, general `recoverHistory`, backup
recovery, ownership-private remote queries or Gate3 acceptance. Canonical wallet
and recovery source are untouched. No input pairing, note opening, key, private
packet or selection digest is written, hashed or logged. The existing installed
`provePayment` consumes its packet once through the unchanged callback and waits
for the genuine Parent worker; this driver never extracts that packet.

## Installation, quota and commands

Use an explicitly reviewed current installation as in root BUILD.md, plus this
directory's exact SOURCE.json approval. SOURCE03 also pins the declared root
`experiments/network-feasibility/GATE2_PROFILE.json`. There are only two fixed
profiles, `--payments 2` (2x3) and `--payments 96` (96x8).

The frozen installed public wallet wrapper's `.init()` has a 512 MiB RETAIN
default and no quota argument. The existing native CLI already accepts
`init-retain DB CHAIN GENESIS HARD_BYTES`. `retain-init.mjs` performs only that
fixed public initialization with **2147483648 bytes**. It executes the approved
ELF through a held FD, checks regular ELF/size/inode/metadata/SHA before and after,
requires exact successful typed public output, then reopens and matches every
head field through the unchanged wrapper. All subsequent operations use that
wrapper. No SQL quota edit, installed overlay or canonical core mutation is used.
The public `retention-init.json` preserves actual native status and validation
booleans even on failure; raw diagnostics are neither forwarded nor retained.

```sh
# Only after reviewed source and Root's diagnostic allocation:
python3 -I experiments/network-feasibility/producer/run.py \
  --label gate2-diagnostic01 --payments 2 \
  --installation .work/network01/fresh/installation.json \
  --approve-installation ACTUAL_REVIEWED_INSTALLATION_SHA256 \
  --approve-source ACTUAL_REVIEWED_SOURCE_JSON_SHA256

# Only after actual diagnostic readback and a new explicit allocation:
python3 -I experiments/network-feasibility/producer/run.py \
  --label gate2-96x8-01 --payments 96 \
  --installation .work/network01/fresh/installation.json \
  --approve-installation ACTUAL_REVIEWED_INSTALLATION_SHA256 \
  --approve-source ACTUAL_REVIEWED_SOURCE_JSON_SHA256
```

The inherited bounded private capture recognizes only fixed typed success/failure
records and never persists or hashes raw worker streams. Source/runtime/provider
pins are checked before/after, including the installed private approvals and
lifecycle helper. Internal watchdogs are 360 s diagnostic and 10800 s full,
one CPU / 4 GiB address space; Root's outer allocation/cleanup is separate.
Per-proof watchdogs/verification are unchanged. These are finite research limits,
not a node target or universal architecture boundary. Keep the first actual
failure stage/status. No generator, private or native run is claimed by this
source candidate.

## Public outputs and expected accounting

Output is `.work/LABEL.public/workload.json`, with exact schema
`CP04-NETWORK-PIPELINE-WORKLOAD01` and top-level fields:

- `format`, `block_version: 4`, `ordinary_count` (total), `batch_size`,
  `ordinary_batch_count`, `chain`, `genesis`, `blocks`, `endpoint`.
- `genesis` and each `header`/body use `{path,sha256}` with normalized paths relative
  to the workload directory. `blocks` has one funding block, then each ordinary
  block in canonical order; each has `{header,bodies}` and exactly N bodies.
- Endpoint fields are decimal strings `height,leaf_count,fee_escrow,
  unconsumed_liabilities` and hex strings `block_id,root_le`.

Full shape is N=96, B=8, ordinary_count=768 and nine blocks. Diagnostic shape is
N=2, B=3, ordinary_count=6 and four blocks. Final native checked scan supplies
all headers; admissions and each changing-root/count/fee boundary are checked.
Transport independently reconstructs and genuinely validates these bytes without
producer DB/private access. Generation does not establish service throughput.

Each original Parent receipt remains unchanged in the installed source's public
evidence directory. `proof-costs.json` contains per-proof worker first-wait4
CPU/wall/peak-RSS, inclusive private proving-call wall, batch number and original
receipt path/hash. Per-body `.proof-cost.json` preserves completed public costs if
a later job fails. Per-batch receipts retain actual accepted anchor/endpoint and
inclusive/admission wall; no secret mapping or amounts are emitted. The private
proving-call interval includes bridge checks, body publication and Parent receipt
read, and worker time includes its own genuine verification. Producer ledger
admission verifies all complete proofs again. These nested times are not added as
independent costs; peak RSS is not a sum or simultaneous whole-tree measurement.

With credit 100,000,000 per lane and exact fees [2116775,2112174,2112248], expected
full state is height 9, 1728 leaves, 1536 consumed ordinary nullifiers, 864 consumed
COREs, 96 consumed sources, fee escrow **1,825,416,864**, liabilities 0 and remaining
note supply **7,774,583,136** (80,985,241 per lane). Diagnostic expected state is
height 4, 16 leaves, 12 nullifiers, 8 COREs, 2 consumed sources, fee escrow
**16,907,038**, liabilities 0 and remaining note supply **183,092,962**.
The 40..50M output split stays positive through these fixed rounds; each actual
input sum and remaining balance is checked. These are source oracles until actual
public artifacts and independent receiving state corroborate them.

At the complete body cap, 864 bodies occupy at most 1,820,080,800 raw bytes,
below the 2 GiB raw-body quota; this is not a filesystem-size cap. Count public
body files, producer SQLite/journal, final scans, Parent proof copies, prepared
transport frames, archive and receiver storage separately. Generation/proving,
fixture receiving/preparation, repeated validation and later network service
remain distinct measured obligations. No WAN, annual capacity, production or
formal joint privacy/PQ conclusion follows from this workload.

## Preserved Gate1 source

`freezes/source01/` contains exactly the old three files and original SOURCE.json
(SHA256 `572433969448de0a293e80b59c278f275122e926dddf9ac61f1e195fbe0e82d3`),
also preserved at commit `9258323`. Restore those four bytes at their original
producer paths in a separate checkout to reproduce that reviewed historical
runner; the relative-path installation assumptions mean the frozen `run.py`
is not intended to execute in place inside `freezes/`. Gate1 actual artifacts
and receipts are unchanged. This successor neither regenerates nor overwrites
the Gate1 campaign.
