# PQ private chain

An independent blockchain research project with private payments and a post-quantum security objective. Run `./pqd start` to launch the first local proof-of-work network with two CPU miners and three validating peers. Follow the [short wallet walkthrough and reproduction instructions](devnet/README.md) to make a payment, restore a wallet from seed and test a deep reorganization. End-to-end PQ security, network privacy and production economics remain open.

Run `./pqd token --home /path/to/new-private-lab walkthrough` to mine and spend one fixed research token. The ordinary wallet handles a token-only recipient, separate mined native funding, one mixed change note, two seed restorations and a fee-changing fork. [Live operator guide and public replay](experiments/token-devnet/README.md)

The first fixed-supply private token prototype uses TKN1. Each note can carry native currency and one token. The research run covers offline receipt, seed recovery, both balance equations and a fresh spend. DLF1 and D8C1 remain the native-only references. [Decision, measurements and reproduction commands](experiments/token-profile/README.md)

The ordinary devnet wallet keeps its verified cursor and local spending paths. It can import an offline recipient's public address, resume a durable payment after a lost reply and restore a fixed chain prefix while mining continues. Run `./pqd wallet-walkthrough` to exercise the published user commands under real proof of work. [Wallet operation and trust assumptions](devnet/WALLET_PROTOCOL.md)

The current CP03 backend provides complete proofs for synthetic authorized
credits and private payments, exact value/fee accounting, nullifiers, durable
atomic ledger updates, encrypted receiving, public history, backup-only recovery
and a newly proved spend. The source includes the prover/verifier, modified proof
library, native signature adapter and wallet. It uses real cryptographic checks,
not a mock ledger or precomputed acceptance verdict.

The [advancing-chain payment experiment](experiments/advancing-payments/DECISION.md) measures independently prepared payments at occupancies one through four, direct producer admission, an externally funded receiver's next spend and competing branches. It includes full public artifacts and [clean reproduction commands](experiments/advancing-payments/REPRODUCE.md).

The [wallet-created payment decision](experiments/wallet-created/DECISION.md) reports six fresh full masked-WHIR payments, a default Qnero wallet comparison and one native two-owner aggregate, with separate pre-inclusion and archive costs. CP03 remains the executable reference.

The next proof experiment selects a direct, one-stage hiding payment circuit on a separate PoW research network. Four independent wallets constructed complete 143,187-byte packets while another block was mined. The existing APV2 devnet remains runnable. [Architecture decision and resource limits](experiments/payment-architecture/DECISION.md) · [Fresh reproduction](experiments/payment-architecture/README.md)

An optional delayed certificate over eight independently admitted DLF1 payments permits a new PoW validator to replay compacted history through another peer. The published experiment measures archival bytes, independent verification, outages, forks and real wallet recovery. [Decision and limits](experiments/delayed-eight/DECISION.md) · [Run the experiment](experiments/delayed-eight/README.md)

## Build and reproduce

Follow [BUILD.md](BUILD.md) for the exact Linux x86-64 prerequisites and commands.
Rust1.99.1, Python3.11+, Node24.22.1 with embedded OpenSSL3.5.9, and system
libcrypto3.0.13 are the currently supported research installation. Node's crypto
provider and the ledger's native SHA3 library are separate dependencies.
Registry dependencies are pinned and vendored; local/path dependencies are
included. Each clean installation explicitly approves its actual runtime identity
and builds into a new isolated workspace with a fresh target. No developer cache,
private historical fixture or original research checkout is a build dependency.

The focused checks execute genuine public signature/proof/state rejection tests
and a new disposable-key credit/payment/receipt/backup-restoration/new-spend
scenario. Public fixtures are synthetic laboratory payments. Private smoke keys,
backups and witnesses are generated locally and are not published. A validated
synthetic credit authority is not permissionless network issuance.

[STATUS.md](STATUS.md) distinguishes the checks actually repeated for the public
revision from historical experiment results. [Delivery](docs/DELIVERY.md) defines
how each later milestone is handed to an independent reviewer by immutable SHA.

## What is here

- `source/`: browsable current ledger, complete payment relation/prover/verifier,
  wallet and native provider, preserving dependency-relative source structure.
- `vendor/`, `Cargo.toml`, `Cargo.lock`: finite pinned Rust dependency closure.
- `scripts/`: setup, trusted runtime installation, build and focused smoke checks.
- `fixtures/cp03-reference/`: genuine public synthetic payments and independent
  public verification inputs; no wallet database or private backup.
- `experiments/network-feasibility/`: version4 larger-block transport, finite
  offered-load/restart tests, isolated local-witness wallet and public replay.
- `experiments/incremental-sync/`: authenticated common-history continuation,
  exact read/traffic measurements, genuine wallet integration and clean review.
- `experiments/architecture-feasibility/`: the real distinct-payment generator,
  public ledger/archive role experiment and local witness reconstruction entry
  points. The short publication smoke does not repeat the32-proof campaign.
- [Architecture](docs/ARCHITECTURE.md), [security assumptions](docs/SECURITY.md),
  [research backlog](docs/RESEARCH_BACKLOG.md) and source import provenance.

The baseline is a selected new-history import from research source revision
`360fc54e6b76dc864131f5c17b80c93b02c8bc67`, with file-level correspondence in
`IMPORT_MAP.json`. Old Git history, internal conversations and historical logs
are not imported. Dependencies retain their upstream license notices; see their
local license/provenance files. Publication makes no new blanket license claim
for third-party code.

## Current practical boundary

The768-ordinary-payment network sample averaged1,751,265.75bytes per body.
At the owner's100M-payment annual sizing input, one body copy alone is
175.126575decimalTB/year, before replicas, relay, indexes and other roles. This is
arithmetic, not measured annual network throughput or an owner traffic budget.
The local full-block experiment includes real admission/archive work and exposes
substantial catch-up costs. Those limits are retained in the architecture decision.

The finite network workload drained its queues with complete retention, and the
264-proof wallet campaign passed local witness recovery, expiry refresh and
controlled rewind. Independent reproduction/publication status is in STATUS.md.
These results retain CP03 for the explicit research model in
[the resource decision](docs/network-feasibility/RESOURCE_DECISION.md).
Ordinary wallet updates now request and authenticate only the new common-history
range from the wallet's own authenticated joint state. Same-head updates need no
history read. Retained shallow checkpoints support branch replacement; deep
replay and cold backup recovery still require full scans. See the
[synchronization results and reproduction commands](experiments/incremental-sync/README.md)
for measured counts, independent acceptance and current publication status.
A subsequent [complete-payment size experiment](experiments/payment-size/RESULTS.md)
saved about 15% with a reversible CP03 representation. Six fresh ordinary
payments, including independent reproduction, remained around 1.48 MB. The
decision retains it as a transport experiment and defers ledger integration.
Full PoW/issuance integration remains behind the payment/history participation decision.
Standalone valid-work PoW remains the preferred consensus direction. No full
consensus engine, permissionless reward issuance or production security is claimed.


The [independent-node payment validation decision](experiments/node-validation/DECISION.md) evaluates a masked sumcheck wallet proof and a transparent block proof over public CP03 payments. CP03 remains the executable reference. The candidate wire sizes and annual role costs are projections. The registered 2x2 matrix, full-size verifier components and pinned Keccak accelerator were actually executed. [Reproduction commands](experiments/node-validation/README.md).
