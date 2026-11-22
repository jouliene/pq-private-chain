# SGM1 on two physical cores

This experiment measures how quickly one home machine can verify and durably apply private payments and swaps. It uses an isolated ledger with the published four-group SGM1 proof registration. The funded C PoW network remains available at the starting revision `beae20b4b9b81598708262cc407f21553ca7ae94`. [Decision and operating range](DECISION.md) · [Independent cryptographic review](review/SECURITY.md)

## Reproduce

On Ubuntu 24.04 x86-64 use the distribution's Python 3.12, NumPy 1.26.4, python3-dev, python3-psutil, g++, libssl-dev, curl and xz-utils. The prover and verifier use PCLMULQDQ and SSE4.1. Use a disk-backed scratch directory for durability measurements. The runner downloads the pinned Node 24.22.1 binary and checks its SHA-256. Its receipt and signature helpers also require the registered OpenSSL 3.5.9 provider. Set `SGM1_PROVERS` from 1 to 6 to control fixture preparation concurrency. Timed validation always uses two distinct physical cores.

```bash
bash experiments/sgm1-admission/reproduce.sh "$(mktemp -d)/run" capacity
```

The default `capacity` run creates a fresh signed funding prefix and 100 distinct operations, compares all 110 accepted proof legs with the original public verifier, exercises rollback, runs negative controls, then measures eight separate admissions of the complete stream on fresh databases. A further eleven catch-up processes each replay this same history into an empty durable store. The twelve-pass series charges startup and signed funding on every pass, and tests sustained verification of previously available history. Live counts include each payment once on its own branch. The shorter `walkthrough` runs the same functional scenarios on 18 payments and two swaps, then measures the 100M-year arrival rate, an overload and historical catch-up. `ci` runs the two-wave correctness checks. Its timings are outside the hardware decision.

The runner places the public corpus in `run/public/`, the functional receipt in `run/controls.json`, actual arrival/commit and per-operation measurements in `run/loads/traces.json`, and the calendar calculation in `run/capacity.json`. Recompute the projections with `python3 experiments/sgm1-admission/report.py run/loads/traces.json`. The corpus generator needs no original wallet or stored proof. No private witness, note-opening record, backup or signing key is written to the evidence. Wallet peers run separately on a cooperative host. OS privilege separation or resistance to a malicious host is outside this experiment. The synthetic genesis and issuance records include their deliberately public grants.

## Replay the exact published payments

The versioned [public corpus](https://github.com/jouliene/pq-private-chain/releases/tag/sgm1-two-core-2026-11-22) includes the 100-operation trace, the genuine conflicting transaction, public funding, and the older SGM1 payment identified by its published digest. The archived tests need only public data. Use fresh generation above to exercise both private signing processes and backup recovery with new keys.

```bash
s=$(mktemp -d)
curl -fL https://github.com/jouliene/pq-private-chain/releases/download/sgm1-two-core-2026-11-22/sgm1-public-100.tar.gz -o "$s/corpus.tgz"
echo "eb9126b06ac3d84b628528bb622fb8b331d0f0d7a59548a2ea7473f096bbeb2b  $s/corpus.tgz" | sha256sum -c -
mkdir "$s/inputs"
tar -xzf "$s/corpus.tgz" -C "$s/inputs"
(cd "$s/inputs" && sha256sum --quiet -c SHA256SUMS)
bash experiments/sgm1-admission/reproduce.sh "$s/replay" public "$s/inputs/public"
FS_RECEIPT_NODE="$s/replay/node-v24.22.1-linux-x64/bin/node" SGM1_NATIVE_LIB="$s/replay/native/libsgm1_verify.so" python3 experiments/sgm1-admission/native/replay.py "$s/inputs/legacy" 783d64bbbd924023a813dbe8b6c279013bd6d3dcdb2b0702466708ab48b6bac9
```

## What a node verifies

The starting chain has eleven pinned native grants and two distinct fixed-supply issues carrying SLH-DSA-SHAKE-256s signatures. The pin comes from test network setup. Consensus selection and mining stay outside this selected-branch experiment. Each subsequent isolated block holds one ordinary frame or one complete ordered swap. The block identity hashes the parent, height and full wire. The signed-prefix spend anchor identifies a chain/genesis-bound funded root and count. Two histories with the same funded state have the same proof anchor. Current branch eligibility, output occurrence uniqueness and spentness are ledger checks. The last 64 predecessor states are eligible under this registration. [Public funding replay](../hidden-membership/paths/funding_fixture.py) · [Packet grammar](packets.py)

An ordinary packet retains the published SGM1 byte format. Each swap holds role 1 and role 2 in an FSW1 frame. Their intents also bind expiry, a private-terms commitment and the role's ephemeral approval key. Both SLH-DSA signatures cover both complete, ordered cores. Role 1 pays the single native fee and role 2 pays zero. Each physical leg, including its signature if present, is bounded at 262,144 bytes. The pair has 20 additional framing bytes. Each resident wallet generates its own backup and final authorization keys, validates its local copy of the selected history and checks its incoming output against its agreement before releasing approval. The coordinator receives public cores and offer details, including negotiated quantities. [Resident wallet](swap_owner.py) A 64-byte FS01 backup and common validated history suffice for the first-time recipient's onward spend. The proof continues to have two input slots even for the single real recovered input.

The previous ordinary parser supports role zero. The comparison for swap legs uses the same Python monetary circuit with a role-specific intent recomputed by the new ledger.

The native library reconstructs the entire monetary setup for each public statement. Its only reusable preprocessing is fixed public algebra and permutation data. The validating thread selects the eligible anchor before dispatch. After stateless verification, the ordered writer checks selected branch and spentness again under `BEGIN IMMEDIATE`. SQLite stores both receipt-bearing cores, fees, four swap nullifiers, four new occurrences, Merkle nodes and undo records in one synchronous WAL transaction. Replacing a suffix rolls back the losing history and verifies the replacement in the same transaction. [Native registration](native/README.md) · [Ledger](ledger.py)

## How capacity is measured

Each measured worker starts with an empty local database. Funding verification is timed separately. Affinity includes the verifier threads, the public frame reader, SQLite writer and child signature processes. Each transaction pays its statement-dependent setup cost. Two operations can undergo cryptographic verification concurrently. One writer publishes them in order. Affinity selects one logical CPU from each of two distinct physical cores. The remaining host CPUs and operating-system services are outside the validator's allocation.

A separate ingress thread reads actual frames from disk on a fixed schedule. It records when each complete frame enters memory. The reported backlog includes queued and in-flight operations until durable commit. At saturation, arrival and completion counts can differ throughout the trace. In catch-up mode input is continuously available with a bounded queue of eight waiting operations and two checks in flight. Each trial starts a fresh process. Filesystem caches may already contain the public frames. The measurement excludes P2P transport, PoW, wallet proving, external traffic generation and the independent Python oracle.

CPU includes the process and its reaped signature helpers. The per-process OS high-water mark and peak sampled sum of RSS over the validator plus helpers are reported separately. The latter is sampled every 20 ms, can miss a brief maximum, and may count shared pages more than once. Filesystem cache is outside both measures. Commit-to-arrival latency includes ordered waiting and durable WAL commits. The final WAL checkpoint and closed database extent are reported separately. Calendar and cold-history projections assume the measured operation mix and service rate persist with a larger state. [Measurement code](measure.py) · [Projection calculation](report.py)

## Checks kept outside the clock

Every ordinary frame and both legs of every pair are checked against the Python implementation on the same genesis, public roots and packet bytes. A separately rebuilt full Python tree, fee oracle and nullifier set must agree with incremental SQLite state at every height. Both verifiers reject full-length changes to public statements and distinct stages of the proof. The integration test also mutates each signature and the second proof, rejects an unpaired leg, restarts the durable database, runs two genuinely conflicting proofs through the same eligible snapshot, and invalidates an already verified result after a branch change. An invalid replacement keeps the entire original suffix. The alternative branch spends the maker's funding and leaves the other swap owner's inputs untouched. [Controls](controls.py)
