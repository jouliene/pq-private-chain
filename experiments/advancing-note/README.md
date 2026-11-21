# First-time private payment on an advancing branch

N7P2 is a separately registered research pool derived from N7P1. Run the experiment on Linux x86-64 with two available physical cores, Python 3.11+, bubblewrap with working user namespaces, GNU time, taskset, curl, xz/tar, a working native linker, Git and rustup. Allow ~2 GiB per proving process in addition to the OS and build. The runner downloads checksum-pinned Node 24.22.1, builds locked Rust packages with toolchain 1.93.0 and checks that it can regenerate the embedded verification key byte for byte. Receipts and signatures use Node's built-in OpenSSL 3.5.9. Network access is needed to fetch public source distributions and the released capture. Wallet and validating roles have no network in the walkthrough.

From a new directory, run the following command. The result includes the complete local measurements and original funded evidence. No keys, prior checkout, funded service or owner-supplied backup is needed.

```sh
work=$(mktemp -d) &&
GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=false \
git -c credential.helper= clone --branch advancing-note-2026-11-21 \
  https://github.com/jouliene/pq-private-chain.git "$work/source" &&
bash "$work/source/experiments/advancing-note/reproduce.sh" "$work/result"
```

The script regenerates the key, tests isolated public-row equations, changes all 49 public coordinates under a real proof, and exercises both arities in its funded cycle. It first independently validates the checksummed capture using the separate trusted founding identity, then generates new funding and checks the offline receipt, zero-balance restore, onward spend, double-spend controls, detached/moving roots, near-expiry boundary and jointly signed swap. Each run admits the same ten authentic canonical blocks in three separate, newly initialized two-core validators. Each validator verifies all eleven proofs, both final swap authorizations, current state and the durable block write. The CPU and RAM figures exclude pre-mining, packet construction and the reference wallet-balance calculations. [Decision and prices](DECISION.md) · [Protocol and security review](review/DESIGN.md)

| Output under the run directory | Scope |
|---|---|
| `controls.json`, `registration.json`, `proof-size.json` | Reusable public key, statement and witness rejection, complete proof geometry |
| `capture/`, `published-check.json`, `wire.json` | Released genesis, canonical and alternate public blocks, two competing public packets, authorized founder ID, public-only replay and independent byte reader |
| `fresh/RESULT.json`, `fresh-wire.json`, `fresh-costs.json` | New wallet proofs and balances, native proving overlap with durable inclusion, fork and expiry controls, individual role CPU/RAM, warm and cold trials, measured sample and projections |
| `index-cost.json` | Synthetic disk-index occupancy, independent of proving and throughput measurements |

With an already built binary, `python3 -IB experiments/advancing-note/lab/run.py fresh EXECUTABLE NODE NEW_DIRECTORY` creates a fresh funding capture. `python3 -IB experiments/advancing-note/lab/run.py check EXECUTABLE NODE CAPTURE_DIRECTORY` admits only public artifacts and exercises rollback and window boundaries in disposable stores. The input directory must have `founding-id`, `public/` and `branch/`. The approved founding digest belongs outside the peer-supplied block set. The numbers in the example balances and the private-input count in diagnostic metrics are intentional synthetic test disclosures. Never publish real wallet directories, backups, shared negotiation terms or witnesses. [Wallet harness](lab/run.py) · [Verifier code](proof/README.md)
