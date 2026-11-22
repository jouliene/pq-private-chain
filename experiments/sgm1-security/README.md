# Reproduce the SGM1 monetary-security decision

Run on Ubuntu 24.04 x86-64 with PCLMULQDQ and SSE4.1, CPython 3.12, NumPy 1.26.4, C/C++, OpenSSL development headers, GNU time, curl and xz. The script verifies the Linux x64 Node 24.22.1 archive by SHA-256, checks the original SGM1 release archive, and builds both native field arithmetic and the registered SGM1 ledger verifier. Ubuntu packages are python3-dev, python3-numpy, python3-psutil, gcc, g++, libssl-dev, time, curl and xz-utils. Use a new scratch directory each time. No external proving or validation service is involved.

```sh
PATH=/usr/bin:/bin bash experiments/sgm1-security/reproduce.sh "$(mktemp -d)/run" published
```

The runner replays the original released SGM1 payment from signed public funding, compares the observer and bounds outputs byte-for-byte, and in published mode also verifies the author's exact new EAR1 payment. It then generates another private two-input EAR1 payment, checks both receipts and four monetary mutations, exercises cross-suite rejection and an equal-length early-table mutation, tests malicious relay substitutions and settles two new genuine swaps. Wallet funds and keys are generated locally. Genesis, packet hashes, timings and wallet-session digests change on fresh runs. The two checksum-pinned author transcripts and pure calculations have deterministic output.

The machine-readable outputs in the scratch directory include SGM1_TRACE.json, OBSERVER.json, BOUNDS.json, EAR1_TRACE.json (published mode), fresh-payment.json, ear1-controls.json, wallet-negative.json and wallet-honest.json. To obtain the chronological event list as well as the grouped byte census, reuse the built scratch directory with the following command from the repository root.

```sh
work=/path/to/completed/scratch/run
OPENBLAS_NUM_THREADS=1 PYTHONDONTWRITEBYTECODE=1 SW_FIELD=gf256 PYTHONPATH="$work/native" \
FS_RECEIPT_NODE="$work/node-v24.22.1-linux-x64/bin/node" \
python3 -B experiments/sgm1-security/trace.py "$work/legacy" \
    783d64bbbd924023a813dbe8b6c279013bd6d3dcdb2b0702466708ab48b6bac9 --events
```

Only the EAR1 ordinary-payment frame and the three signed public funding files are in the new archive. SHA-256 is `5f6bdc65105e3cdde4551b7cbd97f3f8c96f72a76ad434a6c1d85b627901ea80` (240,737 bytes). Funding uses the transparent research grant and signed issuance encoding. Wallet backups, proof witnesses and databases remain outside the release. [SGM1 public inputs](https://github.com/jouliene/pq-private-chain/releases/tag/sgm1-two-core-2026-11-22) · [EAR1 public inputs](https://github.com/jouliene/pq-private-chain/releases/tag/sgm1-early-degree-2026-11-22) · [Decision](DECISION.md)
