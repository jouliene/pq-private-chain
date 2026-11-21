# Verify the funded TCitH swap leg

The isolated registration FTL1 pairs one complete wallet-created TCitH leg with one released SLG1 leg. Separate wallet processes sign both legs together after opening the incoming receipt and checking change. The normal local PoW devnet continues to run MNG1/SLG1. [Architecture decision](DECISION.md) · [Proof protocol](proof/README.md) · [Wallet](wallet/README.md) · [Security review](security/REVIEW.md)

## Public reproduction from an empty checkout

Use x86-64 Linux with working unprivileged nested bubblewrap, Python 3.11+, NumPy/SciPy, Bash, git, curl, GNU tar/time, GCC with C++17 and OpenSSL development headers, and Rustup with the 1.93.0 toolchain. The dependency build needs a C compiler, Cargo registry access and the pinned public Qnero upstream. Allocate scratch space for the Rust build. From the final tested Git revision run:

~~~sh
bash experiments/funded-tcith/reproduce.sh
~~~

The command downloads two SHA-256-pinned public inputs, rebuilds the two legacy proof roles and the FTL1 engine, regenerates its pinned public program, checks two independent design calculations, then replays the public funding history and exact signed bytes. Two disposable nodes execute the conflicting registrations in opposite orders. A competing mined branch displaces the original anchor. A separate startup reconstructs the wallet-history index, including the orphan. Identical funding, spends, fees, proof hashes and branch outcomes are required. Timing and resident-memory measurements vary by host. The script prints the public results and writes them in its scratch directory. [Public archive and checksum](RELEASE.sha256) · [Deterministic comparison](node/compare.py)

The public archive contains only twelve complete mined funding blocks, the matched signed bundles and a manifest with intentionally disclosed disposable test terms and measurements. No prover is needed for this replay. The working copy of the approved deployment contains source, reference executables and verification keys. The public role starts in a fresh read-only Linux namespace with an empty writable temporary filesystem. Its node selects the funded block, derives the leaf count and auxiliary root, recomputes the receipt digest and checks the signed pair. Ordinary inputs arriving from the peer include neither a circuit nor a trusted root. The experiment recalculates the auxiliary tree over the selected prefix at admission. A scalable persistent index and its witness-update costs remain unmeasured.

For an already source-approved public MNG1/SLG1 deployment, supply a new empty scratch directory and the existing deployment directory as the two arguments. This reuses only the released native roles. The public FTL1 verifier, shape and fixtures still come from the new checkout and the pinned public release.

~~~sh
bash experiments/funded-tcith/reproduce.sh "$(mktemp -d)" /absolute/path/to/approved/deployment
~~~

## Generate a new funded signed leg

Use the same proof and runtime toolchains. The native walkthrough creates its own unrelated, disposable funding and wallet seeds. Keep that directory private. After completing public reproduction with an explicit scratch directory, run the following from the same checkout. All private assignments stay in a single owner's process or its prover pipe.

~~~sh
lab=$(mktemp -d)
bash experiments/funded-tcith/reproduce.sh "$lab/replay"
./pqd swap --home "$lab/network" native-walkthrough
upstream=$(find "$lab/network" -path '*/build/upstream/.git' -type d -print -quit)
upstream=${upstream%/.git}
test "$(git -C "$upstream" rev-parse HEAD)" = f04c91307837c0231668383bec76ba98d89d2652
python3 -IB experiments/funded-whir/wallet/build.py "$lab/capture" "$upstream" "$(dirname "$upstream")/target"
constants="$lab/replay/qp-poseidon-core-3.1.0/src/poseidon2.rs"
python3 -IB experiments/funded-tcith/wallet/run.py "$lab/network" "$lab/capture" \
  "$constants" "$lab/replay/tcith" "$lab/replay/shape" "$lab/fresh"
python3 -IB experiments/funded-tcith/node/run.py "$lab/network/deployment" "$lab/fresh" \
  "$constants" "$lab/replay/tcith" "$lab/replay/shape"
~~~

Fresh wallets and randomized proofs have different packet hashes, Merkle frontiers and PoW branches. Compare deterministic ledger controls within that run. The optional full-depth synthetic proof and malformed-transcript controls have a separate entry point. The candidate gate and any migration require evidence on branch binding and extraction beyond these executions. [Synthetic controls](proof/smoke.py) · [Priced alternative](security/WIDER.md)
