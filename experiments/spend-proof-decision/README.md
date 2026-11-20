# Funded spend-proof decision and reproduction

Start with the [engineering decision](DECISION.md), [security review](assurance/REVIEW.md) and [funded-note consequences](FUNDED_NOTES.md). The [independent review](review/REVIEW.md) provides full Linux commands to build the pinned native program and reference tools, mine a baseline network, generate new payments and authorizations from fresh wallets, restore their seeds, verify public proofs in separate processes and run the compact and WHIR-frontend comparisons. The [release](https://github.com/jouliene/pq-private-chain/releases/tag/funded-spend-proof-2026-11-20) contains the precise tested artifacts. A new randomized proof or PoW branch will have a different digest.

## Quick public checks

From the release checkout, run the following. Python 3.10+ suffices for the local parameter/receipt checks. The download uses GitHub CLI and GNU tar/coreutils. These checks parse keys, authenticate release files and reproduce receipt observations. Fresh native proof verification and fresh funding use the separate full reproduction commands below.

~~~sh
p="$PWD/experiments/spend-proof-decision"
w=$(mktemp -d)
gh release download funded-spend-proof-2026-11-20 --repo jouliene/pq-private-chain --pattern '*.tar.gz' --dir "$w"
(cd "$w" && sha256sum -c "$p/RELEASE.sha256")
mkdir "$w/base" "$w/author"
tar -xzf "$w/SPEND-baseline-public.tar.gz" -C "$w/base"
tar -xzf "$w/K384-author-public.tar.gz" -C "$w/author"
(cd "$w/base" && sha256sum -c SHA256SUMS)
(cd "$w/author" && sha256sum -c SHA256SUMS)
python3 -IB "$p/assurance/extract.py" --check
python3 -IB "$p/receipts.py" "$w/base" | diff -u "$p/RECEIPTS.json" -
~~~

After fetching the upstream crates through the locked build, the following independently derives the proof-specific Fiat–Shamir positions and authenticates the fixed-oracle openings on three complete baseline and three K384 proof artifacts. These additional checks complement native public verification.

~~~sh
set -- "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/qp-plonky2-core-1.5.5
python3 -IB "$p/assurance/extract.py" --public "$w/base" --core "$1" --check
python3 -IB "$p/assurance/extract.py" --candidate "$w/author" --core "$1" --check
~~~

## Fresh private wallets and public verification

Use Linux x86-64 with a C toolchain, Rustup, Git, unprivileged bubblewrap, GNU time and sufficient memory for two-thread proving. The full independent OpenSSL signature check uses the pinned Node/OpenSSL binary described in the reviewer guide. The first command below builds both existing native roles and starts and stops fresh local miners and nodes as part of the walkthrough. Its private wallets stay in the fresh work directory. The second build creates only isolated K384 roles and new test wallets.

~~~sh
rustup toolchain install 1.93.0 --profile minimal
export RAYON_NUM_THREADS=2
lab=$(mktemp -d)
./pqd swap --home "$lab/network" walkthrough
set -- "$lab/network"/source-build-*/build
b=$1
p="$PWD/experiments/spend-proof-decision"
python3 -IB "$p/candidate/reproduce.py" "$lab/candidate" "$b/upstream" "$b/roles" --target "$b/target"
python3 -IB "$p/candidate/build_compact.py" "$lab/codec" "$b/upstream" "$b/target"
python3 -IB "$p/compact/compare.py" "$lab/codec/compact" "$lab/candidate/public" "$lab/encoded"
~~~

The reviewer guide adds a separate build of the full-tree reference, independent four-node money/supply replay, OpenSSL signature verification, timed cold/warm public processes and a second implementation of full-packet compact readback. The release carries the raw timings. [Full commands](review/REVIEW.md#reproduce) · [Independent machine results](review/INDEPENDENT.json) · [Public receipt field map](RECEIVING.md) · [Alternate frontend experiment](WHIR_PORT.md)
