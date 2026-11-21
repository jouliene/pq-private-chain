#!/usr/bin/env bash
# Rebuild the registered public verifier and replay the exact funded PoW fixture.
set -euo pipefail
umask 077
here=$(cd "$(dirname "$0")" && pwd)
work=${1:-$(mktemp -d)}
deployment=
if [[ $# -ge 2 ]]; then deployment=$(realpath -e "$2"); fi
export OPENBLAS_NUM_THREADS=1
mkdir -p "$work"
work=$(cd "$work" && pwd)
cd "$work"
curl -fsSL --retry 2 https://static.crates.io/crates/qp-poseidon-core/qp-poseidon-core-3.1.0.crate -o poseidon.crate
curl -fsSL --retry 2 https://github.com/jouliene/pq-private-chain/releases/download/funded-tcith-2026-11-21/funding.tar.gz -o funding.tar.gz
sha256sum -c "$here/RELEASE.sha256"
tar -xzf poseidon.crate
tar -xzf funding.tar.gz
python3 -IB "$here/review/readback.py" "$work/public" | cmp - "$here/review/WIRE.json"
constants="$work/qp-poseidon-core-3.1.0/src/poseidon2.rs"
c++ -std=c++17 -O3 -Wall -Wextra -Werror "$here/proof/engine.cpp" -lcrypto -o "$work/tcith"
python3 -IB "$here/proof/register.py" "$constants" "$work/shape"
python3 -IB "$here/security/price.py" | cmp - "$here/security/PRICE.json"
python3 -IB "$here/security/wider.py" "$constants" | cmp - "$here/security/WIDER.json"
if [[ -z "$deployment" ]]; then
  python3 -IB "$here/node/bootstrap.py" "$work/reference"
  deployment="$work/reference/deployment"
fi
python3 -IB "$here/node/run.py" "$deployment" "$work/public" "$constants" "$work/tcith" "$work/shape" | tee "$work/node.json"
python3 -IB "$here/node/compare.py" "$here/NODE.json" "$work/node.json"
