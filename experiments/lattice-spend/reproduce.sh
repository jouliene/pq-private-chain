#!/usr/bin/env bash
# Reconstruct both cost decisions and replay real public funding history.
set -euo pipefail
cd "$(dirname "$0")"
export OPENBLAS_NUM_THREADS=1
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
curl -fsSL https://static.crates.io/crates/qp-poseidon-core/qp-poseidon-core-3.1.0.crate -o "$work/poseidon.crate"
curl -fsSL https://github.com/jouliene/pq-private-chain/releases/download/funded-whir-2026-11-20/independent-public.tar.gz -o "$work/events.tgz"
(cd "$work" && sha256sum -c - <<'PINS'
5872607e25ea4ee5fb37e64bf1462168e1a36a4e719cdc8a105533c708253918  poseidon.crate
06c6e392a7896aa8670c365e3895e3d673f676e75919b143be36c823851d4673  events.tgz
PINS
tar -xzf poseidon.crate && tar -xzf events.tgz && sha256sum -c SHA256SUMS)
constants="$work/qp-poseidon-core-3.1.0/src/poseidon2.rs"
python3 -EB lazer/check_frame.py lazer/public
python3 -IB sis/screen.py | cmp - sis/SCREEN.json
python3 -IB sis/check_link.py
python3 -IB review/check.py | cmp - review/LLNW.json
python3 -IB funded/lift.py "$constants" | cmp - funded/SHAPES.json
python3 -IB review/memory.py | cmp - review/MEMORY.json
python3 -IB funded/costs.py | cmp - funded/COSTS.json
python3 -IB pivot/price.py "$constants" | cmp - pivot/PRICE.json
python3 -IB pivot/check.py "$constants" "$work/public" | cmp - pivot/CHECKS.json
python3 -IB review/history.py "$constants" "$work/public" | cmp - review/HISTORY.json
python3 -IB review/pivot_price.py | cmp - review/PIVOT.json
echo 'Verified SIS bounds, complete non-native relation shapes, costs, fixed-parent bounds and funded-branch replay.'
