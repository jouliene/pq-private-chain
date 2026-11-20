#!/usr/bin/env bash
# Reproduce the decision from public inputs. Temporary data contains public records only.
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONDONTWRITEBYTECODE=1
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
curl -fsSL https://static.crates.io/crates/qp-poseidon-core/qp-poseidon-core-3.1.0.crate -o "$work/poseidon.crate"
curl -fsSL https://github.com/jouliene/pq-private-chain/releases/download/funded-whir-2026-11-20/independent-public.tar.gz -o "$work/events.tgz"
(cd "$work" && sha256sum -c - <<'PINS'
5872607e25ea4ee5fb37e64bf1462168e1a36a4e719cdc8a105533c708253918  poseidon.crate
06c6e392a7896aa8670c365e3895e3d673f676e75919b143be36c823851d4673  events.tgz
PINS
tar -xzf events.tgz && tar -xzf poseidon.crate && sha256sum -c SHA256SUMS)
constants="$work/qp-poseidon-core-3.1.0/src/poseidon2.rs"
python3 -IB encoding/encoding.py "$constants" | cmp - encoding/CENSUS.json
python3 -IB encoding/check.py "$constants" --events "$work/public" | cmp - encoding/PUBLIC.json
python3 -B ../amplified-spend/traffic.py "$work/events.tgz" | cmp - ../amplified-spend/TRAFFIC.json
python3 -B model/calibrate.py | cmp - model/CALIBRATION.json
python3 -B model/certify.py | cmp - model/CERTIFICATE.json
python3 -B model/miniature.py
python3 -B review/audit.py | cmp - review/AUDIT.json
python3 -B resources/network.py | cmp - resources/NETWORK.json
python3 -B resources/measure.py --check
echo 'Public funded paths, wire bounds, network costs and full-size commitment component reproduced.'
