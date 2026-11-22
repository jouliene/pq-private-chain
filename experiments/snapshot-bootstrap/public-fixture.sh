#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $# -eq 1 ]] || { echo 'usage: public-fixture.sh NEW_DIRECTORY' >&2; exit 2; }
mkdir -- "$1"
out=$(cd -- "$1" && pwd -P)
here=$(cd -- "$(dirname -- "$0")" && pwd -P)
base=https://github.com/jouliene/pq-private-chain/releases/download
curl -fsSL --retry 2 "$base/snapshot-bootstrap-c-v1/snapshot-c-public.tar.gz" -o "$out/snapshot-c-public.tar.gz"
python3 -IB "$here/fixture.py" unpack "$out/snapshot-c-public.tar.gz" "$here/FIXTURE.json" "$out/fixture"
curl -fsSL --retry 2 "$base/funded-pq-assurance-2026-11-21/funded-pq-assurance-c-deployment.tar.gz" -o "$out/c.tgz"
(cd "$out" && echo '682ed92c510c0b73ddf21ed7c50c048c4430bb8b06c5e6fc28db1e63e8c5d942  c.tgz' | sha256sum -c -)
mkdir "$out/source"
tar -xf "$out/c.tgz" -C "$out/source"
export RAYON_NUM_THREADS=2
python3 -IB "$here/fixed.py" "$out"
