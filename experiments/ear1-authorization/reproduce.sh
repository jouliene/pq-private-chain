#!/usr/bin/env bash
# Public inputs only. Fresh test-owned funding and openings stay inside the decoder.
set -euo pipefail
if [[ $# != 1 ]]; then
    echo 'usage: bash reproduce.sh NEW_DIRECTORY' >&2
    exit 2
fi
umask 077
here=$(cd -- "$(dirname -- "$0")" && pwd)
mkdir -- "$1"
work=$(cd -- "$1" && pwd)
export OPENBLAS_NUM_THREADS=1 PYTHONDONTWRITEBYTECODE=1
unset PYTHONPATH FS_RECEIPT_NODE SGM1_NATIVE_LIB SW_FIELD
python3 -Ic 'import sys,numpy; assert sys.version_info[:2]==(3,12) and numpy.__version__=="1.26.4"'
get() {
    curl --proto '=https' -fsSL --retry 2 "$1" -o "$work/$2"
    (cd "$work" && echo "$3  $2" | sha256sum -c -)
}
get https://nodejs.org/dist/v24.22.1/node-v24.22.1-linux-x64.tar.xz node.tar.xz 6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6
get https://github.com/jouliene/pq-private-chain/releases/download/sgm1-early-degree-2026-11-22/sgm1-ear1-public-20261122.tgz early.tgz 5f6bdc65105e3cdde4551b7cbd97f3f8c96f72a76ad434a6c1d85b627901ea80
tar -xf "$work/node.tar.xz" -C "$work"
mkdir "$work/ear1"
tar -xf "$work/early.tgz" -C "$work/ear1"
bash "$here/../hidden-membership/smallwood/build-wide.sh" "$work/native"
export FS_RECEIPT_NODE="$work/node-v24.22.1-linux-x64/bin/node" SW_FIELD=gf256 PYTHONPATH="$work/native"
python3 -B "$here/../sgm1-security/trace.py" "$work/ear1" 682a34abd047472df4caa7ac30452529a231f5d904ff544bb1ad743024379c11 --early --events > "$work/events.json"
python3 -B "$here/alternative.py" --events "$work/events.json" > "$work/costs.json"
python3 -B "$here/loss.py" > "$work/loss.json"
python3 -B "$here/decode_probe.py" > "$work/decoder.json"
python3 -B "$here/transport.py" make "$work/public-transport.bin"
python3 -B "$here/transport.py" check "$work/public-transport.bin" > "$work/transport.json"
for name in costs loss decoder transport; do
    cmp "$here/$name.json" "$work/$name.json"
done
echo "Verified the released EAR1 packet, fresh conditional funded decoding, extraction arithmetic and the EC01 public transport. Results in $work."
