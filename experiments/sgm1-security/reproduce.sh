#!/usr/bin/env bash
# Build from this checkout. Scratch contains public test frames and disposable local test stores.
set -euo pipefail
if [[ $# -lt 1 || $# -gt 2 || ( $# == 2 && "$2" != published ) ]]; then
    echo 'usage: bash reproduce.sh NEW_SCRATCH_DIRECTORY [published]' >&2
    exit 2
fi
umask 077
here=$(cd -- "$(dirname -- "$0")" && pwd)
mkdir -- "$1"
work=$(cd -- "$1" && pwd)
export OPENBLAS_NUM_THREADS=1 PYTHONDONTWRITEBYTECODE=1
unset PYTHONPATH FS_RECEIPT_NODE SGM1_NATIVE_LIB SW_FIELD
python3 -Ic 'import sys,numpy; assert sys.version_info[:2] == (3,12) and numpy.__version__=="1.26.4"'
get() {
    curl --proto '=https' -fsSL --retry 2 "$1" -o "$work/$2"
    (cd "$work" && echo "$3  $2" | sha256sum -c -)
}
get https://nodejs.org/dist/v24.22.1/node-v24.22.1-linux-x64.tar.xz node.tar.xz 6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6
tar -xf "$work/node.tar.xz" -C "$work"
export FS_RECEIPT_NODE="$work/node-v24.22.1-linux-x64/bin/node"
bash "$here/../hidden-membership/smallwood/build-wide.sh" "$work/native"
bash "$here/../sgm1-admission/native/build.sh" "$work/native"
export SW_FIELD=gf256 PYTHONPATH="$work/native" SGM1_NATIVE_LIB="$work/native/libsgm1_verify.so"

get https://github.com/jouliene/pq-private-chain/releases/download/sgm1-two-core-2026-11-22/sgm1-public-100.tar.gz baseline.tgz eb9126b06ac3d84b628528bb622fb8b331d0f0d7a59548a2ea7473f096bbeb2b
tar -xf "$work/baseline.tgz" -C "$work" legacy public
python3 -B "$here/trace.py" "$work/legacy" 783d64bbbd924023a813dbe8b6c279013bd6d3dcdb2b0702466708ab48b6bac9 > "$work/SGM1_TRACE.json"
python3 -B "$here/observer.py" "$work/public" > "$work/OBSERVER.json"
python3 -B "$here/bounds.py" > "$work/BOUNDS.json"
for result in SGM1_TRACE OBSERVER BOUNDS; do cmp "$work/$result.json" "$here/evidence/$result.json"; done

if [[ ${2:-} == published ]]; then
    get https://github.com/jouliene/pq-private-chain/releases/download/sgm1-early-degree-2026-11-22/sgm1-ear1-public-20261122.tgz early.tgz 5f6bdc65105e3cdde4551b7cbd97f3f8c96f72a76ad434a6c1d85b627901ea80
    mkdir "$work/published"
    tar -xf "$work/early.tgz" -C "$work/published"
    python3 -B "$here/trace.py" "$work/published" 682a34abd047472df4caa7ac30452529a231f5d904ff544bb1ad743024379c11 --early > "$work/EAR1_TRACE.json"
    cmp "$work/EAR1_TRACE.json" "$here/evidence/EAR1_TRACE.json"
fi

python3 -B "$here/early_degree.py" cycle "$work/fresh" "$work/native" > "$work/fresh-payment.json"
python3 -B "$here/check_payment.py" "$work/fresh" > "$work/ear1-controls.json"
python3 -B "$here/wallet_checks.py" "$work/negative" negative > "$work/wallet-negative.json"
python3 -B "$here/wallet_checks.py" "$work/honest" honest --workers "${SGM1_PROVERS:-2}" > "$work/wallet-honest.json"
echo "Verified transcript, bounds, funded payment and both wallet endpoints. Results in $work"
