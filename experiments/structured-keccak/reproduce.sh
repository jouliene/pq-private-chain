#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 ]]; then
    echo 'usage: bash experiments/structured-keccak/reproduce.sh NEW_SCRATCH_DIRECTORY' >&2
    exit 2
fi
umask 077
here=$(cd -- "$(dirname -- "$0")" && pwd)
mkdir -- "$1"
work=$(cd -- "$1" && pwd)
export OPENBLAS_NUM_THREADS=1 PYTHONDONTWRITEBYTECODE=1
unset SW_FIELD PYTHONPATH
python3 -Ic 'import sys,numpy; assert sys.version_info[:2]==(3,12) and numpy.__version__=="1.26.4"'
curl -fsSL https://nodejs.org/dist/v24.22.1/node-v24.22.1-linux-x64.tar.xz -o "$work/node.tar.xz"
(cd "$work" && echo '6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6  node.tar.xz' | sha256sum -c - && tar -xf node.tar.xz)
export FS_RECEIPT_NODE="$work/node-v24.22.1-linux-x64/bin/node"
bash "$here/../hidden-membership/smallwood/build-wide.sh" "$work/native"
export PYTHONPATH="$work/native" SW_FIELD=gf256
python3 -B "$here/ring/check.py" verify < "$here/ring/evidence/projection.proof"
python3 -B "$here/ring/check.py" record "$work/ring"
python3 -B "$here/gkr/role.py" verify "$here/evidence/link/public-root.bin" "$here/evidence/link/public.proof" --flatten 4
python3 -B "$here/gkr/kernel_checks.py"
python3 -B "$here/gkr/ragged.py"
python3 -B "$here/payment/check.py" > "$work/inventory.json"
cmp "$here/payment/inventory.json" "$work/inventory.json"
python3 -IB "$here/harness/run.py" "$work/two" "$work/native" 2 --flatten 4
python3 -IB "$here/harness/run.py" "$work/eight" "$work/native" 8 --flatten 4
python3 -IB "$here/funding/run.py" "$work/funded" "$work/native"
python3 -IB "$here/harness/payment_run.py" "$work/payment" "$work/native"
python3 -IB "$here/costs.py" > "$work/costs.json"
cmp "$here/COSTS.json" "$work/costs.json"
