#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 ]]; then
    echo 'usage: bash experiments/hidden-membership/reproduce.sh NEW_SCRATCH_DIRECTORY' >&2
    exit 2
fi
umask 077
here=$(cd -- "$(dirname -- "$0")" && pwd)
mkdir -- "$1"
work=$(cd -- "$1" && pwd)
export OPENBLAS_NUM_THREADS=1
export PYTHONDONTWRITEBYTECODE=1
unset SW_FIELD PYTHONPATH
python3 -Ic 'import sys,numpy; assert sys.version_info[:2]==(3,12) and numpy.__version__=="1.26.4"'
curl -fsSL https://nodejs.org/dist/v24.22.1/node-v24.22.1-linux-x64.tar.xz -o "$work/node.tar.xz"
(cd "$work" && echo '6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6  node.tar.xz' | sha256sum -c - && tar -xf node.tar.xz)
export FS_RECEIPT_NODE="$work/node-v24.22.1-linux-x64/bin/node"
bash "$here/../fresh-spend/proof/reproduce.sh" "$work/vole"
bash "$here/control/build.sh" "$work/vole" "$work/control"
python3 -IB "$here/control/run.py" "$work/control" "$work/linked-control" | tee "$work/control.json"
bash "$here/alternative/reproduce.sh" "$work/alternative" "$work/vole"
python3 -B "$here/smallwood/check.py"
python3 -B "$here/smallwood/role.py" verify "$here/smallwood/evidence/gf16.statement" "$here/smallwood/evidence/gf16.proof"
python3 -B "$here/smallwood/reproduce.py" "$work/linked-low"
bash "$here/smallwood/build-wide.sh" "$work/native"
PYTHONPATH="$work/native" SW_FIELD=gf256 python3 -B "$here/smallwood/check.py"
PYTHONPATH="$work/native" python3 -B "$here/smallwood/reproduce.py" --wide "$work/linked-wide"
PYTHONPATH="$work/native" python3 -B "$here/smallwood/mixed/check.py"
PYTHONPATH="$work/native" python3 -B "$here/smallwood/mixed/reproduce.py" "$work/linked-mixed"
python3 -IB "$here/smallwood/mixed/packed_parent.py" > "$work/packed.json"
cmp "$here/smallwood/mixed/packed-evidence.json" "$work/packed.json"
python3 -IB "$here/paths/test_funding_fixture.py"
python3 -IB "$here/paths/run.py" "$work/paths" gf16 | tee "$work/paths.json"
SW_NATIVE_DIR="$work/native" python3 -IB "$here/paths/run.py" "$work/paths-mixed" mixed | tee "$work/paths-mixed.json"
python3 -IB "$here/assurance/sensitivity.py"
python3 -IB "$here/costs.py" > "$work/costs.json"
cmp "$here/COSTS.json" "$work/costs.json"
