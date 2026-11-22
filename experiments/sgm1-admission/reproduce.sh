#!/usr/bin/env bash
set -euo pipefail
if [[ $# -lt 1 || $# -gt 3 ]]; then
    echo 'usage: reproduce.sh NEW_SCRATCH_DIRECTORY [capacity|walkthrough|ci|public EXISTING_PUBLIC_DIRECTORY]' >&2
    exit 2
fi
mode=${2:-capacity}
case "$mode" in
    capacity|public) waves=10 ;;
    walkthrough|ci) waves=2 ;;
    *) echo 'unknown reproduction mode' >&2; exit 2 ;;
esac
if [[ "$mode" == public ]]; then
    [[ $# == 3 && -d "$3/prefix" ]] || { echo 'public mode needs an extracted corpus' >&2; exit 2; }
    corpus=$(cd -- "$3" && pwd)
elif [[ $# == 3 ]]; then
    echo 'unexpected existing corpus' >&2
    exit 2
fi
umask 077
here=$(cd -- "$(dirname -- "$0")" && pwd)
mkdir -- "$1"
work=$(cd -- "$1" && pwd)
export OPENBLAS_NUM_THREADS=1 PYTHONDONTWRITEBYTECODE=1
unset SW_FIELD PYTHONPATH SGM1_NATIVE_LIB FS_RECEIPT_NODE
python3 -Ic 'import sys,numpy,psutil; assert sys.version_info[:2]==(3,12) and numpy.__version__=="1.26.4"'
curl --proto '=https' -fsSL --retry 2 https://nodejs.org/dist/v24.22.1/node-v24.22.1-linux-x64.tar.xz -o "$work/node.tar.xz"
(cd "$work" && echo '6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6  node.tar.xz' | sha256sum -c - && tar -xf node.tar.xz)
export FS_RECEIPT_NODE="$work/node-v24.22.1-linux-x64/bin/node"
bash "$here/../hidden-membership/smallwood/build-wide.sh" "$work/native"
bash "$here/native/build.sh" "$work/native"
export PYTHONPATH="$work/native" SW_FIELD=gf256 SGM1_NATIVE_LIB="$work/native/libsgm1_verify.so"
c++ -std=c++20 -O3 -Wall -Wextra -mpclmul -msse4.1 "$here/native/backend.cpp" "$here/native/backend_check.cpp" -lcrypto -o "$work/native/backend-check"
"$work/native/backend-check" "$here/../structured-keccak/ring/evidence/projection.proof"
python3 -B "$here/native/wiring_check.py"
if [[ "$mode" != public ]]; then
    corpus="$work/public"
    python3 -B "$here/generate.py" "$corpus" --waves "$waves" --workers "${SGM1_PROVERS:-3}"
fi
python3 -B "$here/controls.py" "$corpus" "$work/controls.sqlite" > "$work/controls.json"
cat "$work/controls.json"
if [[ "$mode" == capacity || "$mode" == public ]]; then
    python3 -B "$here/measure.py" "$corpus" "$work/loads" --catchup-passes 12
elif [[ "$mode" == walkthrough ]]; then
    python3 -B "$here/measure.py" "$corpus" "$work/loads" --modes 100M overload catchup
fi
if [[ -f "$work/loads/traces.json" ]]; then
    python3 -B "$here/report.py" "$work/loads/traces.json" > "$work/capacity.json"
    cat "$work/capacity.json"
fi
