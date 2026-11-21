#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 ]]; then
    echo 'usage: bash experiments/fresh-spend/reproduce.sh NEW_SCRATCH_DIRECTORY' >&2
    exit 2
fi
here=$(cd -- "$(dirname -- "$0")" && pwd)
umask 077
mkdir -- "$1"
work=$(cd -- "$1" && pwd)
export TMPDIR="$work"
cd -- "$work"

curl -fsSL https://nodejs.org/dist/v24.22.1/node-v24.22.1-linux-x64.tar.xz -o node.tar.xz
echo '6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6  node.tar.xz' | sha256sum -c -
tar -xf node.tar.xz
export FS_RECEIPT_NODE="$work/node-v24.22.1-linux-x64/bin/node"
python3 -B "$here/binding/test_relation.py"
python3 -IB "$here/binding/lifetime.py"

bash "$here/proof/reproduce.sh" "$work/vole"
curl -fsSL https://codeload.github.com/microsoft/Picnic/tar.gz/192cc046744a04d884a99940f92cfe443fda6081 -o picnic.tar.gz
bash "$here/wallet/reproduce.sh" "$work/picnic.tar.gz"
python3 -IB "$here/wallet/price.py" > picnic-price.json
cmp picnic-price.json "$here/wallet/PRICE.json"
python3 -IB "$here/membership_cost.py"
