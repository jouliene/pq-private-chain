#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=${1:?pass a new scratch directory}
vole=${2:?pass the pinned shared VOLE source/build directory}
vole=$(cd "$vole" && pwd)
mkdir -- "$work"
work=$(cd "$work" && pwd)
src="$vole/source"
build="$vole/build"
compile() {
    cc -std=c17 -O2 -Wall -Wextra -Werror \
        -I"$src/proof" -I"$src/core" -I"$src/third_party/libtalos_ichor/include" \
        "$1" "$build/libtalos_voleith.a" "$build/third_party/libtalos_ichor/libtalos_ichor.a" \
        -pthread -lcrypto -o "$2"
}
compile "$here/lookup.c" "$work/lookup"
test -x "$vole/leaf"
python3 -IB "$here/price.py" --size-api "$vole/leaf" > "$work/prices.json"
cmp "$work/prices.json" "$here/PRICES.json"
python3 -IB "$here/updates.py"
python3 -IB "$here/exercise.py" "$work/lookup" "$work/public" | tee "$work/component.json"
