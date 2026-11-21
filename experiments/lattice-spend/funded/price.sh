#!/usr/bin/env bash
# Price both complete layouts using the pinned backend's parameter generator.
set -eu
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: price.sh TOOLKIT_BUILD [SDE64]" >&2
  exit 2
fi
src=$(cd "$(dirname "$0")" && pwd)
build=$(cd "$1/lazer" && pwd)
test "$(git -C "$build/src/labrados" rev-parse HEAD)" = c1ae0e612d5accd9e7d9d1c264951c1afe949c83
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
cc -std=gnu2x -O2 -DNDEBUG -DLOGQ=38 -I"$build/src/labrados" "$src/price.c" \
    -L"$build" -Wl,-rpath,"$build" -llabrador38 -lm -o "$tmp/price"
runner=()
if [ "$#" -eq 2 ]; then runner=("$2" -tgl --); fi
for suite in MNG1 SLG1; do
    read -r vectors products < <(python3 - "$src/SHAPES.json" "$suite" <<'PY'
import json
import sys
with open(sys.argv[1]) as stream:
    shape = json.load(stream)[sys.argv[2]]
print(shape["binary_polynomials"], shape["private_quadratic_rows"])
PY
)
    echo "$suite"
    "${runner[@]}" "$tmp/price" "$vectors" "$products" > "$tmp/log"
    grep -E '^(Estimated proof size|field_arrays_B)' "$tmp/log"
done
