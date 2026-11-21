#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=${1:?pass a new scratch directory}
mkdir -- "$work"
work=$(cd "$work" && pwd)
vole=255f1a995b8542de453efef57db7aa47a09f3a03
ichor=1e49bd0e6395523b3499d2deedae3f957e41d5c1
if [[ $# == 2 ]]; then
  cp -- "$2/voleith.tar.gz" "$2/ichor.tar.gz" "$work/"
else
  curl -fsSL "https://codeload.github.com/TalosLogic/libtalos_voleith/tar.gz/$vole" -o "$work/voleith.tar.gz"
  curl -fsSL "https://codeload.github.com/TalosLogic/libtalos_ichor/tar.gz/$ichor" -o "$work/ichor.tar.gz"
fi
cd "$work"
sha256sum --check "$here/SOURCES.sha256"
mkdir source
tar -xzf voleith.tar.gz --strip-components=1 -C source
tar -xzf ichor.tar.gz --strip-components=1 -C source/third_party/libtalos_ichor
s=$work/source
cmake -S "$s" -B build -DCMAKE_BUILD_TYPE=Release -DVOLEITH_BUILD_TESTS=OFF \
  -DVOLEITH_BUILD_EXAMPLES=OFF -DVOLEITH_LEGACY_VERIFY=OFF -DVOLEITH_THREADS=OFF
cmake --build build --target voleith_core -j1
cc -std=c17 -O2 -Wall -Wextra -Werror -I"$s/proof" -I"$s/core" \
  -I"$s/third_party/libtalos_ichor/include" "$here/leaf_component.c" \
  build/libtalos_voleith.a build/third_party/libtalos_ichor/libtalos_ichor.a \
  -pthread -lcrypto -o leaf
for profile in 256s 256f; do
  /usr/bin/time -f '%e real %U user %S sys %M KiB' -o "$profile-prove.time" \
    ./leaf "$profile" prove > "$profile.public"
  /usr/bin/time -f '%e real %U user %S sys %M KiB' -o "$profile-verify.time" \
    ./leaf "$profile" verify < "$profile.public" > "$profile-verify.txt"
  ./leaf "$profile" controls < "$profile.public" > "$profile-controls.txt"
  cat "$profile-prove.time" "$profile-verify.time" "$profile-verify.txt" "$profile-controls.txt"
done
python3 -IB "$here/price.py" ./leaf > sizes.json
cmp -- sizes.json "$here/SIZES.json"
