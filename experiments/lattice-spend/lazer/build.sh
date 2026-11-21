#!/bin/sh
# Build a public, pinned, AVX-512 research artifact into a new local directory.
set -eu
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then echo "usage: build.sh NEW_DIRECTORY [--stock]" >&2; exit 2; fi
case "${2-}" in ""|--stock) ;; *) exit 2 ;; esac
mkdir "$1"
base=$(cd "$1" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
git clone -q https://github.com/lazer-crypto/lazer.git "$base/lazer"
cd "$base/lazer"
lazer_pin=b958e247a2fdb9593b3c25c9603c6c5305c19420
backend_pin=c1ae0e612d5accd9e7d9d1c264951c1afe949c83
if [ "${2-}" = "--stock" ]; then
    lazer_pin=51baa16c4a642ad90b964b9c1592c230aa0c0941
    backend_pin=18b6814bc81ebcdf1c6b7e033fe648d35005937d
fi
git checkout -q --detach "$lazer_pin"
git submodule update --init
test "$(git -C src/labrados rev-parse HEAD)" = "$backend_pin"
if [ "${2-}" = "--stock" ]; then
    echo stock > "$base/profile"
else
    printf '%s  %s\n' 93939b981d7b0dff72cdb3b123dabde98ab7abbeeda62eacffa961780c8c75e1 "$here/quadratic_hash.patch" | sha256sum -c -
    (cd src/labrados && patch -p1 < "$here/quadratic_hash.patch")
    echo canonical-quadratic-v1 > "$base/profile"
fi
python3 -m pip install --target "$base/pydeps" cffi==1.17.1 numpy==1.26.4 setuptools==75.8.0 pycparser==3.12
export PYTHONPATH="$base/pydeps"
# The bundled HEXL chooses lib or lib64 by platform; the upstream Makefile
# hardcodes lib64. Expose its actual build without editing upstream sources.
make third_party/hexl-development
hexl=third_party/hexl-development/build/hexl
if [ ! -e "$hexl/lib64" ] && [ -f "$hexl/lib/libhexl.a" ]; then ln -s lib "$hexl/lib64"; fi
# The original paper Makefile omits this prerequisite on libhexl_wrapper.so.
make src/hexl_shared.o
make -j2 liblazer.so libhexl_wrapper.so liblabrador38.so \
  LABRADOR_CFLAGS='-std=gnu2x -fwrapv -ffast-math -march=tigerlake -mtune=tigerlake -O3 -DNDEBUG -fvisibility=hidden'
make libhash.so CFLAGS='-O3 -march=tigerlake -mtune=tigerlake -DFALCON_FPNATIVE -DFALCON_AVX2 -DFALCON_FMA'
export LD_LIBRARY_PATH="$base/lazer${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
(cd python && make)
cc -std=gnu2x -O2 -DNDEBUG -DLOGQ=38 -fPIC -shared -Isrc/labrados \
    "$here/arrays.c" -o "$base/arrays.so"
