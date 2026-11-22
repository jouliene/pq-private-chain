#!/usr/bin/env bash
set -eu
if [ "$#" -ne 1 ]; then
    echo 'usage: build.sh OUTPUT_DIRECTORY' >&2
    exit 2
fi
if ! grep -qw pclmulqdq /proc/cpuinfo || ! grep -qw sse4_1 /proc/cpuinfo; then
    echo 'Native verifier requires PCLMULQDQ and SSE4.1' >&2
    exit 2
fi
mkdir -p "$1"
src=$(cd "$(dirname "$0")" && pwd)
c++ -std=c++20 -O3 -fPIC -mpclmul -msse4.1 -Wall -Wextra \
    -shared "$src/wiring.cpp" "$src/upper.cpp" "$src/backend.cpp" -lcrypto -o "$1/libsgm1_verify.so"
c++ -std=c++20 -O3 -Wall -Wextra "$src/main.cpp" -L"$1" -lsgm1_verify \
    '-Wl,-rpath,$ORIGIN' -o "$1/sgm1-verify"
