#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=${1:?expected an existing pinned VOLE build}
out=${2:?expected an output executable}
src="$work/source"
cc -std=c17 -O2 -Wall -Wextra -Werror -I"$src/proof" -I"$src/core" \
   -I"$src/third_party/libtalos_ichor/include" "$here/linked.c" \
   "$work/build/libtalos_voleith.a" "$work/build/third_party/libtalos_ichor/libtalos_ichor.a" \
   -pthread -lcrypto -o "$out"
