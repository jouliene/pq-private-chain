#!/usr/bin/env bash
set -eu
if [ "$#" != 1 ]; then
    echo "usage: build-wide.sh PRIVATE_BUILD_DIRECTORY" >&2
    exit 2
fi
case "$(uname -m)" in
    x86_64) ;;
    *) echo "This calibration extension requires x86_64." >&2; exit 2 ;;
esac
if ! grep -qw pclmulqdq /proc/cpuinfo || ! grep -qw sse4_1 /proc/cpuinfo; then
    echo "Missing PCLMULQDQ or SSE4.1." >&2
    exit 2
fi
if ! python3 -c 'import sys; sys.exit(sys.version_info[:2] != (3,12))'; then
    echo "The extension uses the CPython 3.12 long-integer API." >&2
    exit 2
fi
mkdir -p "$1"
cc -O3 -Wall -shared -fPIC -mpclmul -msse4.1 $(python3-config --includes) \
    "$(dirname "$0")/wide_field.c" -o "$1/sw_wide.so"
