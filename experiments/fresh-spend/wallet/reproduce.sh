#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -ne 1 ]; then
    echo 'usage: bash reproduce.sh PINNED_MICROSOFT_PICNIC_ARCHIVE' >&2
    exit 2
fi
here=$(cd -- "$(dirname -- "$0")" && pwd)
archive=$(realpath -- "$1")
pin=368d3f2e85eff045a08214da25928f79a47bbf6a1e3bd027a7fec5f1aa1f0fc0
printf '%s  %s\n' "$pin" "$archive" | sha256sum -c -
scratch=$(mktemp -d "${TMPDIR:-/tmp}/fresh-picnic-ur.XXXXXXXX")
echo "Evidence directory $scratch"
tar -xzf "$archive" --strip-components=1 -C "$scratch"
cd -- "$scratch"
make -j1 libshake.a >build.log 2>&1
make -j1 libpicnic.a kats_test \
    CFLAGS='-O2 -march=native -Wall -Wextra -Wpedantic -Werror -Wshadow -Wno-error=stringop-overflow -std=gnu99 -D__LINUX__ -D__X64__ -I./sha3' \
    >>build.log 2>&1
gcc -O2 -march=native -Wall -Wextra -Wpedantic -Werror -std=gnu99 -I. \
    "$here/picnic_ur_probe.c" libpicnic.a sha3/libshake.a -o picnic_ur_probe
env -u HOME /usr/bin/time -f 'sign_peak_kib %M\nsign_wall_s %e' \
    ./picnic_ur_probe sign probe.public 2>&1 | tee sign.log
env -u HOME /usr/bin/time -f 'verify_peak_kib %M\nverify_wall_s %e' \
    ./picnic_ur_probe verify probe.public 2>&1 | tee verify.log
./kats_test >kats.log 2>&1
echo 'upstream_kats passed'

gcc -O3 -Wall -Wextra "$here/../../new-note/sha3/calibrate.c" -lcrypto -o keccak_component
for trial in 1 2 3; do
    ./keccak_component | tee "keccak-$trial.log"
    python3 -IB "$here/measure_shake.py" | tee "shake-$trial.log"
done
