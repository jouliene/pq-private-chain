#!/usr/bin/env bash
# Project-local Noble userland; no host policy changes or private fixture inputs.
set -euo pipefail
mode=${1:?Usage: ci_noble.sh prepare | run COMMAND...}
shift
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
rootfs=$repo/.tools/noble
record=$repo/.work/ci-noble
base=ubuntu-base-24.04.5-base-amd64.tar.gz
url=https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/$base
base_sha=e77b6f10c2590cef872b33ee9f635a0e3fd1f57fb074c0e52b5c7f56147a0c86
archive=$repo/.tools/$base
rustup_home=$(realpath -e -- "${RUSTUP_HOME:-$HOME/.rustup}")
cargo_bin=$(realpath -e -- "${CARGO_HOME:-$HOME/.cargo}/bin")
guest_home=$(realpath -e -- "$HOME")
node=$repo/.tools/node-v24.22.1-linux-x64/bin/node
for path in "$repo/.tools" "$repo/.work" "$rootfs" "$record"; do
    [[ ! -L $path ]]
    if [[ -e $path ]]; then
        [[ -d $path && $(realpath -e -- "$path") == "$path" ]]
    fi
done
for path in READY base.json dpkg-inventory.tsv dpkg-inventory.sha256; do
    [[ ! -L $record/$path ]]
done
[[ -x $cargo_bin/cargo && -x $cargo_bin/rustup && -x $node ]]

guest() {
    local access=$1
    shift
    local args=(--die-with-parent --new-session --unshare-user --uid 0 --gid 0
                --unshare-pid --unshare-ipc --unshare-uts)
    if [[ $access == prepare ]]; then
        args+=(--bind "$rootfs" /)
    else
        args+=(--ro-bind "$rootfs" / --unshare-net)
    fi
    args+=(--bind "$repo" "$repo"
           --ro-bind "$rustup_home" "$rustup_home" --ro-bind "$cargo_bin" "$cargo_bin"
           --proc /proc --dev /dev --tmpfs /tmp
           --tmpfs "$rootfs" --remount-ro "$rootfs")
    if [[ $access == prepare ]]; then
        args+=(--ro-bind "$(realpath -e /etc/resolv.conf)" /etc/resolv.conf)
    fi
    # No host environment/credentials or host /usr/lib directories are imported.
    /usr/bin/bwrap "${args[@]}" --chdir "$repo" --clearenv \
        --setenv HOME "$guest_home" --setenv RUSTUP_HOME "$rustup_home" \
        --setenv PATH "$cargo_bin:/usr/bin:/bin" --setenv LANG C.UTF-8 \
        --setenv LC_ALL C.UTF-8 --setenv TZ UTC --setenv DEBIAN_FRONTEND noninteractive \
        -- "$@"
}

case "$mode" in
prepare)
    [[ $# == 0 && ! -e $rootfs && ! -L $rootfs && ! -e $record && ! -L $record
       && ! -e $archive && ! -L $archive ]]
    mkdir -p -- "$repo/.tools" "$repo/.work"
    mkdir -- "$record" "$rootfs"
    curl --fail --location --silent --show-error --output "$archive" "$url"
    printf '%s  %s\n' "$base_sha" "$archive" | sha256sum --check -
    tar --extract --gzip --file "$archive" --directory "$rootfs" \
        --no-same-owner --no-same-permissions
    # Create only fresh-image mountpoints; preserve the image's merged-/usr links.
    mkdir -p -- "$rootfs$repo" "$rootfs$rustup_home" "$rootfs$cargo_bin" "$rootfs$guest_home"
    rm -f -- "$rootfs/etc/resolv.conf"
    : > "$rootfs/etc/resolv.conf"
    python3 -I - "$url" "$base_sha" "$rootfs" "$record" "${BASH_SOURCE[0]}" <<'PY'
import hashlib, json, pathlib, sys
url, digest, root, record, script = sys.argv[1:]
value = {'format': 'CP04-CI-NOBLE-BASE01', 'url': url, 'archive_sha256': digest,
         'rootfs': root, 'host_policy_changed': False,
         'single_uid_default_apt_sandbox': True,
         'wrapper_sha256': hashlib.sha256(pathlib.Path(script).read_bytes()).hexdigest()}
with (pathlib.Path(record) / 'base.json').open('x') as output:
    json.dump(value, output, indent=2, sort_keys=True)
    output.write('\n')
PY
    # Default signed apt verification, sandbox and dpkg behavior. Any failure stops.
    guest prepare /bin/sh -ceu '
        apt-get update
        apt-get install -y --no-install-recommends build-essential libssl-dev python3 \
            bubblewrap curl xz-utils ripgrep ca-certificates
    ' > "$record/provision-public.log" 2>&1
    guest run /usr/bin/dpkg-query -W '-f=${binary:Package}\t${Version}\t${Architecture}\n' \
        > "$record/dpkg-inventory.tsv"
    sha256sum "$record/dpkg-inventory.tsv" > "$record/dpkg-inventory.sha256"
    guest run /usr/bin/python3 -I - > "$record/userland-identity.json" <<'PY'
import ctypes, json, re, subprocess, sys
assert sys.version_info >= (3, 11), 'Python3.11 or later required'
version = subprocess.check_output(['/usr/bin/openssl', 'version'], timeout=5).decode().strip()
assert re.match(r'^OpenSSL 3\.0\.13(?: |$)', version), 'OpenSSL3.0.13 required'
crypto = ctypes.CDLL('/usr/lib/x86_64-linux-gnu/libcrypto.so.3')
actual = tuple(getattr(crypto, 'OPENSSL_version_' + name)() for name in ('major', 'minor', 'patch'))
assert actual == (3, 0, 13), 'Actual libcrypto3.0.13 required'
print(json.dumps({'python': sys.version, 'openssl': version, 'libcrypto_version': actual}, sort_keys=True))
PY
    # This is public only. No compiler or wallet/private actor is executed here.
    guest run /usr/bin/python3 -I -B \
        "$repo/experiments/network-feasibility/wallet-integration/ci_preflight.py" \
        --node "$node" --output "$record/public-preflight.json"
    : > "$record/READY"
    ;;
run)
    [[ $# -gt 0 && -f $record/READY && -f $record/base.json && -d $rootfs ]]
    # Record integrity only; fresh discovery/approval still binds actual runtime.
    sha256sum --check "$record/dpkg-inventory.sha256"
    guest run "$@"
    ;;
*)
    printf '%s\n' 'Usage: ci_noble.sh prepare | run COMMAND...' >&2
    exit 2
    ;;
esac
