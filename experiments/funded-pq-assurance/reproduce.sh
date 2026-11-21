#!/usr/bin/env bash
# Reproduce the funded-profile C decision and public C-to-N7 verification.
set -euo pipefail
umask 077

if [[ $# != 1 ]]; then
    echo "Usage: $0 EMPTY_RESULT_DIRECTORY" >&2
    exit 2
fi

destination=$1
if [[ -e "$destination" ]]; then
    [[ -d "$destination" && -z "$(find "$destination" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
        echo "destination must be absent or empty" >&2
        exit 2
    }
else
    mkdir -m 700 -- "$destination"
fi

out=$(cd -- "$destination" && pwd -P)
here=$(cd -- "$(dirname -- "$0")" && pwd -P)
root=$(cd -- "$here/../.." && pwd -P)
export CARGO_HOME="${FUNDED_PQ_CARGO_HOME:-$out/cargo-home}"
export CARGO_TARGET_DIR="$out/target"
export RAYON_NUM_THREADS=2

if ! rustup run 1.93.0 rustc --version >/dev/null 2>&1; then
    export RUSTUP_HOME="$out/rustup"
    rustup toolchain install 1.93.0 --profile minimal
fi

python3 -IB "$here/binding/lifetime_security.py" --check "$here/binding/RESULTS.json"
python3 -IB -m unittest discover -s "$here/binding" -p 'test_*.py'
python3 -IB -m unittest discover -s "$here/binding/migration" -p 'test_*.py'
python3 -IB "$here/proof/check.py"
python3 -IB "$here/review/independent_check.py" --check "$here/review/INDEPENDENT.json"

membership_archive="$out/funded-membership-public.tar.gz"
if [[ -n "${FUNDED_PQ_MEMBERSHIP_ARCHIVE:-}" ]]; then
    cp -- "$FUNDED_PQ_MEMBERSHIP_ARCHIVE" "$membership_archive"
else
    curl --fail --silent --show-error --location --retry 2 \
        --proto '=https' --proto-redir '=https' \
        https://github.com/jouliene/pq-private-chain/releases/download/funded-membership-2026-11-21/funded-membership-public.tar.gz \
        -o "$membership_archive"
fi
(cd "$out" && sha256sum -c "$root/experiments/funded-membership/RELEASE.sha256")
mkdir -m 700 -- "$out/membership"
tar -xzf "$membership_archive" -C "$out/membership"
python3 -IB "$here/review/archive_audit.py" "$membership_archive" \
    --check "$here/review/ARCHIVE.json"
python3 -IB "$here/privacy/analyze.py" "$out/membership/public" \
    --archive "$membership_archive" --output "$out/privacy.json"
cmp "$out/privacy.json" "$here/privacy/RESULTS.json"

bridge_manifest="$here/binding/migration/bridge/Cargo.toml"
n7_manifest="$root/experiments/advancing-note/proof/Cargo.toml"
rustup run 1.93.0 cargo test --locked --release -j2 --manifest-path "$bridge_manifest"
rustup run 1.93.0 cargo build --locked --release -j2 --manifest-path "$bridge_manifest"
rustup run 1.93.0 cargo test --locked --release -j2 --manifest-path "$n7_manifest"
rustup run 1.93.0 cargo build --locked --release -j2 --manifest-path "$n7_manifest"
bridge="$CARGO_TARGET_DIR/release/c2n7-bridge"
n7="$CARGO_TARGET_DIR/release/n7p2"
"$bridge" generate-vk "$out/bridge.vk" >/dev/null
"$n7" generate-vk "$out/n7.vk" >/dev/null
cmp "$out/bridge.vk" "$here/binding/migration/bridge/registered.vk"
cmp "$out/n7.vk" "$root/experiments/advancing-note/proof/registered.vk"

python3 -IB "$here/binding/migration/verify_public.py" \
    "$here/binding/migration/evidence-author05" --bridge "$bridge" --n7 "$n7" \
    > "$out/public-core.json"
cmp "$out/public-core.json" "$here/binding/migration/PUBLIC_VERIFY_CORE.json"

migration_archive="$out/funded-pq-assurance-migration-public.tar.gz"
if [[ -n "${FUNDED_PQ_MIGRATION_ARCHIVE:-}" ]]; then
    cp -- "$FUNDED_PQ_MIGRATION_ARCHIVE" "$migration_archive"
else
    curl --fail --silent --show-error --location --retry 2 \
        --proto '=https' --proto-redir '=https' \
        https://github.com/jouliene/pq-private-chain/releases/download/funded-pq-assurance-2026-11-21/funded-pq-assurance-migration-public.tar.gz \
        -o "$migration_archive"
fi
(cd "$out" && sha256sum -c "$here/MIGRATION_PUBLIC.sha256")
mkdir -m 700 -- "$out/migration"
tar -xzf "$migration_archive" -C "$out/migration"

c_archive="$out/funded-pq-assurance-c-deployment.tar.gz"
if [[ -n "${FUNDED_PQ_C_DEPLOYMENT_ARCHIVE:-}" ]]; then
    cp -- "$FUNDED_PQ_C_DEPLOYMENT_ARCHIVE" "$c_archive"
else
    curl --fail --silent --show-error --location --retry 2 \
        --proto '=https' --proto-redir '=https' \
        https://github.com/jouliene/pq-private-chain/releases/download/funded-pq-assurance-2026-11-21/funded-pq-assurance-c-deployment.tar.gz \
        -o "$c_archive"
fi
(cd "$out" && sha256sum -c "$here/C_DEPLOYMENT.sha256")
mkdir -m 700 -- "$out/c-review"
tar -xzf "$c_archive" -C "$out/c-review"
python3 -IB "$here/review/migration_public_audit.py" \
    "$here/binding/migration/evidence-author05" \
    --archive "$out/migration/membership" \
    --membership-archive "$migration_archive" \
    --c-deployment "$out/c-review/deployment" \
    --c-deployment-archive "$c_archive" \
    --bridge-binary "$bridge" --n7-binary "$n7" \
    --bridge-vk "$here/binding/migration/bridge/registered.vk" \
    --n7-vk "$root/experiments/advancing-note/proof/registered.vk" \
    --check "$here/review/MIGRATION_PUBLIC.json"

echo "Funded profile C calculations and public migration evidence matched."
