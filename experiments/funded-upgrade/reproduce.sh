#!/usr/bin/env bash
# Fresh wallets, both releases of the proving roles, and independent public replay.
set -euo pipefail
umask 077
[[ $# == 1 ]] || { echo "Usage: $0 NEW_RESULT_DIRECTORY" >&2; exit 2; }
mkdir -m 700 -- "$1"
out=$(cd -- "$1" && pwd -P)
here=$(cd -- "$(dirname -- "$0")" && pwd -P)
network="$out/network"
export CARGO_HOME="$out/cargo" RAYON_NUM_THREADS=2
if ! rustup run 1.93.0 rustc --version >/dev/null 2>&1; then
    export RUSTUP_HOME="$out/rustup"
    rustup toolchain install 1.93.0 --profile minimal
fi
fetch() { curl --fail --show-error --silent --location --retry 2 --proto '=https' --proto-redir '=https' "$1" -o "$2"; }
tag_url=https://github.com/jouliene/pq-private-chain/releases/download
fetch "$tag_url/private-atomic-swap-2026-11-20/SWP1-author-public.tar.gz" "$out/old.tar.gz"
(cd "$out" && echo '1ce5693671acbccdcd6ecf7d1d17bf9a153dbde590e0c812762e81612ac2db72  old.tar.gz' | sha256sum -c -)
dist=node-v24.22.1-linux-x64
fetch "https://nodejs.org/dist/v24.22.1/$dist.tar.xz" "$out/node.tar.xz"
(cd "$out" && echo '6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6  node.tar.xz' | sha256sum -c -)
tar -xJf "$out/node.tar.xz" -C "$out" "$dist/bin/node"
node="$out/$dist/bin/node"
python3 -IB "$here/profile.py" | cmp - "$here/PROFILE.json"
python3 -IB "$here/walkthrough.py" "$network" install
source_builds=("$network"/source-build-*/build)
[[ ${#source_builds[@]} == 1 && -d "${source_builds[0]}/upstream" ]]
build=${source_builds[0]}
python3 -IB "$here/walkthrough.py" "$network" fund
python3 -IB "$here/build.py" "$out/b-build" "$build/upstream" "$build/target"
python3 -IB "$here/stage.py" "$network/deployment" "$out/b-build" "$network/deployment-next"
python3 -IB "$here/walkthrough.py" "$network" activate
python3 -IB "$here/early.py" "$network"
python3 -IB "$here/review/recovery.py" "$network" > "$out/fresh-owner-checks.json"
python3 -IB "$here/boundary.py" "$network/deployment-a" "$network/deployment" "$network/public" > "$out/fresh-boundary.json"
python3 -IB "$here/../user-assets/review/build_helpers.py" "$build/upstream" "$out/helpers"
python3 -IB "$here/review/public.py" "$network/public" "$network/deployment" "$out/helpers" "$node" --disclosures "$network/public/RUN.json" > "$out/fresh-public.json"
python3 -IB "$here/probe.py" "$network/deployment" "$network/public" "$out/old.tar.gz" > "$out/fresh-costs.json"
fetch "$tag_url/funded-upgrade-2026-11-21/funded-upgrade-public.tar.gz" "$out/funded-upgrade-public.tar.gz"
(cd "$out" && sha256sum -c "$here/RELEASE.sha256")
mkdir "$out/capture"
tar -xzf "$out/funded-upgrade-public.tar.gz" -C "$out/capture"
python3 -IB "$here/review/public.py" "$out/capture/public" "$network/deployment" "$out/helpers" "$node" > "$out/released-public.json"
cmp "$out/released-public.json" "$here/PUBLIC.json"
python3 -IB "$here/boundary.py" "$network/deployment-a" "$network/deployment" "$out/capture/public" > "$out/released-boundary.json"
echo "Verified the published PoW history and a newly funded migration. See $out/fresh-public.json and $out/fresh-costs.json."
