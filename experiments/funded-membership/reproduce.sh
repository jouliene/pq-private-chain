#!/usr/bin/env bash
# Rebuild A/B/C, mine fresh A/B money and spend it with every prospective C path.
set -euo pipefail
umask 077
[[ $# == 1 ]] || { echo "Usage: $0 NEW_PRIVATE_RESULT_DIRECTORY" >&2; exit 2; }
mkdir -m 700 -- "$1"
out=$(cd -- "$1" && pwd -P)
here=$(cd -- "$(dirname -- "$0")" && pwd -P)
up="$here/../funded-upgrade"
network="$out/network"
export CARGO_HOME="$out/cargo" RAYON_NUM_THREADS=2
if ! rustup run 1.93.0 rustc --version >/dev/null 2>&1; then
    export RUSTUP_HOME="$out/rustup"
    rustup toolchain install 1.93.0 --profile minimal
fi
dist=node-v24.22.1-linux-x64
curl --fail --silent --show-error --location --retry 2 --proto '=https' --proto-redir '=https' \
    "https://nodejs.org/dist/v24.22.1/$dist.tar.xz" -o "$out/node.tar.xz"
(cd "$out" && echo '6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6  node.tar.xz' | sha256sum -c -)
tar -xJf "$out/node.tar.xz" -C "$out" "$dist/bin/node"
python3 -IB "$here/vectors.py"
python3 -IB "$here/profile.py" | cmp - "$here/PROFILE.json"
python3 -IB "$up/walkthrough.py" "$network" install
builds=("$network"/source-build-*/build)
[[ ${#builds[@]} == 1 && -d "${builds[0]}/upstream" ]]
build=${builds[0]}
stop_peers() {
    python3 -IB - "$network" <<'PY'
from pathlib import Path
import sys
home = Path(sys.argv[1])
sys.path.insert(0,str(home/"deployment/devnet"))
from cli import Lab
Lab(home,home/"deployment/runtime").stop()
PY
}
trap stop_peers EXIT
python3 -IB "$up/walkthrough.py" "$network" fund
python3 -IB "$up/build.py" "$out/b-build" "$build/upstream" "$build/target"
python3 -IB "$up/stage.py" "$network/deployment" "$out/b-build" "$network/deployment-next"
python3 -IB "$here/../archive-recovery/fund.py" "$network"
stop_peers
python3 -IB "$here/build_c.py" "$out/c-build" "$build/upstream" "$build/target"
python3 -IB "$here/stage.py" "$network/deployment" "$out/b-build" "$out/c-build" "$network/deployment-c"
mv "$network/deployment" "$network/deployment-b"
mv "$network/deployment-c" "$network/deployment"
python3 -IB "$here/scenario.py" "$network"
python3 -IB "$here/../user-assets/review/build_helpers.py" "$build/upstream" "$out/helpers"
public="$network/public/membership"
python3 -IB "$here/conformance.py" "$public" --miner-backups "$network/owner-backups" > "$out/conformance.json"
python3 -IB "$here/review/replay.py" "$public" "$network/deployment" "$out/helpers" "$out/$dist/bin/node" > "$out/replayed.json"
python3 -IB "$here/controls.py" "$public" "$network/deployment" > "$out/controls.json"
python3 -IB "$here/review/owners.py" "$public" "$network/deployment" "$network/owner-backups/offline" "$network/membership-negotiation/receiver.backup" > "$out/owners.json"
tip=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tips"]["final"]["tip"])' "$public/RUN.json")
python3 -IB "$here/costs.py" "$network/deployment" "$public/blocks" "$tip" --wallet-report "$public/RUN.json" > "$out/costs.json"
echo "Fresh funded membership and monetary replay passed. Private output: $out"
