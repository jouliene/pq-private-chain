#!/usr/bin/env bash
# Build both funded eras and run the disaster drill with previously unused wallets.
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
get() { curl --fail --silent --show-error --location --retry 2 --proto '=https' --proto-redir '=https' "$1" -o "$2"; }
dist=node-v24.22.1-linux-x64
get "https://nodejs.org/dist/v24.22.1/$dist.tar.xz" "$out/node.tar.xz"
(cd "$out" && echo '6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6  node.tar.xz' | sha256sum -c -)
tar -xJf "$out/node.tar.xz" -C "$out" "$dist/bin/node"
python3 -IB "$up/walkthrough.py" "$network" install
source_builds=("$network"/source-build-*/build)
[[ ${#source_builds[@]} == 1 && -d "${source_builds[0]}/upstream" ]]
build=${source_builds[0]}
python3 -IB "$up/walkthrough.py" "$network" fund
python3 -IB "$up/build.py" "$out/b-build" "$build/upstream" "$build/target"
python3 -IB "$up/stage.py" "$network/deployment" "$out/b-build" "$network/deployment-next"
stop_originals() {
    python3 -IB - "$here/../../devnet" "$network" <<'PYTHON'
from pathlib import Path
import sys
sys.path.insert(0, str(Path(sys.argv[1]).resolve()))
from transport import control, rpc
for name in "abc":
    try:
        rpc(control(Path(sys.argv[2]), name), "stop")
    except (OSError, ValueError):
        pass
PYTHON
}
trap stop_originals EXIT
python3 -IB "$here/fund.py" "$network"
python3 -IB "$here/replicate.py" "$network" "$out/archives"
python3 -IB "$here/campaign.py" "$network" "$out/archives" "$out/experiment"
python3 -IB "$here/../user-assets/review/build_helpers.py" "$build/upstream" "$out/helpers"
bash "$here/check.sh" "$network" "$out/archives" "$out/experiment" "$out/helpers" "$out/$dist/bin/node"
get 'https://github.com/jouliene/pq-private-chain/releases/download/funded-upgrade-2026-11-21/funded-upgrade-public.tar.gz' "$out/funded-upgrade-public.tar.gz"
(cd "$out" && sha256sum -c "$up/RELEASE.sha256")
mkdir -m 700 "$out/previous-public"
tar -xzf "$out/funded-upgrade-public.tar.gz" -C "$out/previous-public"
python3 -IB "$here/node_checks.py" "$network/deployment" "$out/previous-public/public" > "$out/experiment/restart-controls.json"
echo "Fresh recovery and independent replay passed. The private result directory is $out"
