#!/usr/bin/env bash
# Run in a new private directory. Cache overrides select checksum-verified public inputs only.
set -euo pipefail
umask 077
[[ $# == 1 ]] || { echo 'usage: bash reproduce.sh NEW_DIRECTORY' >&2; exit 2; }
mkdir -m 700 -- "$1"
out=$(cd -- "$1" && pwd -P)
here=$(cd -- "$(dirname -- "$0")" && pwd -P)
get() {
    local url=$1 file=$2 digest=$3 cache=$4
    if [[ -n "$cache" ]]; then
        cp -- "$cache" "$out/$file"
    else
        curl --proto '=https' --proto-redir '=https' -fsSL --retry 2 "$url" -o "$out/$file"
    fi
    (cd "$out" && echo "$digest  $file" | sha256sum -c -)
}
bwrap --unshare-all --die-with-parent --new-session --cap-drop ALL --ro-bind / / -- /bin/true
base=https://github.com/jouliene/pq-private-chain/releases/download
get "$base/funded-membership-2026-11-21/funded-membership-public.tar.gz" blocks.tgz 24fc62066d1c43b46e33152d83ee642b4d077aed7d9030ce3ffa2b31b5ceea87 "${PARTIAL_PUBLIC_HISTORY:-}"
get "$base/funded-pq-assurance-2026-11-21/funded-pq-assurance-c-deployment.tar.gz" c.tgz 682ed92c510c0b73ddf21ed7c50c048c4430bb8b06c5e6fc28db1e63e8c5d942 "${PARTIAL_PUBLIC_DEPLOYMENT:-}"
get 'https://nodejs.org/dist/v24.22.1/node-v24.22.1-linux-x64.tar.xz' node.tar.xz 6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6 "${PARTIAL_PUBLIC_NODE:-}"
mkdir "$out/network" "$out/history"
tar -xf "$out/blocks.tgz" -C "$out/history" public/blocks
tar -xf "$out/c.tgz" -C "$out/network"
tar -xf "$out/node.tar.xz" -C "$out" node-v24.22.1-linux-x64/bin/node
export STRANGER_NODE="$out/node-v24.22.1-linux-x64/bin/node" RAYON_NUM_THREADS=2
python3 -IB "$here/link.py" --self-test
python3 -IB "$here/../stranger-swap/partial_state_check.py" "$out/network/deployment"
python3 -IB "$here/../stranger-swap/partial_wallet_check.py"
python3 -IB "$here/prepare.py" "$out/network" "$out/history/public"
python3 -IB "$here/walkthrough.py" "$out/network" "$out/result.json"
python3 -IB "$here/review/verify.py" "$out"
