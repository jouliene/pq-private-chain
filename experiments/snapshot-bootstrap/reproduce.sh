#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $# -eq 1 ]] || { echo 'usage: bash reproduce.sh NEW_DIRECTORY' >&2; exit 2; }
mkdir -m 700 -- "$1"
out=$(cd -- "$1" && pwd -P)
here=$(cd -- "$(dirname -- "$0")" && pwd -P)
get() {
    local url=$1 file=$2 digest=$3 cache=$4
    if [[ -n "$cache" ]]; then cp -- "$cache" "$out/$file"
    else curl --proto '=https' --proto-redir '=https' -fsSL --retry 2 "$url" -o "$out/$file"; fi
    (cd "$out" && echo "$digest  $file" | sha256sum -c -)
}
bwrap --unshare-all --die-with-parent --new-session --cap-drop ALL --ro-bind / / -- /bin/true
base=https://github.com/jouliene/pq-private-chain/releases/download
get "$base/funded-membership-2026-11-21/funded-membership-public.tar.gz" blocks.tgz 24fc62066d1c43b46e33152d83ee642b4d077aed7d9030ce3ffa2b31b5ceea87 "${SNAP_PUBLIC_HISTORY:-}"
get "$base/funded-pq-assurance-2026-11-21/funded-pq-assurance-c-deployment.tar.gz" c.tgz 682ed92c510c0b73ddf21ed7c50c048c4430bb8b06c5e6fc28db1e63e8c5d942 "${SNAP_PUBLIC_DEPLOYMENT:-}"
mkdir "$out/source" "$out/history"
tar -xf "$out/blocks.tgz" -C "$out/history" public/blocks
tar -xf "$out/c.tgz" -C "$out/source"
export RAYON_NUM_THREADS=2
python3 -IB "$here/funding.py" "$out"
python3 -IB "$here/campaign.py" "$out"
python3 -IB "$here/node_check.py" "$out/registered" "$out/fixture/blocks" "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["base"])' "$out/fixture/case.json")"
python3 -IB "$here/review/check.py" "$out/fixture" "$out/stores/snap/live.sqlite" "$out/stores/ordinary/live.sqlite" --pin "$out/operator-pin.json"
python3 -IB "$here/node_identity_check.py" "$out/source/deployment"
