#!/usr/bin/env bash
# Linux x86-64. The result directory contains private wallet keys. Only result.json is public evidence.
set -euo pipefail
umask 077
[[ $# == 1 ]] || { echo 'usage: bash reproduce.sh NEW_PRIVATE_DIRECTORY' >&2; exit 2; }
mkdir -m 700 -- "$1"
out=$(cd -- "$1" && pwd -P)
here=$(cd -- "$(dirname -- "$0")" && pwd -P)
get() {
    local url=$1 name=$2 digest=$3 cached=$4
    if [[ -n "$cached" ]]; then cp -- "$cached" "$out/$name"
    else curl --proto '=https' --proto-redir '=https' -fsSL --retry 2 "$url" -o "$out/$name"; fi
    (cd "$out" && echo "$digest  $name" | sha256sum -c -)
}

base=https://github.com/jouliene/pq-private-chain/releases/download
get 'https://github.com/leanprover/lean4/releases/download/v4.19.0/lean-4.19.0-linux.tar.zst' lean.tar.zst \
    6fe3ce97a58f44e2b3567d455b994eacec5bfe9ae7774f2a573444480ba813fe "${CONSERVATION_LEAN_ARCHIVE:-}"
get "$base/funded-membership-2026-11-21/funded-membership-public.tar.gz" history.tar.gz \
    24fc62066d1c43b46e33152d83ee642b4d077aed7d9030ce3ffa2b31b5ceea87 "${CONSERVATION_HISTORY:-}"
get "$base/funded-pq-assurance-2026-11-21/funded-pq-assurance-c-deployment.tar.gz" deployment.tar.gz \
    682ed92c510c0b73ddf21ed7c50c048c4430bb8b06c5e6fc28db1e63e8c5d942 "${CONSERVATION_DEPLOYMENT:-}"
mkdir "$out/network" "$out/history"
tar --zstd -xf "$out/lean.tar.zst" -C "$out"
tar -xf "$out/history.tar.gz" -C "$out/history" public/blocks
tar -xf "$out/deployment.tar.gz" -C "$out/network"
lean="$out/lean-4.19.0-linux/bin/lean"
[[ $("$lean" -g) == 6caaee842e9495688c1567e78c0e68dbb96942aa ]]
"$lean" --version
upstream=${CONSERVATION_QNERO:-}
if [[ -z $upstream ]]; then
    upstream="$out/qnero"
    git init -q "$upstream"
    git -C "$upstream" fetch -q --no-tags --depth=1 https://github.com/DigitalGuards/qnero.git f04c91307837c0231668383bec76ba98d89d2652
    git -C "$upstream" checkout -q --detach FETCH_HEAD
fi
export RAYON_NUM_THREADS=2
bwrap --unshare-all --die-with-parent --new-session --cap-drop ALL --ro-bind / / -- /bin/true
python3 -IB "$here/source_check.py" "$out/deployment.tar.gz" --upstream "$upstream" --sources "$out/sources" > "$out/source-result.json"
python3 -IB "$here/../funded-membership/vectors.py"
python3 -IB "$here/funded.py" "$out"
python3 -IB "$here/ground.py" "$lean" "$out"
