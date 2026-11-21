#!/usr/bin/env bash
# Audit the captured public graphs, stopped home database, private seed and role traffic separately.
set -euo pipefail
[[ $# == 5 ]]
here=$(cd -- "$(dirname -- "$0")" && pwd -P)
network=$1 archives=$2 out=$3 helpers=$4 node=$5
public="$out/public"
python3 -IB "$here/review/replay.py" "$public" "$network/deployment" "$helpers" "$node" --store "$out/home/home.sqlite" --window 3 > "$out/replayed.json"
tip=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["final"])' "$public/OUTCOME.json")
python3 -IB "$here/review/seed_check.py" "$public" "$network/deployment" "$network/owner-backups/offline" "$tip" > "$out/owner-check.json"
python3 -IB "$here/review/peers.py" "$public" "$out/metrics.json" "$archives/archive1/peer.jsonl" "$archives/archive2/peer.jsonl" > "$out/peer-check.json"
python3 -IB "$here/costs.py" "$out" > "$out/costs.json"
