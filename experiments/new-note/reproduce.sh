#!/usr/bin/env bash
# Run the N7P1 public reproduction in a new output directory.
set -euo pipefail
umask 077
if (( $# < 1 || $# > 2 )) || [[ ${2:-} != "" && ${2:-} != "--controls" ]]; then
    echo "Usage: $0 NEW-OUTPUT-DIRECTORY [--controls]" >&2
    exit 2
fi
here=$(cd -- "$(dirname -- "$0")" && pwd -P)
repo=$(cd -- "$here/../.." && pwd -P)
mkdir -- "$1"
work=$(cd -- "$1" && pwd -P)
printf 'Reproduction outputs: %s\n' "$work"
mkdir "$work"/{old-author,old-review,released,tools}
test -x /usr/bin/time
test "$(uname -sm)" = 'Linux x86_64'
for command in bwrap cc curl git openssl python3 rustup sha256sum tar; do
    command -v "$command" >/dev/null
done
python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))'
# Fail promptly if the host cannot run the namespaces used for private/public roles.
bwrap --unshare-all --die-with-parent --ro-bind /usr /usr --ro-bind /lib /lib --ro-bind /lib64 /lib64 -- /usr/bin/true
(
    git -C "$repo" rev-parse HEAD
    uname -srvmo
    cc --version
    openssl version
) > "$work/platform.txt"

base=https://github.com/jouliene/pq-private-chain/releases/download
fetch() { curl --fail --silent --show-error --location --retry 3 --proto '=https' --proto-redir '=https' "$1" -o "$2"; }
fetch "$base/funded-tcith-2026-11-21/funding.tar.gz" "$work/old-author/funding.tar.gz"
fetch "$base/funded-tcith-2026-11-21/independent-funding.tar.gz" "$work/old-review/independent-funding.tar.gz"
fetch "$base/new-note-2026-11-21/public-notes.tar.gz" "$work/released/public-notes.tar.gz"
(cd "$work/old-author" && sed -n '/  funding.tar.gz$/p' "$repo/experiments/funded-tcith/RELEASE.sha256" | sha256sum -c -)
(cd "$work/old-review" && sha256sum -c "$repo/experiments/funded-tcith/review/INDEPENDENT.sha256")
(cd "$work/released" && sed -n '/  public-notes.tar.gz$/p' "$here/RELEASE.sha256" | sha256sum -c -)
python3 - "$work" <<'PY'
from pathlib import Path, PurePosixPath
import shutil
import sys
import tarfile
work = Path(sys.argv[1])
required = {"public/genesis.json", *(f"public/block-{i:04}.bin" for i in (1, 2, 3))}
for folder, name in (("old-author", "funding.tar.gz"), ("old-review", "independent-funding.tar.gz"),
                     ("released", "public-notes.tar.gz")):
    destination = work / folder
    seen = set()
    with tarfile.open(destination / name, "r:gz") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "public":
                raise ValueError("unexpected public archive path")
            out = destination.joinpath(*path.parts)
            if member.isdir():
                out.mkdir(exist_ok=True, parents=True)
            elif member.isfile():
                seen.add(str(path))
                out.parent.mkdir(exist_ok=True, parents=True)
                with archive.extractfile(member) as src, out.open("xb") as dst:
                    shutil.copyfileobj(src, dst)
            else:
                raise ValueError("unexpected public archive entry type")
    if folder == "released" and seen != required:
        raise ValueError("unexpected N7P1 release public file set")
PY
cp "$here/FOUNDING_ID" "$work/released/founding-id"

node_tar=node-v24.22.1-linux-x64.tar.xz
fetch "https://nodejs.org/dist/v24.22.1/$node_tar" "$work/tools/$node_tar"
(
    cd "$work/tools"
    echo "6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6  $node_tar" | sha256sum -c -
    tar -xJf "$node_tar" node-v24.22.1-linux-x64/bin/node
    echo 'e32e2d16081cf644f88392934288086e7662529d0d43277c34f7aad2207cfafb  node-v24.22.1-linux-x64/bin/node' | sha256sum -c -
)
node="$work/tools/node-v24.22.1-linux-x64/bin/node"
"$node" -p '[process.version,process.versions.openssl,process.platform,process.arch].join(" ")' | tee -a "$work/platform.txt"

export CARGO_HOME="$work/cargo-home" CARGO_TARGET_DIR="$work/target" RAYON_NUM_THREADS=4
# Reuse an installed compiler only. All dependency archives, source and targets are fresh.
if ! rustup run 1.93.0 rustc --version >/dev/null 2>&1; then
    export RUSTUP_HOME="$work/rustup"
    rustup toolchain install 1.93.0 --profile minimal
fi
rustup run 1.93.0 rustc -Vv >> "$work/platform.txt"
rustup run 1.93.0 cargo -V >> "$work/platform.txt"
rustup run 1.93.0 cargo fetch --locked --manifest-path "$here/candidate/Cargo.toml"
rustup run 1.93.0 cargo build --release --locked --offline -j 2 --manifest-path "$here/candidate/Cargo.toml"
binary="$CARGO_TARGET_DIR/release/n7p1"
sha256sum "$binary" > "$work/binary.sha256"

python3 -IB "$here/baseline/wire.py" "$work/old-author/public" "$work/old-review/public" > "$work/baseline.json"
cmp "$work/baseline.json" "$here/baseline/WIRE.json"
python3 -B "$here/sha3/price.py" > "$work/sha3-price.json"
cmp "$work/sha3-price.json" "$here/sha3/PRICE.json"
cc -std=c11 -O3 -Wall -Wextra -Werror "$here/sha3/calibrate.c" -lcrypto -o "$work/tools/calibrate"
"$work/tools/calibrate" > "$work/sha3-calibration.txt"
"$node" "$here/sha3/receipt.mjs" > "$work/sha3-receipt.json"
python3 -IB "$here/candidate/size.py" > "$work/size.json"
python3 -IB "$here/review/frame_risk.py" > "$work/frame-risk.json"
python3 -IB "$here/costs.py" > "$work/scenarios.json"
cmp "$work/scenarios.json" "$here/COSTS.json"
python3 -IB "$here/candidate/alternative/public_rows.py" > "$work/public-rows.json"
if [[ ${2:-} == --controls ]]; then
    python3 -IB "$here/candidate/check.py" "$binary" "$work/native-controls" > "$work/native-controls.json"
    python3 -IB "$here/candidate/size.py" "$work/native-controls/proof.bin" > "$work/native-proof-size.json"
fi

python3 -IB "$here/lab/run.py" verify "$binary" "$node" "$work/released" > "$work/released-replay.json"
python3 -IB "$here/lab/run.py" fresh "$binary" "$node" "$work/fresh" > "$work/fresh-run.json"
python3 -IB "$here/lab/run.py" verify "$binary" "$node" "$work/fresh" > "$work/fresh-replay.json"

python3 - "$here" "$work" <<'PY'
import json
from pathlib import Path
import sys
here, work = map(Path, sys.argv[1:])
def read(path):
    return json.loads(path.read_bytes())
def require(ok, detail):
    if not ok:
        raise ValueError(detail)
def replay_shape(rows):
    return [(r["height"], r["block_B"], r["packet_B"], len(r["legs"])) for r in rows]
def replay(result, actual):
    require(result["final"]["state"] == actual["state"], "public replay state")
    require(replay_shape(result["final"]["verification"]) == replay_shape(actual["verification"]), "public block geometry")
    require([len(r["legs"]) for r in actual["verification"]] == [1, 1, 2], "expected four verified proofs")

accepted = read(here / "RESULT.json")
fresh = read(work / "fresh/RESULT.json")
replay(accepted, read(work / "released-replay.json"))
replay(fresh, read(work / "fresh-replay.json"))
for key in ("balances", "controls"):
    require(accepted[key] == fresh[key], "fresh " + key)
for key in ("issued", "height", "count", "spent", "miner_fees"):
    require(accepted["final"]["state"][key] == fresh["final"]["state"][key], "fresh " + key)
require(accepted["final"]["state"]["root"] != fresh["final"]["state"]["root"], "fresh genesis independence")
require((work/"released/founding-id").read_bytes() != (work/"fresh/founding-id").read_bytes(), "distinct founding anchors")
model = read(work/"size.json")
risk = read(work/"frame-risk.json")
require(model["compact_shape_max_bytes"] == risk["max_body_B"] == 246120, "maximum proof")
require(risk["max_signed_B"] == 267134 and risk["iid_above_signed_frame"] == 93, "signed frame model")
alt = read(work/"public-rows.json")
expected = read(here/"candidate/alternative/RESULT.json")
for key in ("log_n", "public_rows", "quartic_modulus", "trace_omega", "full_domain_point",
            "full_domain_term", "checks", "changed_single_words"):
    require(alt[key] == expected[key], "static-row reference " + key)
print("Released history, independent fresh funding, public state, accounting, controls and deterministic models agree.")
PY
