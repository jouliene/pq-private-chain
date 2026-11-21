#!/usr/bin/env bash
# Linux x86-64. All protocol inputs are fetched from their public, pinned sources.
set -euo pipefail
umask 077
[[ $# == 1 ]] || { echo "Usage: $0 NEW-WORK-DIRECTORY" >&2; exit 2; }
here=$(cd -- "$(dirname -- "$0")" && pwd -P)
mkdir -- "$1"
work=$(cd -- "$1" && pwd -P)
mkdir "$work/tools" "$work/capture"
test "$(uname -sm)" = 'Linux x86_64'
test -x /usr/bin/time
python3 -c 'import sys; assert sys.version_info >= (3,11)'
bwrap --unshare-all --die-with-parent --ro-bind /usr /usr --ro-bind /lib /lib --ro-bind /lib64 /lib64 -- /usr/bin/true
fetch() { curl --fail --show-error --silent --location --retry 3 --proto '=https' --proto-redir '=https' "$1" -o "$2"; }
dist=node-v24.22.1-linux-x64
fetch "https://nodejs.org/dist/v24.22.1/$dist.tar.xz" "$work/tools/$dist.tar.xz"
(
    cd "$work/tools"
    echo "6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6  $dist.tar.xz" | sha256sum -c -
    tar -xJf "$dist.tar.xz" "$dist/bin/node"
    echo "e32e2d16081cf644f88392934288086e7662529d0d43277c34f7aad2207cfafb  $dist/bin/node" | sha256sum -c -
)
node="$work/tools/$dist/bin/node"
export CARGO_HOME="$work/cargo-home" CARGO_TARGET_DIR="$work/target" RAYON_NUM_THREADS=4
if ! rustup run 1.93.0 rustc --version >/dev/null 2>&1; then
    export RUSTUP_HOME="$work/rustup"
    rustup toolchain install 1.93.0 --profile minimal
fi
rustup run 1.93.0 cargo fetch --locked --manifest-path "$here/proof/Cargo.toml"
rustup run 1.93.0 cargo build --locked --offline --release -j2 --manifest-path "$here/proof/Cargo.toml"
rustup run 1.93.0 cargo test --locked --offline --release -j2 --manifest-path "$here/proof/Cargo.toml"
bin="$work/target/release/n7p2"
"$bin" generate-vk "$work/rebuilt.vk"
cmp "$work/rebuilt.vk" "$here/proof/registered.vk"
python3 -IB "$here/proof/check.py" "$bin" "$work/native-controls" --single > "$work/controls.json"
python3 -IB "$here/proof/size.py" "$work/native-controls/proof.bin" > "$work/proof-size.json"
python3 -IB "$here/review/registration.py" > "$work/registration.json"
python3 -IB "$here/index_cost.py" > "$work/index-cost.json"

fetch https://github.com/jouliene/pq-private-chain/releases/download/advancing-note-2026-11-21/advancing-public.tar.gz "$work/capture/advancing-public.tar.gz"
(cd "$work/capture" && sha256sum -c "$here/RELEASE.sha256")
python3 - "$work/capture" <<'PY'
from pathlib import Path
import shutil, sys, tarfile
d = Path(sys.argv[1])
allowed = {'public/genesis.json', *(f'public/block-{h:04d}.bin' for h in range(1,11)),
           'branch/original-2.bin', 'branch/original-3.bin', 'branch/conflict.packet', 'branch/detached.packet'}
with tarfile.open(d/'advancing-public.tar.gz') as t:
    members = t.getmembers()
    assert len(members)==len(allowed) and set(m.name for m in members)==allowed
    for m in members:
        assert m.isfile() and 0 < m.size <= 600000
        out = d/m.name
        out.parent.mkdir(exist_ok=True)
        with t.extractfile(m) as inp, out.open('xb') as dst: shutil.copyfileobj(inp,dst)
PY
cp "$here/FOUNDING_ID" "$work/capture/founding-id"
python3 -IB "$here/lab/storage_check.py" "$bin" "$node" "$work/capture/public" "$work/capture/founding-id" > "$work/storage-check.json"
python3 -IB "$here/lab/run.py" check "$bin" "$node" "$work/capture" > "$work/published-check.json"
python3 -IB "$here/review/wire.py" "$work/capture/public" "$work/capture/founding-id" > "$work/wire.json"
python3 -IB "$here/lab/run.py" fresh "$bin" "$node" "$work/fresh" > "$work/fresh-summary.json"
python3 -IB "$here/review/wire.py" "$work/fresh/public" "$work/fresh/founding-id" > "$work/fresh-wire.json"
python3 -IB "$here/evaluate.py" "$work/fresh/RESULT.json" > "$work/fresh-costs.json"
python3 - "$here" "$work" <<'PY'
import json, sys
from pathlib import Path
here,work=map(Path,sys.argv[1:])
def load(p): return json.loads(p.read_bytes())
r=load(here/'RESULT.json')
for t in load(work/'published-check.json')['trials']:
    assert t['final']==r['final']
fresh=load(work/'fresh/RESULT.json')
for k in ('balances','restored','zero','controls'):
    assert r[k]==fresh[k],k
for k in ('count','height','issued','miner_fees','spent'):
    assert r['final'][k]==fresh['final'][k],k
assert fresh['final']['root']!=r['final']['root']
for name,results in [('wire.json',r),('fresh-wire.json',fresh)]:
    checked=load(work/name)
    assert checked['tip']==results['final']['tip'] and checked['spent_hash']==results['final']['spent_hash']
print('Released and independently funded histories, fork controls and final accounting agree.')
PY
