"""Build DLF1 against the exact baseline wallet, pinned upstream and locked dependencies."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BASE = ROOT / "experiments/advancing-payments/crypto/src"
REV = "f04c91307837c0231668383bec76ba98d89d2652"
URL = "https://github.com/DigitalGuards/qnero.git"

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def replace_once(source, before, after):
    if source.count(before) != 1:
        raise ValueError(f"unexpected baseline: {before[:80]}")
    return source.replace(before, after)

def native_sources(dest):
    # Reuse checked-in wallet receipt generation, private compact paths, wire effects and native isolation.
    src = (BASE/"codec.rs").read_text().replace('b"APV2"', 'b"DLF1"')
    src = replace_once(src, '(1..=4).contains(&arity)', 'arity == 1')
    (dest/"codec.rs").write_text(src)
    src = (ROOT/"devnet/crypto/wallet.rs").read_text()
    src = replace_once(src, 'use qnero_prover::WalletProver;', 'use crate::registry::WalletProver;')
    start = src.index('        registry::compare(')
    end = src.index('        *prover = Some(p);', start)
    src = src[:start]+'        let p = WalletProver::new(dir)?;\n'+src[end:]
    src = replace_once(src, 'prover.prove_submission(vec![witness])?', 'prover.prove_spend(&witness)?')
    (dest/"wallet.rs").write_text(src)
    src = (BASE/"main.rs").read_text()
    src = src[:src.index('fn builder(')]+src[src.index('fn main() -> Result<()>'):]
    src = replace_once(src,'let keys = (1..=4)\n                .map(|k| registry::load(dir, k))\n                .collect::<Result<Vec<_>>>()?;', 'let verifier = registry::load(dir)?;')
    src = replace_once(src, '&keys[p.arity - 1]', '&verifier')
    src = src[:src.index('        "builder" =>')]+src[src.index('        "wallet" =>'):]
    src = replace_once(src, "        b'H' =>", "        b'C' => wallet::reward_note(body)?.commitment(),\n        b'H' =>")
    (dest/"main.rs").write_text(src)
    shutil.copyfile(HERE/"profile.rs",dest/"registry.rs")

def prepare(work):
    work.mkdir(parents=True,exist_ok=True)
    upstream = work/"upstream"
    if not upstream.exists():
        subprocess.run(["git","init","-q",upstream],check=True)
    def git(*args):
        return subprocess.run(["git","-C",upstream,*args],check=True,text=True,stdout=subprocess.PIPE).stdout.strip()
    if subprocess.run(["git","-C",upstream,"cat-file","-e",REV+"^{commit}"],stderr=subprocess.DEVNULL).returncode:
        git("fetch","--depth=1",URL,REV)
    git("checkout","--detach",REV)
    if git("status","--porcelain") or git("rev-parse","HEAD")!=REV:
        raise ValueError("need a clean pinned upstream checkout")
    cid = hashlib.sha256((HERE/"profile.rs").read_bytes()+(HERE/"build.py").read_bytes()).hexdigest()
    if (work/"native").exists():
        raise ValueError("existing run directory; use a fresh work location")
    cmd = ["rustup","run","1.93.0","cargo"]
    subprocess.run(cmd+["fetch","--locked"],cwd=upstream,check=True)
    dest = upstream/"crates/qnero-prover/examples/direct_payment"
    dest.mkdir(parents=True)
    try:
        native_sources(dest)
        sources={p.name:sha(p) for p in sorted(dest.iterdir())}
        subprocess.run(cmd+["build","--locked","--offline","--release","-j2","-p","qnero-prover","--example","direct_payment","--features","parallel,zk"],
                       cwd=upstream,env=dict(os.environ,CARGO_TARGET_DIR=str(work/"target")),check=True)
        shutil.copy2(work/"target/release/examples/direct_payment",work/"native")
    finally:
        shutil.rmtree(dest)
    if git("status","--porcelain"):
        raise RuntimeError("upstream checkout changed")
    return dict(upstream=REV,lock_sha256=sha(upstream/"Cargo.lock"),driver_sha256=cid,
                compiled_sources=sources,binary_sha256=sha(work/"native"))

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("work",type=Path)
    a=p.parse_args()
    work=a.work.resolve()
    data=prepare(work)
    (work/"BUILD.json").write_text(json.dumps(data,sort_keys=True,indent=2)+"\n")
    print(json.dumps(data,sort_keys=True))
