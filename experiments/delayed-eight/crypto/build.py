"""Build the registered eight-slot verifier/builder in a clean disposable pinned Qnero checkout."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
DIRECT=ROOT/"experiments/payment-architecture/direct"
REV="f04c91307837c0231668383bec76ba98d89d2652"
LOCK="ed076404a8d396ddda4acf9a42a915c54472bb70d3dc58300e262f7ecf152a20"


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def build(upstream,target,out):
    import importlib.util
    spec=importlib.util.spec_from_file_location("pinned_direct_build",DIRECT/"build.py")
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    def git(*args):
        return subprocess.check_output(["git","-C",upstream,*args],text=True).strip()
    if git("rev-parse","HEAD")!=REV or git("status","--porcelain") or sha(upstream/"Cargo.lock")!=LOCK:
        raise ValueError("expected clean Qnero at pinned revision and Cargo.lock")
    out.mkdir(parents=True,exist_ok=False)
    dest=upstream/"crates/qnero-prover/examples/delayed_eight"
    dest.mkdir()
    try:
        mod.native_sources(dest)
        (dest/"registry.rs").rename(dest/"inner.rs")
        # Retain the historical DLF1 packet/effect codec, but pass explicit active
        # statement fields into its unchanged effect and receipt checks for the new suite.
        raw=(dest/"codec.rs").read_text()
        anchor='    ensure!(slots.len() == 26 * p.arity, "slot length");'
        raw=mod.replace_once(raw,anchor,'    checked_slots(p, slots)\n}\n\npub fn checked_slots(p: &Packet, slots: &[F]) -> Result<Vec<u8>> {\n'+anchor)
        (dest/"codec.rs").write_text(raw)
        (dest/"wallet.rs").unlink()
        shutil.copyfile(HERE/"main.rs",dest/"main.rs")
        sources={p.name:sha(p) for p in sorted(dest.iterdir())}
        cargo=["rustup","run","1.93.0","cargo","build","--locked","--offline","--release","-j2","-p","qnero-prover",
               "--example","delayed_eight","--features","parallel,zk"]
        subprocess.run(cargo,cwd=upstream,env=dict(os.environ,CARGO_TARGET_DIR=str(target)),check=True)
        shutil.copy2(target/"release/examples/delayed_eight",out/"native")
    finally:
        shutil.rmtree(dest)
    assert not git("status","--porcelain")
    result=dict(upstream=REV,cargo_lock_sha256=LOCK,compiled_sources_sha256=sources,
                build_driver_sha256=sha(HERE/"build.py"),inner_build_driver_sha256=sha(DIRECT/"build.py"),
                preregistration_sha256=sha(HERE/"PROFILE.md"),binary_sha256=sha(out/"native"),cargo=cargo,
                compiler=subprocess.check_output(["rustup","run","1.93.0","rustc","-Vv"],text=True).strip())
    (out/"BUILD.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("upstream","target","fresh_output"):
        p.add_argument(name,type=lambda v:Path(v).resolve())
    a=p.parse_args()
    build(a.upstream,a.target,a.fresh_output)
