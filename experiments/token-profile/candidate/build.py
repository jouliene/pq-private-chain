"""Compile the TKN1 native roles against a clean pinned Qnero source checkout."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BASE = ROOT / "experiments/payment-architecture/direct/build.py"
spec = importlib.util.spec_from_file_location("blinded_spend", BASE)
direct = importlib.util.module_from_spec(spec)
spec.loader.exec_module(direct)
LOCK = "ed076404a8d396ddda4acf9a42a915c54472bb70d3dc58300e262f7ecf152a20"

def run(work, upstream, target):
    if (work/"native").exists():
        raise ValueError("use a fresh output directory")
    work.mkdir(exist_ok=True, parents=True)
    def git(*args):
        return subprocess.check_output(["git","-C",upstream,*args],text=True).strip()
    if git("rev-parse","HEAD")!=direct.REV or git("status","--porcelain") or direct.sha(upstream/"Cargo.lock")!=LOCK:
        raise ValueError("expected pristine pinned upstream")
    # Patch only this throwaway copy, keeping the pinned checkout unmodified.
    with tempfile.TemporaryDirectory(dir=work) as tmp:
        tree=Path(tmp)/"source"
        shutil.copytree(upstream,tree,ignore=shutil.ignore_patterns(".git","target"))
        dest=tree/"crates/qnero-prover/examples/token_pair"
        dest.mkdir(parents=True)
        direct.native_sources(dest)
        main=(dest/"main.rs").read_text()
        main=main.replace("effects, encode, packet","effects, packet").replace("use plonky2::iop::witness::{PartialWitness, WitnessWrite};","").replace("use std::collections::HashSet;","")
        (dest/"main.rs").write_text(main)
        codec=(dest/"codec.rs").read_text().replace('b"DLF1"','b"TKN1"')
        (dest/"codec.rs").write_text(codec)
        shutil.copyfile(HERE/"profile.rs",dest/"registry.rs")
        shutil.copyfile(HERE/"wallet.rs",dest/"wallet.rs")
        original=(ROOT/"devnet/crypto/wallet.rs").read_text()
        start,end=original.index("fn seed("),original.index("fn pages(")
        (dest/"seed.inc").write_text("use std::{fs::{self,OpenOptions},os::unix::fs::{OpenOptionsExt,PermissionsExt}};\n"+original[start:end])
        enc=tree/"crates/qnero-notes/src/encrypt.rs"
        enc.write_text(enc.read_text()+"\n"+(HERE/"pair_codec.rs").read_text())
        pq=tree/"crates/qnero-pqcrypto/src/note_encryption.rs"
        src=pq.read_text()
        before='.field("asset_id", &self.asset_id)'
        if src.count(before)!=2:
            raise ValueError("expected both private asset debug printers")
        pq.write_text(src.replace(before,'.field("token_value", &"[REDACTED]")'))
        sources={str(p.relative_to(tree)):direct.sha(p) for p in [*sorted(dest.iterdir()),enc,pq]}
        cmd=["rustup","run","1.93.0","cargo"]
        env=dict(os.environ,CARGO_TARGET_DIR=str(target))
        subprocess.run(cmd+["fetch","--locked"],cwd=tree,env=env,check=True)
        subprocess.run(cmd+["build","--locked","--offline","--release","-j2","-p","qnero-prover","--example","token_pair",
                            "--features","parallel,zk"],cwd=tree,env=env,check=True)
        shutil.copy2(target/"release/examples/token_pair",work/"native")
    out=dict(upstream=direct.REV,lock_sha256=LOCK,generated_sources=sources,binary_sha256=direct.sha(work/"native"),
             registration_design_sha256=direct.sha(HERE/"PROFILE.md"))
    (work/"BUILD.json").write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("work","upstream","target"):p.add_argument(name,type=Path)
    a=p.parse_args()
    run(a.work.resolve(),a.upstream.resolve(),a.target.resolve())
