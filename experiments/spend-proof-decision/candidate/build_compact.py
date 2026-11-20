"""Build the separately supplied public codec for the registered K384 configuration."""
import argparse
from pathlib import Path
import json
import os
import shutil
import subprocess
import tempfile
from hashlib import sha256

HERE=Path(__file__).resolve().parent


def build(work,upstream,target):
    rev="f04c91307837c0231668383bec76ba98d89d2652"
    lock="ed076404a8d396ddda4acf9a42a915c54472bb70d3dc58300e262f7ecf152a20"
    def git(*args):
        return subprocess.check_output(["git","-C",upstream,*args],text=True).strip()
    def digest(path):
        return sha256(path.read_bytes()).hexdigest()
    if git("rev-parse","HEAD")!=rev or git("status","--porcelain") or digest(upstream/"Cargo.lock")!=lock:
        raise ValueError("expected pristine pinned Qnero")
    main=HERE.parent/"compact/codec.rs"
    if not main.is_file(): raise ValueError("missing K384 public codec source")
    work.mkdir(parents=True,exist_ok=False)
    with tempfile.TemporaryDirectory(dir=work) as tmp:
        tree=Path(tmp)/"source"
        shutil.copytree(upstream,tree,ignore=shutil.ignore_patterns(".git","target"))
        enc=tree/"crates/qnero-notes/src/encrypt.rs"
        pq=tree/"crates/qnero-pqcrypto/src/note_encryption.rs"
        pq.write_text(pq.read_text()+'\npub use sha3 as candidate_sha3;\n')
        enc.write_text(enc.read_text()+'\npub use qnero_pqcrypto::note_encryption::candidate_sha3;\n')
        example=tree/"crates/qnero-prover/examples/k384_compact"
        example.mkdir(parents=True)
        shutil.copyfile(main,example/"main.rs")
        shutil.copyfile(HERE/"config.rs",example/"config.rs")
        command=["rustup","run","1.93.0","cargo"]
        env=dict(os.environ,CARGO_TARGET_DIR=str(target))
        subprocess.run(command+["fetch","--locked"],cwd=tree,env=env,check=True)
        subprocess.run(command+["build","--locked","--offline","--release","-j2","-p","qnero-prover",
                                "--example","k384_compact","--features","parallel,zk"],cwd=tree,env=env,check=True)
        shutil.copy2(target/"release/examples/k384_compact",work/"compact")
    receipt={"upstream":rev,"lock_sha256":lock,"codec_sha256":digest(main),
             "config_sha256":digest(HERE/"config.rs"),"binary_sha256":digest(work/"compact")}
    (work/"BUILD.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("work","upstream","target"):p.add_argument(name,type=Path)
    a=p.parse_args()
    build(a.work.resolve(),a.upstream.resolve(),a.target.resolve())
