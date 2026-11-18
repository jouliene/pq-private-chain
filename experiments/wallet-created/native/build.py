"""Add one example to a disposable, clean pinned upstream checkout. Its Cargo lockfile is unchanged."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
PIN = "f04c91307837c0231668383bec76ba98d89d2652"


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("upstream",type=Path)
    ap.add_argument("target",type=Path)
    ap.add_argument("output",type=Path)
    a=ap.parse_args()
    checkout=a.upstream.resolve()
    target=a.target.resolve()
    output=a.output.resolve()
    assert not output.exists()
    def git(*args):
        return subprocess.check_output(["git","-C",str(checkout),*args],text=True).strip()
    assert git("rev-parse","HEAD")==PIN and not git("status","--porcelain")
    source=checkout/"crates/qnero-prover/examples/native_pair.rs"
    source.parent.mkdir(exist_ok=True)
    assert not source.exists()
    shutil.copyfile(HERE/"native_pair.rs",source)
    env={**os.environ,"CARGO_TARGET_DIR":str(target),"CARGO_BUILD_JOBS":"2"}
    try:
        assert subprocess.check_output(["rustc","--version"],cwd=checkout,env=env,text=True).startswith("rustc 1.93.0 ")
        subprocess.run(["cargo","build","--locked","--release","-p","qnero-prover","--example","native_pair","--features","parallel"],cwd=checkout,env=env,check=True)
        with output.open("xb") as out:
            with (target/"release/examples/native_pair").open("rb") as binary:
                shutil.copyfileobj(binary,out)
        output.chmod(0o755)
    finally:
        source.unlink()
    assert not git("status","--porcelain")
    sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
    print(json.dumps(dict(upstream=PIN,cargo_lock_sha256=sha(checkout/"Cargo.lock"),example_sha256=sha(HERE/"native_pair.rs"),
                          binary_sha256=sha(output),compiler=subprocess.check_output(["rustc","-Vv"],cwd=checkout,text=True).splitlines()),indent=2))


if __name__=="__main__":
    main()
