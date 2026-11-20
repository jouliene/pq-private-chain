"""Build the locked Rust public verifier and generate both registered public matrices."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
HASHES = {"MNG1":"a1cfa119fe582ecd935734ac51db5d1e6c91af9e0019af737d79791dd688cb9c",
          "SLG1":"2bc9e336428462084efd673d31da240992e25a289e7fa6ab88237f2d568f6f3e"}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("work",type=Path)
    a = p.parse_args()
    work = a.work.resolve()
    work.mkdir(mode=0o700,parents=True,exist_ok=True)
    manifest = str(HERE/"proof/Cargo.toml")
    cargo = ["cargo","+1.99.1"]
    subprocess.run([*cargo,"build","--release","--locked","--manifest-path",manifest,
                    "--target-dir",work/"build"],check=True)
    deps = json.loads(subprocess.check_output([*cargo,"metadata","--locked","--format-version","1",
                                               "--manifest-path",manifest]))
    source, = [Path(n["manifest_path"]).parent/"src/poseidon2.rs" for n in deps["packages"]
               if n["name"] == "qp-poseidon-core" and n["version"] == "3.1.0"]
    for suite, expected in HASHES.items():
        path = work/(suite+".r1cs")
        if not path.exists():
            subprocess.run([sys.executable,"-IB",HERE/"relation/frontend.py","register",suite,source,path],
                           check=True,stdout=sys.stderr)
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("registered public matrix differs: "+suite)
    print(json.dumps(dict(constants=str(source),binary=str(work/"build/release/funded-whir"),
                          matrix_directory=str(work))))


if __name__ == "__main__":
    main()
