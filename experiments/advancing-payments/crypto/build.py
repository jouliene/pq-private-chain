"""Build the APV2 executable in a disposable, clean pinned Qnero checkout."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
REVISION = "f04c91307837c0231668383bec76ba98d89d2652"
CONFIG = Path("crates/qnero-circuit/src/config.rs")
PREIMAGE = "6ecd00581bbd804a65f4485fab7b3e2f287187850ba050652feb89f778758390"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["upstream", "target", "output"]:
        parser.add_argument(name, type=lambda p: Path(p).resolve())
    args = parser.parse_args()
    src = args.upstream
    cmd = lambda *parts: subprocess.check_output(parts, cwd=src, text=True).strip()
    if cmd("git", "rev-parse", "HEAD") != REVISION or cmd("git", "status", "--porcelain"):
        raise ValueError("a clean, disposable checkout of the pinned upstream revision is required")
    original = (src / CONFIG).read_bytes()
    if sha(original) != PREIMAGE or args.output.exists():
        raise ValueError("unexpected config preimage or existing output")
    example = src / "crates/qnero-prover/examples/advancing"
    sources = sorted((HERE / "src").glob("*.rs"))
    patch = HERE / "profile.patch"
    rustc = cmd("rustup", "run", "1.93.0", "rustc", "-Vv")
    build = ["rustup", "run", "1.93.0", "cargo", "build", "--locked", "--offline",
             "--release", "-j2", "-p", "qnero-prover", "--example", "advancing", "--features", "parallel"]
    cmd("git", "apply", "--check", str(patch))
    example.mkdir(parents=True)
    try:
        cmd("git", "apply", str(patch))
        overlay_sha = sha((src / CONFIG).read_bytes())
        for path in sources:
            shutil.copyfile(path, example / path.name)
        subprocess.run(build, cwd=src, env=dict(os.environ, CARGO_TARGET_DIR=str(args.target)), check=True)
        binary = args.target / "release/examples/advancing"
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("xb") as out, binary.open("rb") as inp:
            shutil.copyfileobj(inp, out)
        args.output.chmod(0o755)
    finally:
        (src / CONFIG).write_bytes(original)
        shutil.rmtree(example)
    if cmd("git", "status", "--porcelain"):
        raise RuntimeError("upstream checkout changed after restoring sources")
    print(json.dumps(dict(upstream=REVISION, rustc=rustc, cargo=build,
                          config_before_sha256=PREIMAGE, config_after_sha256=overlay_sha,
                          cargo_lock_sha256=sha((src/"Cargo.lock").read_bytes()),
                          sources_sha256={p.relative_to(HERE).as_posix():sha(p.read_bytes()) for p in
                                          [*sources, patch, HERE/"build.py", HERE/"PROFILE.md"]},
                          binary_sha256=sha(args.output.read_bytes())), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
