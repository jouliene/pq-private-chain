"""Build and run the pinned upstream wallet and isolated public verifier on Linux."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import time

SOURCE = Path(__file__).resolve().parent
PIN = "f04c91307837c0231668383bec76ba98d89d2652"
VK_BLAKE2B = "f0e736d14a206824bfcc32b27e6702814cbaf29ecac0dddaccbc558edd0f7784"
OVERLAYS = {"comparative_wallet.rs": "crates/qnero-wallet/tests/comparative_wallet.rs",
            "public_check.rs": "crates/qnero-verifier/examples/public_check.rs"}


def capture(args, **kw):
    return subprocess.check_output(args, text=True, **kw).strip()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def timed(cmd, path, env=None):
    # The first wait4 carries the actual command's CPU, peak RSS and status.
    with path.with_suffix(".stdout").open("xb") as out:
        start = time.monotonic()
        proc = subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT, env=env)
        _, status, usage = os.wait4(proc.pid, 0)
        proc.returncode = os.waitstatus_to_exitcode(status)
        result = {"elapsed_s": time.monotonic() - start, "user_s": usage.ru_utime,
                  "system_s": usage.ru_stime, "peak_rss_kib": usage.ru_maxrss,
                  "exit": proc.returncode}
    path.with_suffix(".json").write_text(json.dumps(result, indent=2) + "\n")
    if proc.returncode:
        raise RuntimeError(f"{path.name} exited {proc.returncode}. See {path.with_suffix('.stdout')}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("upstream", type=Path)
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    upstream = args.upstream.resolve()
    out = args.out.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    public = out / "public"
    public.mkdir()
    def git(*args):
        return capture(["git", "-C", upstream, *args])
    assert git("rev-parse", "HEAD") == PIN and not git("diff", "HEAD", "--name-only")
    for name, relative in OVERLAYS.items():
        dest = upstream / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() and sha(dest) != sha(SOURCE / name):
            raise RuntimeError(f"existing overlay differs: {dest}")
        if not dest.exists():
            shutil.copyfile(SOURCE / name, dest)
    assert set(git("ls-files", "--others", "--exclude-standard").splitlines()) == set(OVERLAYS.values())
    cmd = ["rustup", "run", "1.93.0", "cargo"]
    producer = subprocess.run(cmd + ["test", "--release", "--locked", "-j2", "-p", "qnero-wallet",
        "--features", "parallel", "--test", "comparative_wallet", "--no-run", "--message-format=json"],
        cwd=upstream, stdout=subprocess.PIPE, check=True)
    artifacts = [json.loads(x) for x in producer.stdout.splitlines()]
    paths = [v["executable"] for v in artifacts if v.get("target", {}).get("name") == "comparative_wallet" and v.get("executable")]
    assert len(paths) == 1
    wallet = Path(paths[0])
    subprocess.run(cmd + ["build", "--release", "--locked", "-j2", "-p", "qnero-verifier",
                           "--example", "public_check"], cwd=upstream, check=True)
    verifier = wallet.parents[1] / "examples" / "public_check"
    def pins():
        return {**{n: sha(upstream / p) for n, p in OVERLAYS.items()},
                "wallet_executable": sha(wallet), "public_verifier_executable": sha(verifier),
                "upstream_Cargo.lock": sha(upstream / "Cargo.lock"), "runner": sha(Path(__file__))}
    initial = pins()
    receipt = {"git": PIN, "before": initial, "rustc": capture(["rustup", "run", "1.93.0", "rustc", "-Vv"]),
               "kernel": platform.release(), "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
               "affinity": sorted(os.sched_getaffinity(0)), "threads": 4}
    (out / "pins.json").write_text(json.dumps(receipt, indent=2) + "\n")
    with tempfile.TemporaryDirectory(prefix="qnero-wallet-", dir="/dev/shm") as private:
        env = dict(os.environ, QNERO_PRIVATE=private, QNERO_PUBLIC=str(public), RAYON_NUM_THREADS="4")
        timed([wallet, "--exact", "ordinary_wallet_payment"], out / "producer", env=env)
    assert hashlib.blake2b((public / "private-verifier.bin").read_bytes(), digest_size=32).hexdigest() == VK_BLAKE2B
    # No wallet storage, source, host home or real network in either process.
    sandbox = ["bwrap", "--unshare-all", "--die-with-parent", "--clearenv", "--ro-bind", "/usr", "/usr",
               "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64", "--dev", "/dev",
               "--proc", "/proc", "--ro-bind", public, "/public", "--ro-bind", verifier, "/check", "--",
               "/check", "/public"]
    for mode in ["positive", "controls"]:
        timed(sandbox + [mode], out / mode)
    receipt.update({"after": pins(), "public": {p.name: {"sha256": sha(p), "bytes": p.stat().st_size}
                                               for p in sorted(public.iterdir())}})
    assert receipt["after"] == initial and not git("diff", "HEAD", "--name-only")
    (out / "pins.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
