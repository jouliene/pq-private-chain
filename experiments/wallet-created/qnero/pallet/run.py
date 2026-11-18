"""Execute funded wallet creation then pinned FRAME dispatch on the resulting public data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, cwd, out, env):
    started = time.monotonic()
    with out.with_suffix(".log").open("xb") as log:
        child = subprocess.Popen(command, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        try:
            _, state, usage = os.wait4(child.pid, 0)
            child.returncode = os.waitstatus_to_exitcode(state)
        finally:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if child.returncode is None:
                _, state, usage = os.wait4(child.pid, 0)
                child.returncode = os.waitstatus_to_exitcode(state)
            out.with_suffix(".json").write_text(json.dumps(
                {"exit":child.returncode, "elapsed_s":time.monotonic()-started, "cpu_user_s":usage.ru_utime,
                 "cpu_system_s":usage.ru_stime, "max_rss_kib":usage.ru_maxrss}, indent=2) + "\n")
    if child.returncode:
        raise RuntimeError(f"{out.name} returned {child.returncode}; see the stage log")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path)
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    checkout = args.checkout.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    public = out / "public"
    public.mkdir()
    git = lambda *a: subprocess.check_output(["git", "-C", checkout, *a], text=True).strip()
    assert git("rev-parse", "HEAD") == "f04c91307837c0231668383bec76ba98d89d2652"
    assert not git("status", "--porcelain") or set(git("status","--porcelain").splitlines()).issubset({
        "M chain/pallets/shielded/src/lib.rs", " M chain/pallets/shielded/src/lib.rs",
        "?? chain/pallets/shielded/src/anchored_wallet_replay.rs",
        "?? crates/qnero-wallet/tests/dispatch_inputs.rs"})
    env = dict(os.environ, RAYON_NUM_THREADS="4")
    run([sys.executable, HERE / "stage.py", checkout], checkout, out/"stage", env)
    tracked = [checkout / "Cargo.lock", checkout / "chain/Cargo.lock", HERE / "run.py",
               HERE / "stage.py", HERE.parent / "comparative_wallet.rs", HERE / "anchored_wallet_replay.rs",
               checkout / "chain/pallets/shielded/src/lib.rs",
               checkout / "chain/pallets/shielded/src/anchored_wallet_replay.rs",
               checkout / "crates/qnero-wallet/tests/dispatch_inputs.rs"]
    def pins():
        return {str(path.relative_to(checkout) if path.is_relative_to(checkout) else
                    "overlay/" + str(path.relative_to(HERE.parent))):sha(path) for path in tracked}
    snapshot = pins()
    (out / "source.json").write_text(json.dumps(snapshot, indent=2) + "\n")
    cargo = ["rustup", "run", "1.93.0", "cargo", "test", "--offline", "--locked", "-j2", "--release"]
    with tempfile.TemporaryDirectory(prefix="qnero-funding-", dir="/dev/shm") as private:
        run(cargo + ["-p", "qnero-wallet", "--features", "parallel", "--test", "dispatch_inputs",
                     "--", "--exact", "ordinary_wallet_payment"], checkout, out/"wallet",
            dict(env, QNERO_PRIVATE=private, QNERO_PUBLIC=str(public)))
    # No secret path is live when pallet code runs.
    run(cargo + ["-p", "pallet-shielded", "--lib", "--", "--exact",
                 "anchored_wallet_replay::funded_public_wallet_dispatch", "--nocapture"],
        checkout / "chain", out/"pallet", dict(env, QNERO_PUBLIC=str(public)))
    log = (out / "pallet.log").read_text()
    lines = [s for s in log.splitlines() if s.startswith('{"minted_steps":')]
    assert len(lines) == 1 and "1 passed; 0 failed" in log
    wallet_log = (out/"wallet.log").read_text()
    assert "1 passed; 0 failed" in wallet_log and pins() == snapshot
    result = {"git":git("rev-parse", "HEAD"), "pallet":json.loads(lines[0]), "source_unchanged":True,
              "wallet":json.loads((public / "wallet.json").read_text()),
              "public":{f.name:{"sha256":sha(f), "bytes":f.stat().st_size} for f in sorted(public.iterdir())}}
    (out / "summary.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
