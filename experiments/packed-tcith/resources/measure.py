"""Build, run and time the two isolated component roles; no wallet inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
from verify import verify

HERE = Path(__file__).resolve().parent


def measured(command, record):
    p = subprocess.run(["/usr/bin/time", "-o", str(record), "-f", "%e %U %S %M", *map(str, command)],
                       text=True, capture_output=True, check=True)
    elapsed, user, system, rss = record.read_text().split()
    return p.stdout, dict(elapsed_s=float(elapsed), user_cpu_s=float(user),
                          system_cpu_s=float(system), peak_KiB=int(rss))


def run():
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp)
        binary, sample = path/"commit", path/"test-component.bin"
        subprocess.run(["c++", "-Wall", "-Wextra", "-Werror", "-std=c++17", "-O3",
                        str(HERE/"commit.cpp"), "-lcrypto", "-o", str(binary)], check=True)
        stdout, wallet = measured([binary, sample], path/"commit.time")
        warm, native = measured([binary, "--verify", sample], path/"native.time")
        native["warm_wall_s"] = [float(value) for value in warm.splitlines()]
        result, verifier = measured([sys.executable, "-IB", HERE/"verify.py", sample], path/"verify.time")
        raw = sample.read_bytes()
        # First altered leaf word and last sibling separately exercise the two checks.
        mutations = {"opened_share":64+8*126*33+32, "frontier":len(raw)-1}
        controls = {}
        for label, at in mutations.items():
            modified = bytearray(raw)
            modified[at] ^= 1
            try:
                verify(bytes(modified))
            except ValueError as exc:
                controls[label] = str(exc)
                changed = path/"changed.bin"
                changed.write_bytes(modified)
                native_reject = subprocess.run([binary, "--verify", changed], capture_output=True, text=True)
                if native_reject.returncode != 1 or native_reject.stderr.strip() != str(exc):
                    raise RuntimeError("native corruption verdict mismatch")
            else:
                raise RuntimeError("corruption passed: " + label)
        return dict(shape="SLG1 degree7, 2^20 parties, 101 slots, 25 openings, 33 masks",
                    component_sha256=hashlib.sha256(raw).hexdigest(), public_result=json.loads(result),
                    altered_components=controls, wallet_component=wallet, native_verifier_component=native, python_verifier_component=verifier,
                    kernel_timer=stdout.strip(), platform=platform.platform(),
                    compiler=subprocess.check_output(["c++","--version"],text=True).splitlines()[0],
                    openssl=subprocess.check_output(["openssl","version"],text=True).strip(),
                    python=platform.python_version())


if __name__ == "__main__":
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--check", action="store_true")
    args = args.parse_args()
    result = run()
    if args.check:
        record = json.loads((HERE/"MEASURE.json").read_text())
        for key in ("component_sha256","public_result","altered_components"):
            if result[key] != record[key]:
                raise SystemExit("component reproduction mismatch: " + key)
    print(json.dumps(result, indent=2))
