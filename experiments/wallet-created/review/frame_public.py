"""Replay a pinned, already-built upstream FRAME test using only public payment inputs."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def check(args):
    checkout = args.upstream
    def git(*argv):
        return subprocess.check_output(["git", "-C", str(checkout), *argv])
    source = json.loads(args.pins.read_bytes())
    pin = "f04c91307837c0231668383bec76ba98d89d2652"
    assert git("rev-parse", "HEAD").decode().strip() == pin
    lib = "chain/pallets/shielded/src/lib.rs"
    assert git("diff", "--name-only", "HEAD").decode().splitlines() == [lib]
    assert (checkout/lib).read_bytes() == git("show", f"HEAD:{lib}") + b"\n#[cfg(test)]\nmod anchored_wallet_replay;\n"
    for name, digest in source.items():
        path = args.overlay/name.removeprefix("overlay/") if name.startswith("overlay/") else checkout/name
        assert sha(path.read_bytes()) == digest
    assert sha(args.binary.read_bytes()) == args.binary_sha
    public_files = ("funding-inner.bin", "funding-commitment.bin", "payment.scale", "anchor-fields.bin",
                    "anchor.bin", "commitments.bin", "real-slot-nullifiers.bin")
    data = json.loads(args.summary.read_bytes())
    with tempfile.TemporaryDirectory() as d:
        for name in public_files:
            raw = (args.public/name).read_bytes()
            assert sha(raw) == data["public"][name]["sha256"] and len(raw) == data["public"][name]["bytes"]
            (Path(d)/name).write_bytes(raw)
        result = subprocess.check_output(["bwrap", "--unshare-all", "--new-session", "--die-with-parent",
            "--clearenv", "--cap-drop", "ALL", "--setenv", "QNERO_PUBLIC", "/inputs", "--ro-bind", "/usr", "/usr",
            "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev",
            "--ro-bind", d, "/inputs", "--ro-bind", str(args.binary.resolve()), "/test", "--remount-ro", "/",
            "--", "/test", "--exact", "anchored_wallet_replay::funded_public_wallet_dispatch", "--nocapture"],
            text=True, timeout=30, stdin=subprocess.DEVNULL)
    rows = [json.loads(line) for line in result.splitlines() if line.startswith('{"minted_steps":')]
    assert len(rows) == 1 and rows[0] == data["pallet"] and "1 passed; 0 failed" in result
    return {"upstream": pin, "test_elf_sha256": args.binary_sha,
            "upstream_and_overlay_hashes": source, "source_manifest_sha256": sha(args.pins.read_bytes()),
            "public_files_sha256": {name:data["public"][name]["sha256"] for name in public_files},
            "frame": rows[0]}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("upstream", "overlay", "pins", "public", "summary", "binary"):
        p.add_argument(name, type=Path)
    p.add_argument("binary_sha")
    print(json.dumps(check(p.parse_args()), indent=2))
