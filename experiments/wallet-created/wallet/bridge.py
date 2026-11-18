"""Run one approved payment prover or verifier in a new mount/PID/network namespace."""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import struct
import subprocess
import sys
import tempfile
import time

MAX_PROOF = 2_097_152


def require(condition):
    if not condition:
        raise ValueError("invalid payment bridge input")


def convert(packet, statement):
    require(len(packet) == 20 + 528 + 5996 and packet[:8] == b"CPPRV004")
    require(struct.unpack_from("<HHI", packet, 8) == (4, 0, 528))
    require(packet[16:544] == statement and packet[544:552] == struct.pack("<IBBH", 5996, 2, 2, 0))
    offset = 552

    def words(n):
        nonlocal offset
        result = struct.unpack_from(f"<{n}Q", packet, offset)
        offset += 8 * n
        return result

    inputs = []
    for _ in range(2):
        note, key, origin, index = words(20), words(5), words(8), words(1)[0]
        require(struct.unpack_from("<HH", packet, offset) == (40, 0))
        offset += 4
        inputs.append(dict(note=note, key=key, origin=origin, index=index, siblings=[words(8) for _ in range(40)]))
    witness = dict(inputs=inputs, outputs=[words(20), words(20)])
    require(offset == len(packet))
    return json.dumps(dict(statement_hex=statement.hex(), witness=witness), separators=(",", ":")).encode()


def libraries(binary):
    lines = subprocess.check_output(["/usr/bin/ldd", str(binary)], text=True,
                                    env={"PATH": "/usr/bin:/bin", "LANG": "C"}).splitlines()
    paths = []
    for line in lines:
        if "linux-vdso" in line:
            continue
        match = re.fullmatch(r"\s*(?:[^ ]+ => )?(/[^ ]+) \(0x[0-9a-f]+\)", line)
        require(match is not None)
        paths.append(Path(match[1]))
    return paths


def run(config, mode, statement, proof, data):
    binary = Path(config["binary"])
    require(hashlib.sha256(binary.read_bytes()).hexdigest() == config["binary_sha256"])
    require(statement.is_file() and statement.stat().st_size == 528)
    raw_statement = statement.read_bytes()
    require(raw_statement[:12] == b"CP-P2-03\x03\x00\x02\x02")
    proving = mode == "prove"
    require(proving or (mode == "verify" and not data))
    require((not proof.exists()) if proving else proof.is_file() and 0 < proof.stat().st_size <= MAX_PROOF)
    cp03 = config["backend"] == "reference"
    if proving and not cp03:
        data = convert(data, raw_statement)
    timer = Path("/usr/bin/time")
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp)
        args = ["/usr/bin/bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
                "--clearenv", "--setenv", "LANG", "C", "--setenv", "RAYON_NUM_THREADS", "1",
                "--proc", "/proc", "--dev", "/dev", "--dir", "/inputs", "--dir", "/output",
                "--ro-bind", str(binary), "/backend", "--ro-bind", str(timer), "/meter",
                "--ro-bind", str(statement.resolve(strict=True)), "/inputs/statement.bin"]
        for path in sorted(set(libraries(binary) + libraries(timer))):
            real = path.resolve(strict=True)
            require(config["libraries"].get(str(real)) == hashlib.sha256(real.read_bytes()).hexdigest())
            args += ["--ro-bind", str(real), str(path)]
        if proving:
            args += ["--bind", str(target), "/output"]
        else:
            args += ["--ro-bind", str(proof.resolve(strict=True)), "/inputs/proof.bin"]
        if cp03:
            invocation = ["prove-private", "/output/public"] if proving else ["valid-public", "/inputs"]
            output = target / "public/proof.bin"
        else:
            invocation = ["prove", "/inputs/statement.bin", "/output/proof"] if proving else ["verify", "/inputs/statement.bin", "/inputs/proof.bin"]
            output = target / "proof"
        args += ["--remount-ro", "/", "--chdir", "/", "--", "/meter", "-f", "meter %U %S %M", "/backend", *invocation]
        begin = time.monotonic()
        result = subprocess.run(args, input=data, capture_output=True, timeout=900)
        elapsed = time.monotonic() - begin
        if result.returncode != 0:
            return None
        # Logs from the private subprocess never leave this bridge.
        match = re.fullmatch(rb"meter ([0-9.]+) ([0-9.]+) ([0-9]+)\n", result.stderr)
        require(match and len(result.stdout) <= 262144)
        value = json.loads(result.stdout)
        if cp03:
            require(value["genuine_proof_created"] if proving else value["mode"] == "public-valid-only")
        else:
            require(value.get("accepted") is True and value.get("mode") == mode)
        if proving:
            require(output.is_file() and not output.is_symlink() and 0 < output.stat().st_size <= MAX_PROOF)
            if cp03:
                require((target / "public/statement.bin").read_bytes() == raw_statement)
            with proof.open("xb") as dest:
                dest.write(output.read_bytes())
        return dict(mode=mode, accepted=True, proof_bytes=proof.stat().st_size, elapsed_s=elapsed,
                    cpu_user_s=float(match[1]), cpu_system_s=float(match[2]), peak_rss_kib=int(match[3]))


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    config_path, mode, statement, proof = sys.argv[1:]
    config = json.loads(Path(config_path).read_bytes())
    payload = sys.stdin.buffer.read(65537)
    require(len(payload) <= 65536)
    result = run(config, mode, Path(statement), Path(proof), payload)
    if result is None:
        print("payment backend rejected", file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, subprocess.SubprocessError):
        sys.exit("payment bridge failed")
