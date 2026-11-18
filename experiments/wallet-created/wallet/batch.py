"""Authenticate three detached ordinary statements/proofs under one verifier-owned setup."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bridge import libraries, require


def main():
    config_path, public_dir = sys.argv[1:]
    config = json.loads(Path(config_path).read_bytes())
    require(config["backend"] == "whir")
    binary = Path(config["binary"])
    require(hashlib.sha256(binary.read_bytes()).hexdigest() == config["binary_sha256"])
    timer = Path("/usr/bin/time")
    argv = ["/usr/bin/bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
            "--clearenv", "--setenv", "LANG", "C", "--setenv", "RAYON_NUM_THREADS", "1",
            "--proc", "/proc", "--dev", "/dev", "--dir", "/inputs",
            "--ro-bind", str(binary), "/backend", "--ro-bind", str(timer), "/meter"]
    for path in sorted(set(libraries(binary) + libraries(timer))):
        real = path.resolve(strict=True)
        require(config["libraries"].get(str(real)) == hashlib.sha256(real.read_bytes()).hexdigest())
        argv.extend(["--ro-bind", str(real), str(path)])
    files = []
    for index in range(3):
        for kind in ("statement", "proof"):
            name = f"{index}.{kind}"
            path = Path(public_dir, name).resolve(strict=True)
            require(path.is_file())
            require(path.stat().st_size == 528 if kind == "statement" else 0 < path.stat().st_size < 272557)
            argv.extend(["--ro-bind", str(path), "/inputs/"+name])
            files.append("/inputs/"+name)
    argv += ["--remount-ro","/","--chdir","/","--","/meter","-f","meter %U %S %M","/backend","verify-many",*files]
    started = time.monotonic()
    proc = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
    require(proc.returncode == 0)
    meter = re.fullmatch(rb"meter ([0-9.]+) ([0-9.]+) ([0-9]+)\n", proc.stderr)
    require(meter and len(proc.stdout) <= 65536)
    checked = json.loads(proc.stdout)
    require(checked["mode"] == "verify-many" and checked["accepted"] is True and len(checked["records"])==3)
    for record in checked["records"]:
        require(record["accepted"] is True and record["mode"]=="verify")
    print(json.dumps(dict(backend=checked,elapsed_s=time.monotonic()-started,user_s=float(meter[1]),
                          system_s=float(meter[2]),peak_rss_kib=int(meter[3]))))


if __name__ == "__main__":
    main()
