"""Read one isolated native verification child's wait4 metrics on Linux."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from run import VK_BLAKE2B

public = Path(sys.argv[1]).resolve()
checker = Path(sys.argv[2]).resolve()
vk = (public / "private-verifier.bin").read_bytes()
assert hashlib.blake2b(vk, digest_size=32).hexdigest() == VK_BLAKE2B
# wait4 in the child's PID namespace. Peak RSS can include the inherited
# launcher image before exec; measure the no-op child for comparison.
inside = """
import json, os
for command in [["/usr/bin/true"], ["/check", "/public", "positive"]]:
    pid = os.posix_spawn(command[0], command, {})
    _, stat, usage = os.wait4(pid, 0)
    assert os.waitstatus_to_exitcode(stat) == 0
    print(json.dumps({"exec":command[0], "exit":0, "user_s":usage.ru_utime,
        "system_s":usage.ru_stime, "peak_rss_kib":usage.ru_maxrss}), flush=True)
"""
print(json.dumps({"payment_sha256": hashlib.sha256((public / "payment.scale").read_bytes()).hexdigest(),
                  "verifier_elf_sha256": hashlib.sha256(checker.read_bytes()).hexdigest()}), flush=True)
subprocess.run(["bwrap", "--unshare-all", "--die-with-parent", "--clearenv", "--ro-bind", "/usr", "/usr",
                "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64", "--dev", "/dev",
                "--proc", "/proc", "--ro-bind", public, "/public", "--ro-bind", checker, "/check",
                "--", "/usr/bin/python3", "-I", "-c", inside], check=True)
