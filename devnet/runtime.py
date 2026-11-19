"""Prepare the pinned source-built public runtime, shared read-only by the participants."""
import fcntl
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
AP = ROOT / "experiments/advancing-payments"
KEYS = AP / "evidence/public-registry"
sys.path.insert(0,str(HERE))
from crypto.check_build import validate
from wallet import PROFILE, checked_keys

UPSTREAM = "f04c91307837c0231668383bec76ba98d89d2652"
DEFAULT = ROOT / ".work/devnet-runtime"


def config(directory):
    directory = Path(directory).resolve()
    binary = directory / "native"
    binary_sha = validate(binary, directory / "BUILD.json")
    return SimpleNamespace(binary=binary, binary_sha=binary_sha,
                           keys=checked_keys(KEYS), profile_sha=PROFILE)


def prepare(directory):
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    with (directory/"build.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if (directory/"BUILD.json").exists():
            return config(directory)
        for cmd in ("rustup","git","bwrap","cc"):
            if shutil.which(cmd) is None:
                raise ValueError("required program missing: "+cmd)
        if subprocess.run(["rustup","run","1.93.0","rustc","-V"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:
            subprocess.run(["rustup","toolchain","install","1.93.0","--profile","minimal"],check=True)
        upstream = directory/"source"
        if not upstream.exists():
            subprocess.run(["git","init","-q",str(upstream)],check=True)
        def git(*args):
            return subprocess.run(["git","-C",str(upstream),*args],check=True)
        if subprocess.run(["git","-C",str(upstream),"cat-file","-e",UPSTREAM+"^{commit}"],stderr=subprocess.DEVNULL).returncode:
            git("fetch","--depth=1","https://github.com/DigitalGuards/qnero.git",UPSTREAM)
        git("checkout","--detach",UPSTREAM)
        subprocess.run(["rustup","run","1.93.0","cargo","fetch","--locked"],cwd=upstream,check=True)
        with tempfile.TemporaryDirectory(dir=directory) as stage:
            staged = Path(stage)
            doc = subprocess.check_output([sys.executable,"-IB",str(HERE/"crypto/build.py"),str(upstream),str(directory/"target"),str(staged/"native")])
            (staged/"BUILD.json").write_bytes(doc)
            config(staged)
            for name in ("native","BUILD.json"):
                os.replace(staged/name,directory/name)
        return config(directory)
