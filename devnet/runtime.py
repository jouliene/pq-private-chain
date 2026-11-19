"""Prepare the pinned source-built public runtime, shared read-only by the participants."""
import fcntl
import hashlib
import json
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
    if (directory/"active-runtime").is_symlink():
        # Resolve one generation for both reads, even while an upgrade activates another.
        directory=(directory/"active-runtime").resolve(strict=True)
    binary = directory / "native"
    binary_sha = validate(binary, directory / "BUILD.json")
    return SimpleNamespace(binary=binary, binary_sha=binary_sha,
                           keys=checked_keys(KEYS), profile_sha=PROFILE)


def _sync(path):
    fd=os.open(path,os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _link(directory,name,target):
    if (directory/name).is_symlink() and os.readlink(directory/name)==target:
        return
    with tempfile.TemporaryDirectory(dir=directory) as work:
        tmp=Path(work)/"link"
        tmp.symlink_to(target)
        os.replace(tmp,directory/name)
    _sync(directory)


def _installed(directory):
    # All compiler/source pins are fixed in this checkout. Identical installed source
    # built in different paths may have separate ELF digests, checked in its own receipt.
    pin=hashlib.sha256((HERE/"crypto/evidence/BUILD.json").read_bytes()).hexdigest()
    return directory/"installs"/pin


def _activate(directory,generation):
    config(generation)
    link="active-runtime"
    if not os.path.lexists(directory/link):
        previous=generation
        if all((directory/x).is_file() for x in ("native","BUILD.json")):
            # Preserve both initially installed flat files. During conversion of the two
            # entry points, both the old files and the new aliases resolve to identical bytes.
            previous=generation.parent/("previous-"+hashlib.sha256((directory/"BUILD.json").read_bytes()).hexdigest())
            if not previous.exists():
                with tempfile.TemporaryDirectory(dir=generation.parent) as work:
                    pair=Path(work)/"pair"
                    pair.mkdir()
                    for name in ("native","BUILD.json"):
                        os.link((directory/name).resolve(strict=True),pair/name)
                    _sync(pair)
                    os.rename(pair,previous)
                _sync(generation.parent)
        _link(directory,link,os.path.relpath(previous,directory))
    for name in ("native","BUILD.json"):
        _link(directory,name,link+"/"+name)
    _link(directory,link,os.path.relpath(generation,directory))
    return config(directory)


def prepare(directory):
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    with (directory/"build.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        generation=_installed(directory)
        if generation.is_dir():
            return _activate(directory,generation)
        if (directory/"BUILD.json").exists():
            # Rebuild the previous published devnet profile from trusted source. Unknown
            # receipts still fail closed. Never execute the retired binary while migrating.
            record=json.loads((directory/"BUILD.json").read_bytes())
            old=json.loads((HERE/"crypto/evidence/BUILD_V1.json").read_bytes())
            if (record.keys()!=old.keys() or any(record[k]!=old[k] for k in old if k!="binary_sha256")):
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
        generation.parent.mkdir(exist_ok=True)
        _sync(directory)
        with tempfile.TemporaryDirectory(dir=generation.parent) as stage:
            staged = Path(stage)/"pair"
            staged.mkdir()
            doc = subprocess.check_output([sys.executable,"-IB",str(HERE/"crypto/build.py"),str(upstream),str(directory/"target"),str(staged/"native")])
            (staged/"BUILD.json").write_bytes(doc)
            config(staged)
            for name in ("native","BUILD.json"):
                _sync(staged/name)
            _sync(staged)
            os.rename(staged,generation)
            _sync(generation.parent)
        return _activate(directory,generation)
