"""The research deployment's verifier and operator-approved executable identities."""
import hashlib
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DEFAULT = ROOT/"runtime"
PROFILE = "5d6cfc6ccff5792e4899799124b2fb1e7dac50f727825c4886485dc01a564ce8"

def checked_keys(keys):
    if keys.is_symlink() or {p.name for p in keys.iterdir()}!={"direct.vk"}:
        raise ValueError("unexpected direct verifier registry")
    vk = keys/"direct.vk"
    if vk.is_symlink() or not vk.is_file() or hashlib.sha256(vk.read_bytes()).hexdigest()!=PROFILE:
        raise ValueError("unregistered direct payment verifier")
    return keys.resolve(strict=True)

def config(directory):
    binary = Path(directory).resolve(strict=True)/"native"
    actual = hashlib.sha256(binary.read_bytes()).hexdigest()
    # Written by staging, from the operator's explicit build approval and the verified build receipt.
    expected = (HERE/"approved-native.sha256").read_text().strip()
    if binary.is_symlink() or actual!=expected:
        raise ValueError("unexpected direct wallet executable")
    return SimpleNamespace(binary=binary,binary_sha=actual,keys=checked_keys(ROOT/"keys"),profile_sha=PROFILE)

prepare = config
