"""A staged local node accepts only the approved binary and fixed TKN1 verifier."""
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DEFAULT = ROOT / "runtime"
PROFILE = "f4b865c6c2aaa9afdd6a7a7ecb94fe9b76ffdc75d25d5a570cf595d315576c2b"


def checked_keys(keys):
    key = keys / "token.vk"
    if (keys.is_symlink() or set(keys.iterdir()) != {key} or key.is_symlink()
            or sha256(key.read_bytes()).hexdigest() != PROFILE):
        raise ValueError("unapproved TKN1 verifier")
    return keys.resolve(strict=True)


def config(directory):
    binary = Path(directory).resolve(strict=True) / "native"
    expected = (HERE / "approved-native.sha256").read_text().strip()
    if binary.is_symlink() or sha256(binary.read_bytes()).hexdigest() != expected:
        raise ValueError("unapproved TKN1 executable")
    return SimpleNamespace(binary=binary, binary_sha=expected, profile_sha=PROFILE,
                           keys=checked_keys(ROOT / "keys"))

prepare = config
