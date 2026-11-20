"""Local executable and shared verifier identity for the AST1 deployment."""
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DEFAULT = ROOT / "runtime"
APPROVED = (HERE / "asset.vk").read_bytes()
PROFILE = sha256(APPROVED).hexdigest()


def checked_keys(directory):
    key = directory / "asset.vk"
    if directory.is_symlink() or set(directory.iterdir()) != {key} or key.is_symlink() or key.read_bytes() != APPROVED:
        raise ValueError("unapproved AST1 verifier")
    return directory.resolve(strict=True)


def config(directory):
    binary = Path(directory).resolve(strict=True) / "native"
    expected = (HERE/"approved-native.sha256").read_text().strip()
    if binary.is_symlink() or sha256(binary.read_bytes()).hexdigest() != expected:
        raise ValueError("unapproved AST1 executable")
    return SimpleNamespace(binary=binary,binary_sha=expected,profile_sha=PROFILE,keys=checked_keys(ROOT/"keys"))


prepare = config
