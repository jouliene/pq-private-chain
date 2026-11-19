"""Local founding policy. One token allocation and zero native issuance at height zero."""
from hashlib import sha256
import struct

VERIFIER = bytes.fromhex("f4b865c6c2aaa9afdd6a7a7ecb94fe9b76ffdc75d25d5a570cf595d315576c2b")
ASSET = sha256(b"TKNPOW/asset/v1\0fixed-research-token").digest()
TOKEN_SUPPLY = 240
GENESIS_MAGIC = b"TKDEVGN1"
BLOCK_MAGIC = b"TKDEVBL1"


def opening(pk):
    if len(pk) != 32 or not any(pk):
        raise ValueError("invalid founding spend identifier")
    context = sha256(b"TKNPOW/founding/v1\0" + VERIFIER + ASSET + pk).digest()
    return context + pk + struct.pack("<QQ", 0, TOKEN_SUPPLY)


def founding_bytes(pk, hashes):
    record = opening(pk)
    cm = hashes.call(b"C" + record)
    root = hashes.call(b"R" + cm)
    if len(cm) != 32 or len(root) != 32:
        raise ValueError("founding commitment or root")
    return GENESIS_MAGIC + VERIFIER + ASSET + record + cm + root


def load(directory, rules, digest, canonical):
    raw = (directory / "genesis.bin").read_bytes()
    approval = (directory / "approved-genesis.sha256").read_text().strip()
    if len(raw) != 216 or sha256(raw).hexdigest() != approval or raw[:72] != GENESIS_MAGIC + VERIFIER + ASSET:
        raise ValueError("unapproved founding inventory")
    row, root = raw[72:184], raw[184:]
    if row[:80] != opening(row[32:64]) or not all(canonical(v) and any(v) for v in (row[32:64], row[80:], root)):
        raise ValueError("invalid founding allocation")
    network = sha256(b"TKNPOW/network/v1\0" + VERIFIER + ASSET + sha256(raw).digest() + rules).digest()
    genesis = sha256(b"TKNPOW/genesis/v1\0" + network).digest()
    header = bytes(36) + digest(b"dev-genesis-state", network) + digest(b"dev-genesis-body", network) + root
    return network, genesis, row, header
