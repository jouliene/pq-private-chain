"""Approved public profiles and a length-delimited membership-only envelope."""
import hashlib
import json
from pathlib import Path
import struct
import sys

MAGIC = b"LMW1"
HEADER = struct.Struct("<4sB32sI")
ROOT_BYTES = 512
LIMIT = 1 << 20
GEOMETRY = {"stock64": (1, 64, 1), "shared40": (2, 40, 2)}


def descriptor(profile):
    ident, depth, paths = GEOMETRY[profile]
    record = {
        "protocol": "toolkit-membership-only-v1",
        "id": ident,
        "lazer": "b958e247a2fdb9593b3c25c9603c6c5305c19420",
        "labrador": "c1ae0e612d5accd9e7d9d1c264951c1afe949c83",
        "quadratic_patch_sha256": "93939b981d7b0dff72cdb3b123dabde98ab7abbeeda62eacffa961780c8c75e1",
        "public": "one-root-512-u8",
        "dimension": 512, "arity": 2, "depth": depth, "paths": paths,
        "ring_q": (1 << 38) - 107, "ring_n": 256, "zk": True,
        "wire": "LZM1-le16-le32-coefficient-arrays-XZ",
    }
    canonical = json.dumps(record, separators=(",", ":"), sort_keys=True).encode("ascii")
    return hashlib.sha256(canonical).digest()


def encode(profile, root, proof):
    if len(root) != ROOT_BYTES or not 4 <= len(proof) <= LIMIT or not proof.startswith(b"LZM1"):
        raise ValueError("membership frame fields")
    return HEADER.pack(MAGIC, GEOMETRY[profile][0], descriptor(profile), len(proof)) + root + proof


def decode(profile, frame):
    if not HEADER.size + ROOT_BYTES + 4 <= len(frame) <= HEADER.size + ROOT_BYTES + LIMIT:
        raise ValueError("membership frame size")
    magic, ident, registration, size = HEADER.unpack_from(frame)
    if (magic, ident, registration) != (MAGIC, GEOMETRY[profile][0], descriptor(profile)):
        raise ValueError("unapproved membership descriptor")
    off = HEADER.size + ROOT_BYTES
    if len(frame) != off + size or not frame[off:].startswith(b"LZM1"):
        raise ValueError("membership proof boundary")
    return frame[HEADER.size:off], frame[off:]


if __name__ == "__main__":
    profile, directory = sys.argv[1:]
    dest = Path(directory)
    packet = encode(profile, (dest/"root.bin").read_bytes(), (dest/"proof.lzm").read_bytes())
    with (dest/"membership.bin").open("xb") as stream:
        stream.write(packet)
