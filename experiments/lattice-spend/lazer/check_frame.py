"""Cheap negative framing checks for the fully registered fixture formats."""
from pathlib import Path
import sys
from frame import GEOMETRY, HEADER, decode, encode


def check(public):
    for profile in GEOMETRY:
        sample = (public/f"{profile}.bin").read_bytes()
        root, proof = decode(profile, sample)
        if encode(profile, root, proof) != sample:
            raise RuntimeError("fixture re-encoding changed")
        other = next(x for x in GEOMETRY if x != profile)
        wrong_digest = bytearray(sample)
        wrong_digest[5] ^= 1
        wrong_length = bytearray(sample)
        wrong_length[HEADER.size-1] ^= 1
        for name, body in ((other, sample), (profile, wrong_digest), (profile, wrong_length),
                           (profile, sample[:-1]), (profile, sample+b"\x00")):
            try:
                decode(name, body)
            except ValueError:
                continue
            raise AssertionError("invalid public framing accepted")
    print("accepted two registered frames; rejected ten descriptor/length mutations")


if __name__ == "__main__":
    check(Path(sys.argv[1]))
