"""Check the same canonical wire shape against two independently registered public verifier roles."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from parameters import dimensions, parse_packet, EXPERIMENTS, ARCHIVE
from wire import Role


def check(direct_build, token_build, token_packet):
    direct_keys = EXPERIMENTS / "payment-architecture/direct/registry"
    token_keys = HERE / "candidate/registry"
    direct = (ARCHIVE / "evidence/successor/payment.bin").read_bytes()
    token = token_packet.read_bytes()
    if token.startswith(b"TKN1BLK1"):
        # The independent ledger replay verifies PoW, parent, genesis and roots.
        # Here the version-1 block only frames the one public proof under test.
        length = int.from_bytes(token[172:176], "little")
        if len(token) != 176 + length + 8:
            raise ValueError("invalid framed TKN1 block")
        token = token[176:-8]
    assert direct[:4] == b"DLF1" and token[:4] == b"TKN1"
    # Ignore only the external four-byte suite tag for this structural check.
    # Walk each canonical inner proof, through its 26 public words and two receipts.
    direct_dims = dimensions((direct_keys / "direct.vk").read_bytes())
    token_dims = dimensions((token_keys / "token.vk").read_bytes())
    for packet in (direct, token):
        for layout in (direct_dims, token_dims):
            parse_packet(b"DLF1" + packet[4:], layout)
    observed = {}
    for name, build, keys, tag, own, other in (
        ("DLF1", direct_build, direct_keys, b"DLF1", direct, token),
        ("TKN1", token_build, token_keys, b"TKN1", token, direct),
    ):
        approved = json.loads((build / "BUILD.json").read_bytes())["binary_sha256"]
        role = Role(build / "native", approved, ["verify", "/keys"], keys)
        try:
            success = role.call(own)
            foreign = role.call(tag + other[4:])
            if len(success) != 3757 or success[:1] != b"1" or foreign != b"0":
                raise ValueError(f"{name} cross-key control failed")
            role.close()
        finally:
            role.abort()
        observed[name] = dict(accepted_own=True, rejected_reframed_other=True,
                              public_packet_sha256=hashlib.sha256(own).hexdigest(),
                              packet_B=len(own), raw_proof_B=int.from_bytes(own[5:9], "little"))
    return observed


if __name__ == "__main__":
    if not __debug__:
        sys.exit("Use without -O for canonical layout checks.")
    ap = argparse.ArgumentParser(description=__doc__)
    for arg in ("direct_build", "token_build", "token_packet"):
        ap.add_argument(arg, type=Path)
    print(json.dumps(check(**vars(ap.parse_args())), sort_keys=True, indent=2))
