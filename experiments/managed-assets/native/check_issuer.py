"""Exercise the public signature verifier and seed-restored issuer in disposable RAM storage."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from managed_ops import authorization_digest


def frame(message):
    return len(message).to_bytes(4, "little") + message


def invoke(binary, args, requests):
    out = subprocess.run([binary, *args], input=b"".join(frame(m) for m in [*requests, b""]),
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True,
                         env=dict(os.environ, RAYON_NUM_THREADS="2"), timeout=60).stdout
    replies = []
    while out:
        size = int.from_bytes(out[:4], "little")
        if len(out) < size + 4:
            raise ValueError("truncated role reply")
        replies.append(out[4:4+size])
        out = out[4+size:]
    return replies


def run(build):
    binary = build / "native"
    keys = build / "registered"
    with tempfile.TemporaryDirectory(dir="/dev/shm") as tmp:
        home = Path(tmp)
        wallet = ["wallet", keys, home / "issuer"]
        address, public_key = invoke(binary, [*wallet, "create"], [b"J"])
        _, unrelated = invoke(binary, ["wallet", keys, home / "other", "create"], [b"J"])
        network = os.urandom(32)
        # Isolate the signature primitive. The payload names a synthetic inner digest
        # and receives no payment approval. Full packets go through the live node.
        inner = os.urandom(32)
        msg = authorization_digest(inner, "register", network, public_key, 0, bytes(32))
        changed = authorization_digest(inner, "register", sha256(network).digest(),
                                       public_key, 0, bytes(32))
        restored, restored_key, sig, again, bad_j, bad_l = invoke(
            binary, [*wallet, "restore"], [b"J", b"L"+msg, b"L"+msg, b"Jx", b"L"])
        if (len(address) != 1601 or address != restored or len(public_key) != 32
                or restored_key != public_key or unrelated == public_key or len(sig) != 17088
                or again != sig or (bad_j,bad_l) != (b"0", b"0")):
            raise ValueError("issuer role identity/signature")
        altered = bytearray(sig)
        altered[-1] ^= 1
        valid = b"V"+public_key+msg+sig
        replies = invoke(binary, ["verify", keys], [
            valid, b"V"+unrelated+msg+sig, b"V"+public_key+changed+sig,
            b"V"+public_key+msg+altered, valid[:-1], valid+b"x",
        ])
        if replies != [b"1", b"0", b"0", b"0", b"0", b"0"]:
            raise ValueError("unexpected public signature verdict")
    return {"scheme": "SLH-DSA-SHAKE-128f", "public_key_bytes":32, "signature_bytes":17088,
            "restore_same_key":True, "repeat_same_signature":True, "public_verify":True,
            "wrong_key":False, "wrong_network_digest":False, "changed_signature":False,
            "short_request":False, "trailing_byte":False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    print(json.dumps(run(parser.parse_args().build.resolve()), sort_keys=True))
