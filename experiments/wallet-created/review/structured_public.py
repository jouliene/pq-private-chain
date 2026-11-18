"""Verify published WHIR payment bodies in a namespace containing only public inputs."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def verify(binary, binary_sha, directory, genesis_sha):
    if sha(binary.read_bytes()) != binary_sha:
        raise ValueError("wrong installed verifier")
    genesis = (directory / "genesis.bin").read_bytes()
    if sha(genesis) != genesis_sha or len(genesis) != 296 or genesis[:8] != b"WGEN0001":
        raise ValueError("wrong approved genesis")
    chain = genesis[8:40]
    report = []
    spent = set()
    with tempfile.TemporaryDirectory() as temp:
        public = Path(temp)
        for n in (1, 2, 3):
            body = (directory / f"payment{n}.body").read_bytes()
            hdr = (b"WHPAY001" + (1).to_bytes(2, "little") + (528).to_bytes(2, "little")
                   + (len(body) - 4876).to_bytes(4, "little") + bytes(4))
            if not 4876 < len(body) <= 272556 or body[:20] != hdr:
                raise ValueError("wrong body version or framing")
            s, proof = body[20:548], body[4876:]
            if s[:16] != b"CP-P2-03\x03\x00\x02\x02\x01\x00\x00\x00" or s[16:48] != chain:
                raise ValueError("wrong CP03 statement context")
            nullifiers = {s[80:144], s[144:208]}
            if len(nullifiers) != 2 or nullifiers & spent:
                raise ValueError("conflicting public nullifiers")
            spent.update(nullifiers)
            if (int.from_bytes(s[336:344], "little") != 2112248 or
                    int.from_bytes(s[408:416], "little") != 2*n or any(s[416:432])):
                raise ValueError("fee, occurrence count or external flow mismatch")
            (public / f"s{n}").write_bytes(s)
            (public / f"p{n}").write_bytes(proof)
            report.append({"body_sha256": sha(body), "body_bytes": len(body),
                           "proof_sha256": sha(proof), "proof_bytes": len(proof)})
        # Change only the public inputs of the cryptographic verifier. Receipt or
        # preliminary ledger checks cannot cause these negative results.
        (public / "extra").write_bytes((public / "p1").read_bytes() + b"\x00")
        sandbox = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--clearenv",
                   "--cap-drop", "ALL", "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib",
                   "--symlink", "usr/lib64", "/lib64", "--dev", "/dev", "--proc", "/proc",
                   "--ro-bind", str(public), "/inputs", "--ro-bind", str(binary), "/verify",
                   "--remount-ro", "/", "--chdir", "/inputs", "--", "/verify"]
        def run(*argv):
            return subprocess.run(sandbox + list(argv), stdin=subprocess.DEVNULL,
                                  capture_output=True, timeout=60)
        good = run("verify-many", "s1", "p1", "s2", "p2", "s3", "p3")
        good.check_returncode()
        checks = json.loads(good.stdout)
        if len(checks["records"]) != 3 or not all(item["accepted"] for item in checks["records"]):
            raise ValueError("incomplete verifier output")
        for statement, proof in (("s1", "p2"), ("s1", "extra")):
            bad = run("verify", statement, proof)
            if bad.returncode == 0 or b"CFW rejection at" not in bad.stderr:
                raise ValueError("control did not reach and reject in the compiled verifier")
    return {"binary_sha256": binary_sha, "approved_genesis_sha256": genesis_sha, "payments": report,
            "distinct_nullifiers": len(spent), "public_replay": checks,
            "valid_second_proof_wrong_first_statement_rejected": True, "trailing_proof_byte_rejected": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("binary_sha")
    parser.add_argument("with_bodies", type=Path)
    parser.add_argument("genesis_sha")
    args = parser.parse_args()
    print(json.dumps(verify(args.binary.resolve(strict=True), args.binary_sha, args.with_bodies,
                            args.genesis_sha), indent=2))
