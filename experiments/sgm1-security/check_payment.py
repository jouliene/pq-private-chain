"""Check the funding-bound EAR1 transcript against the baseline and an equal-length field mutation."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent


def main(directory):
    wire = (directory / "payment.bin").read_bytes()
    pin = hashlib.sha256((directory / "prefix" / "genesis.bin").read_bytes()).hexdigest()
    original = HERE.parent / "structured-keccak" / "harness" / "payment_role.py"
    experimental = HERE / "early_degree.py"
    def verify(role, packet):
        return subprocess.run([sys.executable, "-B", role, "verify", directory/"prefix", pin, packet, "unused"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if verify(experimental, directory/"payment.bin").returncode:
        raise ValueError("public EAR1 verification failed")
    with tempfile.TemporaryDirectory() as scratch:
        changed = Path(scratch) / "changed.bin"
        tampered = bytearray(wire)
        tampered[3990+64] ^= 1
        changed.write_bytes(tampered)
        r = verify(experimental, changed)
        checks = ("ring trace projection", "mixed linear constraints", "mixed Merkle opening",
                  "mixed Q opening", "explicit degree opening")
        allowed = {f"EAR1 payment rejected: {check} rejected" for check in checks}
        if r.returncode != 1 or r.stderr.decode().strip() not in allowed:
            raise ValueError("equal-length degree message mutation survived or verifier failed")
        # Present the new proof to the prior registration with its own magic.
        # The unchanged old proof extent check must still reject this suite.
        changed.write_bytes(b"SGM1"+wire[4:])
        baseline = verify(original, changed)
        if baseline.returncode != 1 or b"funded packet length rejected" not in baseline.stderr:
            raise ValueError("EAR1 proof is not separated from the old registration")
    print(json.dumps(dict(positive=True, degree_mutation_rejected=True, old_suite_rejects=True,
                          mutation_reason=r.stderr.decode().strip()),indent=2))

if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
