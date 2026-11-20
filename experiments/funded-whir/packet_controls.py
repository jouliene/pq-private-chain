"""Run fresh, public-only proof checks and distinguish cryptographic from packet rejection."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent/"wallet-created/wallet"))
from bridge import libraries
sys.path.insert(0, str(HERE))
from packet import split


def sandbox(binary):
    cmd = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
           "--clearenv", "--ro-bind", str(binary), "/verify"]
    for lib in libraries(binary):
        cmd.extend(["--ro-bind", str(lib.resolve(strict=True)), str(lib)])
    return cmd


def run(binary, directory, matrices):
    cmd = sandbox(binary)
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp)/"packet"
        a, b = split((directory/"candidate.swap").read_bytes())
        specimens = [("ordinary","MNG1",31,(directory/"ordinary.candidate").read_bytes()),
                     ("leg-a","SLG1",34,a.leg), ("leg-b","SLG1",34,b.leg),
                     ("onward","MNG1",31,(directory/"onward.candidate").read_bytes())]
        for name, suite, n, original in specimens:
            proof_start = 9+8*n
            proof_end = len(original)-3584
            matrix = matrices/f"{suite}.r1cs"
            # Alter canonical field elements or hash bytes; keep every length valid.
            # A Fiat-Shamir mismatch reaches sumcheck; the final sibling must reach a Merkle check.
            tests = [("fresh_public_verification", None, None), ("changed_anchor_low_bit", 9, "outer.rs"),
                     ("changed_first_oracle_root", proof_start, "outer.rs"),
                     ("changed_terminal_authentication", proof_end-1, "oracle.rs"),
                     ("changed_first_receipt", proof_end, "main.rs")]
            if suite == "SLG1":
                tests.append(("changed_ephemeral_key",9+26*8, "outer.rs"))
            else:
                tests.append(("unauthorized_supply_delta",9+30*8, "main.rs"))
            for label, offset, expect in tests:
                raw = bytearray(original)
                if offset is not None:
                    raw[offset] ^= 1
                path.write_bytes(raw)
                check = subprocess.run([*cmd, "--ro-bind", str(matrix), "/matrix",
                                        "--ro-bind", str(path), "/packet", "--remount-ro", "/",
                                        "--chdir", "/", "--", "/verify", "verify", suite, "/matrix", "/packet"],
                                       capture_output=True, timeout=30)
                if expect is None:
                    if check.returncode:
                        raise RuntimeError(f"{name}: public verification failed")
                elif not check.returncode or expect not in check.stderr.decode():
                    raise RuntimeError(f"{name}: wrong result or rejection layer for {label}")
                results.append(dict(specimen=name, control=label,
                                    outcome="accepted" if expect is None else "rejected",
                                    module=expect))
    return results


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("public", type=Path)
    p.add_argument("matrices", type=Path)
    a = p.parse_args()
    print(json.dumps(run(a.binary.resolve(strict=True), a.public.resolve(strict=True),
                         a.matrices.resolve(strict=True)), indent=2))
