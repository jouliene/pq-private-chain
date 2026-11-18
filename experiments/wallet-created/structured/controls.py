"""Exercise malformed semantic assignments before PCS and corrupt actual public proofs."""
import argparse
import copy
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import common


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--installation", type=Path, required=True)
    p.add_argument("--approve-installation", required=True)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--public-payments", type=Path, required=True)
    a = p.parse_args()
    install = common.load_installation(a.installation, a.approve_installation)
    assert Path(install["repository"]) == ROOT
    source = Path(install["source_root"])/"experiments/compact-all-payments-v3/reference.py"
    spec = importlib.util.spec_from_file_location("registered_fixture", source)
    ref = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ref)
    bundle, _ = ref.linked()
    assert hashlib.sha256(ref.canonical(bundle)).hexdigest() == "9d8dde618ce9ce60579d23549f552ff104ccfb8023a5fbdee0fbb1dfa8c95a95"
    original = bundle["fixtures"][2]
    binary = a.binary.resolve()
    rows = []
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        statement = temp/"statement"
        proof = temp/"proof"

        def rejected(name, mode, info, payload=None):
            start = time.monotonic()
            r = subprocess.run([binary, mode, statement, proof], input=payload or b"",
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            elapsed = time.monotonic()-start
            rejection = re.fullmatch(rb"CFW rejection at ([A-Za-z0-9_.]+:[0-9]+)\n", r.stderr)
            assert r.returncode != 0 and not r.stdout and rejection, name
            rows.append(dict(case=name, mode=mode, reference_predicates=info,
                             check_location=rejection[1].decode(), exit_code=r.returncode, wall_s=elapsed))

        for case in ("changed ownership key with matching nullifier", "changed second sibling",
                     "second input index equals count", "altered public nullifier",
                     "increased output amount with matching commitment"):
            w = copy.deepcopy(original["witness"])
            s = ref.r.parse(bytes.fromhex(original["statement_hex"]))
            chain = bytes(s["chain"])
            if case.startswith("changed ownership"):
                note = w["inputs"][0]
                note["key"][0] ^= 1
                cm = ref.r.h(chain, 2, note["note"])
                s["nullifiers"][0] = ref.r.h(chain, 3, note["key"] + note["origin"] + cm)
            elif case.startswith("changed second"):
                w["inputs"][1]["siblings"][0][0] ^= 1
            elif case.startswith("second input"):
                s["count"] = w["inputs"][1]["index"]
            elif case.startswith("altered"):
                s["nullifiers"][1][0] ^= 1
            else:
                w["outputs"][0][1] += 1
                s["commitments"][0] = ref.r.h(chain, 2, w["outputs"][0])
            errors = ref.r.relation(s, w)
            assert len(errors) == 1, (case, errors)
            data = ref.r.encode(s)
            statement.write_bytes(data)
            rejected(case, "prove", errors, ref.canonical(dict(statement_hex=data.hex(), witness=w)))
            assert not proof.exists()

        signed = (a.public_payments/"payment1.statement").read_bytes()
        good = (a.public_payments/"payment1.proof").read_bytes()
        wrong = bytearray(signed)
        wrong[48] ^= 1  # A valid statement with a different nonce, outside the 49 projected words.
        for name, public, edited in [
            ("different canonical statement nonce", wrong, good),
            ("last authenticated frontier hash", signed, good[:-1]+bytes([good[-1]^1])),
            ("short proof", signed, good[:-1]),
            ("trailing proof", signed, good+b"!"),
            ("noncanonical outer EF5", signed, good[:64]+bytes([255])*8+good[72:]),
        ]:
            statement.write_bytes(public)
            proof.write_bytes(edited)
            rejected(name, "verify", [])
    print(json.dumps(dict(binary_sha256=common.sha(binary), proof_sha256=hashlib.sha256(good).hexdigest(),
                          statement_sha256=hashlib.sha256(signed).hexdigest(), rejected=rows), indent=2))


if __name__ == "__main__":
    main()
