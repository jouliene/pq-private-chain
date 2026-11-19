"""Build the devnet wallet and original APV2 verifiers using the locked APV2 compiler driver."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
BASE = HERE.parents[1] / "experiments/advancing-payments/crypto"
PROFILE = "af88a0ac0caa5f0aa27d38d687b6cc39495a0aa2659ed4a7e5e74653724cc1b1"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("upstream", "target", "output"):
        p.add_argument(name, type=lambda x: Path(x).resolve())
    args = p.parse_args()
    base_receipt = BASE.parent/"evidence/BUILD.json"
    if sha(base_receipt) != "68f711df34467ffd3a9025cd716a6b79ea2dc19094d78ec21e87f4e73c0ec852":
        raise ValueError("incorrect APV2 baseline build receipt")
    dev_inputs = {name: sha(HERE/name) for name in ("build.py","wallet.rs")}
    manifest = json.loads(base_receipt.read_bytes())["sources_sha256"]
    for path, expected in manifest.items():
        if sha(BASE/path) != expected:
            raise ValueError("registered APV2 build input changed: " + path)
    with tempfile.TemporaryDirectory(prefix="pq-dev-build-") as tmp:
        dest = Path(tmp)
        for rel in manifest:
            fp = dest/rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(BASE/rel, fp)
        main_rs = dest/"src/main.rs"
        replacement = "        b'C' => wallet::reward_note(body)?.commitment(),\n        b'H' => header(body)?.block_hash(),"
        original = "        b'H' => header(body)?.block_hash(),"
        source = main_rs.read_text()
        if source.count(original) != 1:
            raise ValueError("hash role preimage")
        main_rs.write_text(source.replace(original,replacement))
        shutil.copyfile(HERE/"wallet.rs", dest/"src/wallet.rs")
        command = [sys.executable,"-IB",str(dest/"build.py"),str(args.upstream),str(args.target),str(args.output)]
        record = json.loads(subprocess.check_output(command))
    if (dev_inputs != {name: sha(HERE/name) for name in dev_inputs}
            or record["sources_sha256"]["src/wallet.rs"] != dev_inputs["wallet.rs"]
            or sha(args.output) != record["binary_sha256"]):
        raise ValueError("devnet build inputs changed during compilation")
    record.update(registered_profile_sha256=PROFILE, base_build_sha256=sha(base_receipt), devnet_overlay_sha256=dev_inputs)
    print(json.dumps(record,sort_keys=True,indent=2))


if __name__ == "__main__":
    main()
