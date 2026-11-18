"""Measure the size of the registered AIR after a concrete sparse R1CS lowering."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import common

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", required=True, type=Path)
    parser.add_argument("--approve-installation", required=True)
    parser.add_argument("--measure-matrix", action="store_true")
    parser.add_argument("--first-row", action="store_true")
    args = parser.parse_args()
    inst = common.load_installation(args.installation, args.approve_installation)
    assert Path(inst["repository"]) == ROOT
    libs = Path(inst["workspace"]) / "target/release/deps"
    source = Path(inst["source_root"])
    rustc = inst["toolchain"]["tools"]["rustc"]
    assert common.sha(rustc["path"]) == rustc["sha256"]
    with tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / "lower"
        command = [rustc["path"], "--edition", "2024", "-O", "-Dwarnings", str(HERE / "lower.rs"),
                   "-L", f"dependency={libs}", "-o", str(binary)]
        for alias, name in [("compact_arity_v3", "compact_bounded_arity_v3"), *[(n, n) for n in
                            ("p3_air", "p3_field", "p3_goldilocks", "serde_json", "tiny_keccak", "libc", "p3_dft", "p3_matrix")]]:
            artifact, = libs.glob(f"lib{name}-*.rlib")
            command.extend(["--extern", f"{alias}={artifact}"])
        subprocess.run(command, check=True)
        if args.first_row:
            print(json.dumps(json.loads(subprocess.check_output([str(binary), "--first-row"])), indent=2, sort_keys=True))
            return
        if args.measure_matrix:
            statements = ROOT / "experiments/payment-size/evidence/three-payments"
            sample_paths = [statements / f"sample{i}.statement" for i in range(1,4)]
            out = subprocess.check_output([str(binary), *map(str, sample_paths)])
            print(json.dumps(json.loads(out), indent=2, sort_keys=True))
            return
        reference = source / "experiments/compact-all-payments-v3/reference.py"
        spec = importlib.util.spec_from_file_location("dimension_public_fixture", reference)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        bundle, _ = module.linked()
        assert hashlib.sha256(module.canonical(bundle)).hexdigest() == "9d8dde618ce9ce60579d23549f552ff104ccfb8023a5fbdee0fbb1dfa8c95a95"
        result = json.loads(subprocess.check_output([str(binary)], input=module.canonical(bundle["fixtures"][2])))
    base = result["ordinary"]
    n = base["base_inputs"]
    result["extension_with_base_constraints"] = {
        "rows": base["rows"] + 64*n, "private": base["private"] + 63*n,
        "public": base["public"], "nnz_abc": [k+64*n for k in base["nnz_abc"]]}
    print(json.dumps(result, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
