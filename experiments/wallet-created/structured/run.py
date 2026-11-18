"""Compile a public-only driver using the registered lowering and frozen matrix oracle."""
import argparse
import hashlib
import json
import os
import platform
import resource
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DIMS = ROOT / "experiments/node-validation/dimensions"
sys.path.insert(0, str(ROOT / "scripts"))
import common


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--approve-installation", required=True)
    parser.add_argument("--repeat", type=int, default=2)
    args = parser.parse_args()
    assert 1 <= args.repeat <= 5
    installation = common.load_installation(args.installation, args.approve_installation)
    assert Path(installation["repository"]) == ROOT
    compiler = installation["toolchain"]["tools"]["rustc"]
    assert sha(Path(compiler["path"])) == compiler["sha256"]
    libs = Path(installation["workspace"]) / "target/release/deps"
    statement_dir = ROOT / "experiments/payment-size/evidence/three-payments"
    paths = [statement_dir / f"sample{i}.statement" for i in (1, 2, 3)]
    raw = (DIMS / "lower.rs").read_text()
    cutoff = raw.index("        let runs: Vec<_> = paths")
    oracle = (DIMS / "matrix.rs").read_text()
    before = 'json!({"basis_and_contract_seconds"'
    assert oracle.count(before) == 1
    oracle = oracle.replace(before, 'json!({"public_and_fold_shake256_32":digest_outputs(&form[..50],&private[..active]),"basis_and_contract_seconds"')
    with tempfile.TemporaryDirectory() as temp:
        tmp = Path(temp)
        (tmp / "lower.rs").write_text(raw[:cutoff] + """
        let build_plan = std::time::Instant::now();
        let plan = matrix.plan();
        let build_s = build_plan.elapsed().as_secs_f64();
        let mut records = Vec::new();
        for (i, p) in paths.iter().enumerate() {
            let data = std::fs::read(p).unwrap();
            let (reference, candidate) = if i%2==0 {
                (matrix.measure(&data),plan.eval(&data))
            } else {
                let v=plan.eval(&data);
                (matrix.measure(&data),v)
            };
            assert_eq!(reference["public_and_fold_shake256_32"],candidate["public_and_fold_shake256_32"]);
            records.push(json!({"statement":std::path::Path::new(p).file_name().unwrap().to_str().unwrap(), "reference":reference,"candidate":candidate}));
        }
        println!("{}",json!({"matrix_prep_wall_s":prep,"plan_prep_wall_s":build_s,"counts":plan.counts(),"paired_runs":records}));
        return;
    }
    panic!("public statements required");
}
""")
        (tmp / "fft.rs").write_bytes((DIMS / "fft.rs").read_bytes())
        (tmp / "matrix.rs").write_text(oracle + "\n" + (HERE / "plan.rs").read_text())
        binary = tmp / "probe"
        command = [compiler["path"], "--edition", "2024", "-O", str(tmp / "lower.rs"),
                   "-L", f"dependency={libs}", "-o", str(binary)]
        linked = {}
        for name in ("compact_bounded_arity_v3", "p3_air", "p3_field", "p3_goldilocks", "serde_json", "tiny_keccak", "libc", "p3_dft", "p3_matrix"):
            artifact, = libs.glob(f"lib{name}-*.rlib")
            linked[artifact.name] = sha(artifact)
            alias = "compact_arity_v3" if name == "compact_bounded_arity_v3" else name
            command += ["--extern", f"{alias}={artifact}"]
        subprocess.run(command, check=True)
        timing = tmp / "time"
        result = json.loads(subprocess.check_output(["/usr/bin/time", "-f", "%U %S %e %M", "-o", str(timing), str(binary), *paths * args.repeat]))
        user, system, wall, rss = timing.read_text().split()
        result.update(process={"user_s":float(user), "system_s":float(system), "wall_s":float(wall), "maxrss_kib":int(rss)},
                      affinity=sorted(os.sched_getaffinity(0)), kernel=platform.release(),install_sha256=args.approve_installation,
                      rustc=compiler,rlib_sha256=linked, oracle_source_sha256=sha(DIMS/"matrix.rs"),
                      lowering_sha256=sha(DIMS/"lower.rs"), statements_sha256=[sha(p) for p in paths])
        frozen = json.loads((DIMS/"MATRIX.json").read_text())["runs"]
        for i, entry in enumerate(result["paired_runs"]):
            assert entry["reference"]["combined_form_hex"] == frozen[i%3]["combined_form_hex"]
        print(json.dumps(result,indent=2,sort_keys=True))


if __name__ == "__main__":
    main()
