"""Generate three funded wallet-created proofs and independently replay the public files."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import common
sys.path.insert(0, str(HERE))
from bridge import libraries


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--installation", type=Path, required=True)
    ap.add_argument("--approve-installation", required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--candidate", type=Path)
    ap.add_argument("--approve-candidate")
    ap.add_argument("--public-genesis", help="Independent public-only replay of an existing output, with this approved genesis SHA256")
    args = ap.parse_args()
    inst = common.load_installation(args.installation, args.approve_installation)
    binary = (args.candidate or Path(inst["workspace"]) / "target/release/compact-all-payments-v3").resolve(strict=True)
    expected = args.approve_candidate if args.candidate else inst["pins"][str(binary)]
    common.need(common.sha(binary) == expected, "approved backend")
    output = args.output.resolve()
    if not args.public_genesis:
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
    pins = {}
    for path in set(libraries(binary) + libraries(Path("/usr/bin/time"))):
        real = str(path.resolve(strict=True))
        common.need(inst["pins"].get(real) == common.sha(real), "runtime dependency pin")
        pins[real] = common.sha(real)
    config = dict(backend="whir" if args.candidate else "reference", binary=str(binary), binary_sha256=expected,
                  libraries=pins, source_root=inst["source_root"], output=str(output), python=sys.executable,
                  bridge=str(HERE / "bridge.py"), helper_sha256=inst["helper_sha256"])
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        local = Path(tmp) / "config.json"
        local.write_text(json.dumps(config))
        env = common.controlled_env()
        proc_args = [inst["node"], "--disable-sigusr1", str(HERE / "cycle.mjs"), str(local)]
        def execute(mode, extra=()):
            ret = subprocess.run([*proc_args, mode, *extra], env=env, capture_output=True, timeout=3600)
            if ret.returncode or ret.stderr:
                stage = ret.stderr.strip()
                allowed = {b"wallet cycle failed at "+k for k in (b"prove",b"verify",b"receive",b"initialization")}
                raise ValueError("wallet cycle failed at " + (stage.decode() if stage in allowed else mode))
            return json.loads(ret.stdout)
        if args.public_genesis:
            raw = execute("replay", [args.public_genesis])
            print(json.dumps(raw, indent=2))
            return
        generated = execute("generate")
        replay = execute("replay", [generated["genesis_sha256"]])
        common.need(replay["spent"] == 6 and replay["leaves"] == 8 and replay["fees"] == str(3*2112248)
                    and len(replay["controls"]) == 12 and len(generated["produced"]) == 3,
                    "public replay and funded wallet cycle")
        common.hashes(inst["pins"])
        evidence = dict(installation_sha256=args.approve_installation, backend_sha256=expected,
                        generated=generated, public_replay=replay,
                        files={p.name:dict(bytes=p.stat().st_size,sha256=common.sha(p))
                               for p in sorted(output.iterdir()) if p.is_file()})
        common.save(output / "RESULT.json", evidence)
        print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    main()
