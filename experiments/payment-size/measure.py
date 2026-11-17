"""Compare three independently generated ordinary 2x2 bodies using fresh public-only processes."""
import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("psize_common", ROOT / "scripts/common.py")
common = importlib.util.module_from_spec(spec)
sys.dont_write_bytecode = True
spec.loader.exec_module(common)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resources(proc):
    return {k: proc[k] for k in ("process_exit", "wall_seconds", "user_seconds", "system_seconds", "maxrss_kib")}


def closure(binary):
    # Only locally built, operator-approved executables reach ldd.
    result = subprocess.run(["/usr/bin/ldd", str(binary)], check=True, capture_output=True,
                            env=common.controlled_env(), text=True)
    paths = []
    for line in result.stdout.splitlines():
        if "linux-vdso" in line:
            continue
        match = re.fullmatch(r"\s*(?:[^ ]+ => )?(/[^ ]+) \(0x[0-9a-f]+\)\s*", line)
        common.need(match is not None, "resolved ELF runtime closure")
        paths.append(Path(match[1]))
    common.need(bool(paths), "dynamic runtime expected")
    return paths


def isolated(binary, files, args, pins):
    argv = ["/usr/bin/bwrap", "--unshare-all", "--die-with-parent", "--new-session",
            "--cap-drop", "ALL", "--clearenv", "--setenv", "LANG", "C", "--proc", "/proc",
            "--dev", "/dev", "--dir", "/inputs", "--ro-bind", str(binary), "/program"]
    timer = Path("/usr/bin/time")
    argv.extend(["--ro-bind", str(timer), "/meter"])
    deps = sorted(set(closure(binary) + closure(timer)))
    for dep in deps:
        actual = str(dep.resolve())
        common.need(actual in pins and pins[actual] == digest(dep), "approved verifier runtime " + actual)
        argv.extend(["--ro-bind", actual, str(dep)])
    for name, path in files.items():
        argv.extend(["--ro-bind", str(path.resolve(strict=True)), "/inputs/" + name])
    argv.extend(["--remount-ro", "/", "--chdir", "/", "--", "/meter", "-f", "worker %U %S %M", "/program", *args])
    proc, output, err = common.run(argv, cwd=ROOT, seconds=60, cap=256 * 1024)
    meter = re.fullmatch(rb"worker ([0-9]+\.[0-9]+) ([0-9]+\.[0-9]+) ([0-9]+)\n", err)
    common.need(proc["wrapper_exit"] == proc["process_exit"] == 0 and meter is not None, "isolated public verification: " + err.decode(errors="replace")[:400])
    worker = dict(user_seconds=float(meter[1]), system_seconds=float(meter[2]), maxrss_kib=int(meter[3]),
                  clock_resolution_seconds=0.01, wall_seconds_including_namespace=proc["wall_seconds"],
                  meter_sha256=digest(timer), scope="GNU time inside namespace waits on the verifier process")
    common.need(worker["maxrss_kib"] > 0, "worker RSS observed")
    return json.loads(output), worker, {str(p): digest(p) for p in deps}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--installation", type=Path, required=True)
    ap.add_argument("--approve-installation", required=True)
    ap.add_argument("--candidate", type=Path, required=True)
    ap.add_argument("--approve-candidate", required=True)
    ap.add_argument("--samples", nargs=3, required=True)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    candidate = a.candidate.resolve(strict=True)
    common.need(digest(candidate) == a.approve_candidate, "candidate identity")
    inst = common.load_installation(a.installation, a.approve_installation)
    workspace, source = Path(inst["workspace"]), Path(inst["source_root"])
    baseline = workspace / "target/release/compact-all-payments-v3"
    common.need(inst["pins"].get(str(baseline)) == digest(baseline), "baseline identity")
    output = a.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    common.need(len(set(a.samples)) == 3, "three distinct private cycles")
    for index, label in enumerate(a.samples, 1):
        common.need(re.fullmatch(r"[a-z][a-z0-9_-]{0,31}",label), "private cycle label")
        cycle = source / "experiments/cp03-private-cycle/evidence" / (label + ".public")
        body = cycle / "payer2x2.body"
        approved = common.read_json(workspace / ("private-" + label + ".json"))
        common.need(approved["passed"] and approved["source_runtime_unchanged"] and approved["result"]["private_credit_payment_receipt"], "fresh admitted source payment")
        base_dir = source / "experiments/compact-all-payments-v3"
        prover_name = "cp03-cycle-" + label + "-payer"
        original = base_dir / "public" / prover_name
        parent_path = base_dir / "evidence" / (prover_name + ".json")
        parent, manifest = common.read_json(parent_path), common.read_json(original / "manifest.json")
        assoc = common.read_json(cycle / "cycle-public-artifacts.json")["artifacts"][1]
        for name, path in (("body",body),("parent_receipt",parent_path),("proof",original/"proof.bin"),("statement",original/"statement.bin")):
            common.need(assoc[name]["sha256"] == digest(path), "wallet cycle artifact association")
        raw = body.read_bytes()
        common.need(len(raw) == 4876 + manifest["envelope_bytes"] and raw[4876:] == (original / "proof.bin").read_bytes()
                    and raw[20:548] == (original / "statement.bin").read_bytes() and manifest["arity"] == 2, "exact complete source body")
        common.need(parent["wrapper_exit"] == parent["process_exit"] == 0 and parent["source_pins_unchanged"]
                    and parent["runtime_pins_unchanged"] and not parent["private_input_written_or_hashed"]
                    and manifest["genuine_proof_created"], "genuine fresh worker")
        compact = output / f"sample{index}.body"
        pack_proc, encoded, err = common.run([str(candidate), "pack", str(body), str(compact)],
                     cwd=ROOT, seconds=60, cap=256 * 1024)
        common.need(pack_proc["wrapper_exit"] == pack_proc["process_exit"] == 0 and not err, "pack")
        pack = json.loads(encoded)
        check, verify_proc, deps = isolated(candidate, {"payment":compact}, ["verify","/inputs/payment"], inst["pins"])
        legacy, legacy_proc, base_deps = isolated(baseline, {n:original/n for n in ("proof.bin","statement.bin")}, ["valid-public","/inputs"], inst["pins"])
        common.need(pack["legacy_body_roundtrip_checked"] and check["accepted"] and legacy["valid"]["accepted"] and
                    check["legacy_body_sha256"] == digest(body) and check["candidate_body_bytes"] == compact.stat().st_size, "exact real verification")
        rows.append(dict(label=label, chain=raw[36:68].hex(), statement_sha256=digest(original/"statement.bin"),
            proof_sha256=digest(original/"proof.bin"), body_sha256=digest(body), candidate_sha256=digest(compact),
            source_body_bytes=len(raw), source_proof_bytes=len(raw)-4876, candidate_body_bytes=compact.stat().st_size,
            candidate_proof_bytes=compact.stat().st_size-4876, reference_prover={k:parent[k] for k in
            ("child_wall_seconds","wait4_user_seconds","wait4_system_seconds","wait4_maxrss_kib")},
            reference_prover_stages={k:v for k,v in manifest.items() if k.endswith("_seconds")}, pack=pack, pack_process=resources(pack_proc),
            public_verify=check, public_verify_process=verify_proc, verifier_libraries=deps,
            baseline_public_check=legacy["valid"], baseline_preparation_seconds=legacy["preparation_seconds"],
            baseline_public_verify_process=legacy_proc, baseline_libraries=base_deps))
    for k in ["chain","statement_sha256","proof_sha256","candidate_sha256"]:
        common.need(len({r[k] for r in rows}) == 3, "independent samples: " + k)
    common.load_installation(a.installation, a.approve_installation)
    common.need(digest(candidate) == a.approve_candidate, "candidate post-pin")
    common.save(output/"RESULT.json", dict(passed=True, installation_sha256=a.approve_installation,
        candidate_binary_sha256=a.approve_candidate, candidate_binary_bytes=candidate.stat().st_size,
        baseline_binary_bytes=baseline.stat().st_size, dependency_bytes={p:Path(p).stat().st_size for p in deps},
        bwrap_sha256=digest(Path("/usr/bin/bwrap")), rows=rows,
        scope="One complete payment per file. All auxiliaries rebuilt locally from pinned program. Fresh namespace with selected public bytes, executable and its pinned ELF libraries only. Verifier CPU/RSS from GNU time inside the namespace, outer elapsed includes namespace startup. Prover and pack wait4 are direct workers. Source payment generation and candidate encoding are sequential."))
    print(json.dumps([r["candidate_body_bytes"] for r in rows]))


if __name__ == "__main__":
    main()
