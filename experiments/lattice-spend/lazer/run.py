"""Run independent LaZer roles, save the public fixture and bounded measurements."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import shutil


def main():
    p = argparse.ArgumentParser()
    p.add_argument("build", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--sde", type=Path, help="Intel SDE executable for Tiger Lake emulation")
    p.add_argument("--cpu", type=int)
    p.add_argument("--profile", choices=("stock64", "shared40", "both"), default="both")
    p.add_argument("--replay", type=Path, help="directory containing approved stock64.bin and shared40.bin")
    p.add_argument("--positive-only", action="store_true", help="run the positive roles only")
    args = p.parse_args()
    base = args.build.resolve()
    out = args.output.resolve()
    out.mkdir()
    profiles = ("stock64", "shared40") if args.profile == "both" else (args.profile,)
    results = {"execution": "Intel SDE -tgl" if args.sde else "native",
               "membership_only": True, "transcript": (base/"profile").read_text().strip(), "runs": {}}
    env = {**os.environ, "PYTHONPATH": f"{base}/pydeps:.:..", "OPENBLAS_NUM_THREADS": "1",
           "LD_LIBRARY_PATH": str(base/"lazer"), "FIXTURE_ARRAYS": str(base/"arrays.so")}
    prefix = ["/usr/bin/time", "-f", "METER %e %U %S %M"]
    if args.cpu is not None:
        prefix += ["taskset", "-c", str(args.cpu)]
    if args.sde:
        prefix += [str(args.sde.resolve()), "-tgl", "--"]
    if results["transcript"] == "stock":
        if args.replay or args.profile == "shared40":
            p.error("stock supports only the original Table 3 one-path in-process run")
        log = out / "upstream.log"
        cmd = prefix + ["/usr/bin/python3", "-Bu", str(Path(__file__).with_name("benchmark.py").resolve()), "upstream"]
        with log.open("wb") as f:
            subprocess.run(cmd, cwd=base/"lazer/python/succinct_zkp", env=env,
                           stdout=f, stderr=subprocess.STDOUT, check=True)
        raw = log.read_text()
        info = json.loads(re.search(r"^UPSTREAM (.+)$",raw,re.M)[1])
        info["upstream_estimate_rounded_KiB"] = float(re.search(r"Estimated proof size: ([\d.]+)KB",raw)[1])
        info["whole_process_meter"] = re.search(r"^METER (.+)$",raw,re.M)[1]
        results["runs"]["original_author_function"] = info
        (out/"metrics.json").write_text(json.dumps(results, indent=2)+"\n")
        print(json.dumps(info))
        return
    if results["transcript"] != "canonical-quadratic-v1":
        p.error("unregistered build profile")
    for profile in profiles:
        dest = out / profile
        dest.mkdir()
        results["runs"][profile] = {}
        modes = [] if args.replay else ["prove"]
        if args.replay:
            shutil.copyfile(args.replay.resolve()/f"{profile}.bin", dest/"membership.bin")
        modes += ["verify"] if args.positive_only else ["verify", "wrong-root", "changed-proof"]
        for mode in modes:
            log = dest / f"{mode}.log"
            cmd = prefix + ["/usr/bin/python3", "-Bu", str(Path(__file__).with_name("benchmark.py").resolve()),
                            mode, profile, str(dest)]
            with log.open("wb") as f:
                subprocess.run(cmd, cwd=base/"lazer/python/succinct_zkp", env=env,
                               stdout=f, stderr=subprocess.STDOUT, check=True)
            result = parse(log)
            results["runs"][profile][mode] = result
            print(json.dumps(result), flush=True)
            (out/"metrics.json").write_text(json.dumps(results,indent=2)+"\n")


def parse(path):
    log = path.read_text()
    result = json.loads(re.search(r"^METRICS (.+)$", log, re.M)[1])
    meter = re.search(r"^METER (\S+) (\S+) (\S+) (\d+)$", log, re.M)
    result["whole_process"] = dict(zip(("wall_s","user_s","sys_s","peak_RSS_KiB"),
                                        [float(x) for x in meter.groups()[:3]]+[int(meter[4])]))
    estimate = re.search(r"Estimated proof size: ([\d.]+)KB",log)
    result["upstream_estimate_rounded_KiB"] = float(estimate[1])
    return result


if __name__ == "__main__":
    main()
