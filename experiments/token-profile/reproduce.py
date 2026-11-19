"""Build source-approved reference and typed verifiers, then replay or produce complete TKN1 payments."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
CANDIDATE = HERE / "candidate"
DIRECT = HERE.parent / "payment-architecture/direct"


def run(script, *args, capture=False):
    cmd = [sys.executable, "-IB", script, *map(str, args)]
    return subprocess.run(cmd, check=True, stdout=subprocess.PIPE if capture else None).stdout


def reproduce(work, public_only):
    os.umask(0o077)
    work.mkdir(parents=True, exist_ok=False)
    run(HERE / "parameters.py", "--check")
    direct, token = work / "direct", work / "token"
    run(DIRECT / "build.py", direct)
    run(CANDIDATE / "build.py", token, direct / "upstream", direct / "target")
    builds = ((direct, "direct.vk", DIRECT / "registry", DIRECT / "REGISTER.json"),
              (token, "token.vk", CANDIDATE / "registry", CANDIDATE / "evidence/REGISTER.json"))
    for build, vk, pinned, spec in builds:
        keys = build / "registered"
        registration = json.loads(subprocess.check_output([build / "native", "register", keys]))
        if registration != json.loads(spec.read_bytes()) or (keys / vk).read_bytes() != (pinned / vk).read_bytes():
            raise ValueError("source-derived verification key or dimensions differ from registration")
    expected_build = json.loads((CANDIDATE / "evidence/BUILD.json").read_bytes())
    actual_build = json.loads((token / "BUILD.json").read_bytes())
    for key in ("upstream", "lock_sha256", "generated_sources", "registration_design_sha256"):
        if actual_build[key] != expected_build[key]:
            raise ValueError(f"source correspondence failed at {key}")
    public = CANDIDATE / "evidence"
    receipt = json.loads((public / "RESULT.json").read_bytes())
    observed = run(CANDIDATE / "campaign.py", "replay", token, public,
                   "--approve-genesis", receipt["genesis_sha256"], capture=True)
    if json.loads(observed)["state_hash"] != receipt["public_replay"]["state_hash"]:
        raise ValueError("independent public replay differs from author endpoint")
    (work / "PUBLIC_REPLAY.json").write_bytes(observed)
    if not public_only:
        public = work / "fresh-payments"
        run(CANDIDATE / "campaign.py", "generate", token, public)
    observed = run(HERE / "cross_keys.py", direct, token, public / "blocks/1.bin", capture=True)
    (work / "CROSS_KEYS.json").write_bytes(observed)
    print(f"Public replay and cross-key controls passed. Results in {work}", flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("new_work_directory", type=Path)
    p.add_argument("--public-only", action="store_true", help="replay the committed public payments without any seed")
    args = p.parse_args()
    reproduce(args.new_work_directory.resolve(), args.public_only)
