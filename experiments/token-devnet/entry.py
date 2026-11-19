"""Launch the ordinary operator CLI on a separately staged live TKN1 PoW network."""
import argparse
import fcntl
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from stage import ROOT, build_runtime, sha, stage


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=ROOT / ".work/live-token-devnet")
    parser.add_argument("--build", type=Path, help="existing source-built live wallet roles")
    parser.add_argument("--approve-native-sha", help="operator binary pin for an existing build")
    parser.add_argument("command", choices=("start", "status", "stop", "create", "export-address", "backup",
                                            "restore", "balance", "send", "resume", "intents", "mine", "walkthrough"))
    parser.add_argument("args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if bool(args.build) != bool(args.approve_native_sha):
        parser.error("--build and --approve-native-sha must be supplied together")
    home = args.home.resolve()
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    if home.stat().st_mode & 0o077:
        parser.error("--home needs private mode 0700")
    deployed = home / "deployment"
    with (home / ".installation.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not deployed.exists():
            if args.command not in ("start", "walkthrough"):
                parser.error("start the token network before using its wallet")
            if args.build:
                build, approved = args.build.resolve(), args.approve_native_sha
            else:
                # Each new build uses a new target and checks the exact source/key pins.
                import tempfile
                tmp = Path(tempfile.mkdtemp(dir=home, prefix="source-build-"))
                build = build_runtime(tmp / "build")
                approved = sha(build / "native")
            stage(home, build, approved)
        elif args.build and (deployed / "devnet/approved-native.sha256").read_text().strip() != args.approve_native_sha:
            parser.error("binary approval differs from the existing deployment")
    if args.command == "walkthrough":
        if args.args:
            parser.error("walkthrough takes no extra arguments")
        args2 = [HERE / "walkthrough.py", home]
    else:
        args2 = [deployed / "devnet/cli.py", "--home", home, args.command, *args.args]
    os.execv(sys.executable, [sys.executable, "-IB", *map(str, args2)])


if __name__ == "__main__":
    main()
