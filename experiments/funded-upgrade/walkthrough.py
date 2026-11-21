"""Mine an A-funded public history, then exercise the B upgrade on that exact network."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
SWAP = HERE.parent / "atomic-swap"
sys.path[:0] = [str(SWAP), str(HERE)]


def require(ok, message):
    if not ok:
        raise ValueError(message)


def install(home, managed, swap):
    import stage as released
    require(not (home / "deployment").exists(), "deployment already exists")
    if managed is None and swap is None:
        builds = released.build(home)
    else:
        require(managed is not None and swap is not None, "specify both local builds")
        builds = (managed, released.sha(managed / "native"), swap, released.sha(swap / "native"))
    released.install(home, *builds)


def save(path, record):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def fund(w):
    require(not (w.HOME / "network.json").exists(), "fund needs an unused network")
    require(not (w.HOME / "deployment/devnet/b-managed.vk").exists(), "fund with the released A-only installation")
    for name in ("blocks", "packets", "controls"):
        (w.PUBLIC / name).mkdir(parents=True)
    w.N.mkdir(mode=0o700)
    w.BACKUPS.mkdir(mode=0o700)
    w.lab.start(manual=True)
    for owner in ("alice", "bob", "offline", "conflict", "forward", "recipient", "rival"):
        w.cmd("create", owner)
    for owner in ("alice", "bob", "offline"):
        w.cmd("export-address", owner, w.N / (owner + ".addr"))
    for owner in ("offline", "conflict"):
        w.cmd("backup", owner, w.BACKUPS / owner)
        require((w.BACKUPS / owner).stat().st_size == 32, "backup width differs")
    for node in "ab":
        w.lab.mine(node, 3)
        w.agree("abc")
    fixed = w.ordinary("issue-fixed", ("issue", "miner-a", 80))["asset_id"]
    managed = w.ordinary("register-managed", ("register", "miner-b", 100), "b")["asset_id"]
    w.ordinary("fund-fixed", ("send", "miner-a", "alice", 40, fixed, 30))
    w.ordinary("fund-managed", ("send", "miner-b", "bob", 24, managed, 50), "b")
    w.ordinary("fund-conflict", ("send", "miner-a", "conflict", 20, "native", 0))
    w.ordinary("fund-offline", ("send", "miner-b", "@" + str(w.N / "offline.addr"), 20, managed, 12), "b")
    # Do not start or query the offline receiver after its pre-funding backup.
    st = w.snapshot("common", "c", ("alice", "bob", "conflict"))
    require(st["height"] == 12 and st["fees"] == 18, "wrong preactivation history")
    require(w.r["balances"]["common"] == {"alice": dict(native=40, assets={fixed: 30}),
                "bob": dict(native=24, assets={managed: 50}), "conflict": dict(native=20, assets={})},
            "funded recipient balance mismatch")
    w.r["asset_ids"] = dict(fixed=fixed, managed=managed)
    save(w.PUBLIC / "PREFIX.json", w.r)


def switch(home):
    dev = home / "deployment"
    archived, new = home / "deployment-a", home / "deployment-next"
    require((new / "devnet/b-managed.vk").is_file() and not archived.exists(), "stage a fresh upgrade first")
    sys.path.insert(0, str(dev / "devnet"))
    from transport import control
    require(all(not control(home, n).exists() for n in "abcd"), "stop the A peers before installation")
    dev.rename(archived)
    try:
        new.rename(dev)
    except OSError:
        archived.rename(dev)
        raise


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("home", type=Path)
    p.add_argument("phase", choices=("install", "fund", "activate"))
    p.add_argument("--managed-build", type=Path)
    p.add_argument("--swap-build", type=Path)
    a = p.parse_args()
    home = a.home.resolve()
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(home.is_dir() and not home.stat().st_mode & 0o077, "use a private 0700 home")
    with (home / ".upgrade-walkthrough.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if a.phase == "install":
            install(home, a.managed_build, a.swap_build)
            return
        # The historical operator harness reads the lab home from the first argument.
        sys.argv[1] = str(home)
        if a.phase == "activate":
            switch(home)
        import walkthrough as w
        try:
            if a.phase == "fund":
                fund(w)
            else:
                from upgrade_scenario import activate
                activate(w)
        finally:
            if (home / "network.json").exists():
                w.lab.stop()


if __name__ == "__main__":
    main()
