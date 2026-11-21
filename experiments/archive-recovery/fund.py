"""Fund the original offline recipient on both sides of the scheduled proof upgrade."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
UPGRADE = HERE.parent / "funded-upgrade"
SWAP = HERE.parent / "atomic-swap"
OWNERS = ("miner-a", "miner-b", "alice", "bob", "forward", "conflict", "offline")


def module(label, path):
    spec = importlib.util.spec_from_file_location(label, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path)
    args = parser.parse_args()
    home = args.original.resolve()
    if home.stat().st_mode & 0o077 or not (home / "public/PREFIX.json").is_file():
        parser.error("select the private home after mining the released funded-upgrade A prefix")
    # The released walkthrough resolves its lab from argv when it is imported.
    sys.argv[1] = str(home)
    upgrade = module("funded_walkthrough", UPGRADE / "walkthrough.py")
    upgrade.switch(home)
    w = module("atomic_walkthrough", SWAP / "walkthrough.py")
    from upgrade_scenario import included, need, swap, transfer
    w.r.update(json.loads((w.PUBLIC / "PREFIX.json").read_bytes()))
    fixed, managed = (w.r["asset_ids"][k] for k in ("fixed", "managed"))
    try:
        w.lab.start(manual=True)
        need(w.agree("abc") == w.r["tips"]["common"], "wrong A prefix on upgraded peers")
        for owner in OWNERS:
            if owner not in ("offline", "conflict"):
                w.cmd("backup", owner, w.BACKUPS / owner)
        w.cmd("export-address", "forward", w.N / "forward.addr")
        address = "@" + str(w.N / "offline.addr")
        packet = transfer(w, "b", "fund-offline-b", "miner-b", address, 14, managed, 16)
        included(w, "b", packet)
        w.agree("abc")
        packet = swap(w, "b", fixed, managed)
        included(w, "b", packet)
        w.agree("abc")
        # Never query the offline recipient during funding or full-node observations.
        controls = tuple(owner for owner in OWNERS if owner != "offline")
        fork = w.snapshot("fork", "c", controls)
        need(fork["height"] == 14, "signed swap missed the fork point")
        w.ordinary("branch-mint", ("mint", "miner-b", "forward", managed, 7), "b")
        w.lab.mine("a", 9)
        w.agree("abc")
        current = w.snapshot("initial", "c", controls)
        need(current["height"] == 24 and current["fees"] == 27, "unexpected funded-chain economics")
        need(w.r["registries"]["initial"][managed]["supply"] == 107 and
             w.r["registries"]["fork"][managed]["supply"] == 100, "branch-specific issuer effects")
        need({f.name for f in w.lab.walletdir("offline").iterdir()} == {"seed", "address"},
             "offline recipient unexpectedly started scanning")
        need(sum(row["native"] for row in w.r["balances"]["initial"].values()) + 34 == current["issued"],
             "funded control wallets do not reconcile native supply")
        need(sum(row["assets"].get(managed, 0) for row in w.r["balances"]["initial"].values()) + 28 == 107,
             "funded control wallets do not reconcile managed supply")
        w.r["fixture"] = dict(offline_A=dict(native=20, managed=12), offline_B=dict(native=14, managed=16),
                              requested_payment=dict(native=28, managed=25, fee=3))
        upgrade.save(w.PUBLIC / "SCENARIO.json", w.r)
        print(json.dumps({"ready": current["tip"], "height": current["height"], "fork": fork["tip"]}))
    except BaseException:
        w.lab.stop()
        raise


if __name__ == "__main__":
    main()
