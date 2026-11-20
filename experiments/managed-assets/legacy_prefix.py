"""Create and retain a small, genuinely funded prefix from the unmodified AST1 CLI and peers."""
import argparse
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
INTENT = "legacy-fixed-17"
MINERS = ("miner-a", "miner-b")


def need(condition, message):
    if not condition:
        raise ValueError(message)


def save_json(path, data):
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as temp:
        json.dump(data, temp, indent=2, sort_keys=True)
        temp.write("\n")
        temp.flush()
        os.fsync(temp.fileno())
    os.replace(temp.name, path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def retain(path, raw):
    if path.exists():
        need(path.read_bytes() == raw, "retained public object differs from the original AST1 block or packet")
        return
    path.write_bytes(raw)


def load(home):
    record = json.loads((home/"legacy-prefix.json").read_text())
    need(record["height"] == len(record["blocks"]) and record["blocks"][-1] == record["tip"],
         "invalid saved legacy prefix")
    for bid in record["blocks"]:
        path = home/"public/blocks"/(bid+".bin")
        need(sha256(path.read_bytes()).hexdigest() == record["block_sha256"][bid], "saved legacy block bytes changed")
    tx = record["payment"]["tx"]
    need(sha256((home/"public/packets"/(tx+".bin")).read_bytes()).hexdigest() == tx,
         "saved legacy payment packet changed")
    for name in MINERS:
        p = home/"legacy-backups"/(name+".seed")
        need(p.is_file() and not p.is_symlink() and p.stat().st_size == 32 and not p.stat().st_mode & 0o077,
             "missing or unsafe private legacy backup")
    return record


def prepare(home, build=None, approved=None):
    """The fresh default builds the original AST1 roles. Isolate original modules from MNG1 imports."""
    home = Path(home).resolve()
    need(bool(build) == bool(approved), "supply both a built original runtime and its explicit native SHA")
    if not (home/"legacy-prefix.json").exists():
        command = [sys.executable, "-IB", HERE, home, "--worker"]
        if build:
            command.extend(["--build", Path(build).resolve(), "--approve-native-sha", approved])
        subprocess.run(command, check=True)
    return load(home)


def worker(home, build, approved):
    os.umask(0o077)
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    need(not home.stat().st_mode & 0o077, "legacy prefix requires a private lab home")
    with (home/".legacy-prefix.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if (home/"legacy-prefix.json").exists():
            return load(home)
        return generate(home, build, approved)


def generate(home, build, approved):
    legacy = home/"legacy"
    base = [ROOT/"pqd", "assets", "--home", legacy]
    options = ["--build", Path(build).resolve(), "--approve-native-sha", approved] if build else []
    def cmd(*args, timeout=330):
        result = subprocess.run(base+list(args), stdout=subprocess.PIPE, check=True, timeout=timeout)
        return json.loads(result.stdout)
    # Existing partial runs use the same privately owned lab, wallets and intent.
    try:
        cmd(*options, "start", "--manual", timeout=3600)
        sys.path.insert(0, str(legacy/"deployment/devnet"))
        from chain import GENESIS, NETWORK, PROFILE, block_id, decode_block
        from cli import Lab, wait
        lab = Lab(legacy, legacy/"deployment/runtime")
        def common():
            rows = [lab.status(n) for n in "abc"]
            return rows[0] if all((r["tip"], r["height"]) == (rows[0]["tip"], rows[0]["height"]) for r in rows) else None
        def converge():
            return wait(common, bool, "original AST1 peers share tip", 90)
        lab.mining("a", 0)
        lab.mining("b", 0)
        state = converge()
        if not state["height"]:
            lab.mine("a", 1)
            state = converge()
        if state["height"] == 1:
            lab.mine("b", 1)
            converge()
        paid = cmd("issue", "miner-a", "17", "--intent", INTENT, "--node", "a")
        if paid["status"] != "confirmed":
            # Submit to and explicitly mine at the same original validating peer.
            lab.mine("a", 3)
            converge()
            paid = cmd("resume", "miner-a", INTENT, "--node", "a", "--wait", "60")
        need(paid["status"] == "confirmed" and paid["issue_supply"] == paid["token_amount"] == 17 and paid["fee"] == 3,
             "original wallet did not confirm fixed issuance")
        lab.mining("a", 0)
        lab.mining("b", 0)
        state = converge()
        registration = cmd("list", "--node", "c")["assets"][paid["asset_id"]]
        need(registration["tx"] == paid["tx"] and registration["supply"] == 17, "wrong original selected fixed registry")
        if state["height"] < registration["height"] + 2:
            lab.mine("b", registration["height"] + 2 - state["height"])
            state = converge()
        public = home/"public"
        for sub in ("blocks", "packets"):
            (public/sub).mkdir(parents=True, exist_ok=True)
        hashes, blocks, txs = {}, [], []
        parent = GENESIS
        for h in range(1, state["height"] + 1):
            selected = [lab.request(n, "selected", start=h, limit=1)[0][0] for n in "abc"]
            need(len(set(selected)) == 1, "original peers disagree on selected block")
            bid = selected[0]
            raw = lab.request("c", "block", id=bid)[1]
            b = decode_block(raw)
            need(block_id(raw).hex() == bid and b.parent == parent and b.height == h, "original block continuity")
            blocks.append(bid)
            hashes[bid] = sha256(raw).hexdigest()
            retain(public/"blocks"/(bid+".bin"), raw)
            for packet in b.packets:
                tx = sha256(packet).hexdigest()
                need(packet[:5] == b"AST1\x01", "prefix must contain original AST1 packets")
                retain(public/"packets"/(tx+".bin"), packet)
                txs.append(tx)
            parent = bytes.fromhex(bid)
        need(txs == [paid["tx"]] and blocks[-1] == state["tip"], "unexpected original prefix payment set")
        backups = home/"legacy-backups"
        backups.mkdir(mode=0o700, exist_ok=True)
        keys = {}
        for name in MINERS:
            keys[name] = lab.address(name)[1:33].hex()
            p = backups/(name+".seed")
            if not p.exists():
                cmd("backup", name, p)
            else:
                import hmac
                need(not p.is_symlink() and not p.stat().st_mode & 0o077 and
                     hmac.compare_digest(p.read_bytes(), (lab.walletdir(name)/"seed").read_bytes()),
                     "partial original miner backup differs")
        keys_to_publish = ("tx", "amount", "fee", "change", "token_change", "asset_id", "token_amount", "issue_supply",
                           "input_total", "token_input_total", "real_inputs", "packet_B", "prover_cpu_s",
                           "proving_wall_s", "prover_role_peak_rss_KiB", "anchor_height")
        item = {k:paid[k] for k in keys_to_publish}
        record = dict(tip=state["tip"], height=state["height"], network=NETWORK.hex(), genesis=GENESIS.hex(),
                      verifier=PROFILE.hex(), miner_keys=keys, payment=item, blocks=blocks, block_sha256=hashes,
                      inclusion_height=registration["height"], confirmations=state["height"]-registration["height"]+1,
                      observed_nodes=list("abc"), native_issued=state["issued"], fees=state["fees"], fixed_supply=17)
    finally:
        if (legacy/"network.json").is_file():
            cmd("stop", timeout=75)
    save_json(home/"legacy-prefix.json", record)
    return load(home)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("home", type=Path)
    p.add_argument("--build", type=Path)
    p.add_argument("--approve-native-sha")
    p.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = p.parse_args()
    if bool(args.build) != bool(args.approve_native_sha):
        p.error("--build and --approve-native-sha must be supplied together")
    if args.worker:
        worker(args.home.resolve(), args.build, args.approve_native_sha)
    else:
        result = prepare(args.home, args.build, args.approve_native_sha)
        print(json.dumps(dict(height=result["height"], tip=result["tip"], tx=result["payment"]["tx"])))
