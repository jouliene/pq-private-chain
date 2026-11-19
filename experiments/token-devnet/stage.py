"""Install the existing PoW implementation for one explicitly authorized typed founding inventory."""
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BASE = HERE.parent / "advancing-payments"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(BASE))
from policy import VERIFIER, founding_bytes
from wire import Role

REV = "f04c91307837c0231668383bec76ba98d89d2652"
LOCK = "ed076404a8d396ddda4acf9a42a915c54472bb70d3dc58300e262f7ecf152a20"
CANDIDATE = HERE.parent / "token-profile/candidate"


def sha(path):
    return sha256(path.read_bytes()).hexdigest()


def replace(s, old, new):
    if s.count(old) != 1:
        raise ValueError(f"unexpected source for TKN1 network installation: {old[:65]}")
    return s.replace(old, new)


def build_runtime(directory):
    src = directory / "upstream"
    directory.mkdir(parents=True, exist_ok=False)
    subprocess.run(["git", "init", "--quiet", src], check=True)
    subprocess.run(["git", "-C", src, "fetch", "--quiet", "--depth=1",
                    "https://github.com/DigitalGuards/qnero.git", REV], check=True)
    subprocess.run(["git", "-C", src, "checkout", "--quiet", "--detach", REV], check=True)
    out = directory / "roles"
    subprocess.run([sys.executable, "-IB", HERE / "wallet/build.py", out, src, directory / "target"], check=True)
    subprocess.run([out / "native", "register", out / "registered"], check=True)
    return out


def validate_build(build, approved):
    receipt = json.loads((build / "BUILD.json").read_bytes())
    expected = json.loads((CANDIDATE / "evidence/BUILD.json").read_bytes())["generated_sources"]
    expected["crates/qnero-prover/examples/token_pair/wallet.rs"] = sha(HERE / "wallet/wallet.rs")
    if (receipt["upstream"] != REV or receipt["lock_sha256"] != LOCK
            or receipt["generated_sources"] != expected or sha(build / "native") != approved
            or receipt["binary_sha256"] != approved or sha(build / "registered/token.vk") != VERIFIER.hex()):
        raise ValueError("source, executable or verifier identity differs from the local approval")


def chain_source():
    src = (ROOT / "devnet/chain.py").read_text()
    src = replace(src, '"approved APV2 profile"', '"approved TKN1 profile"')
    start, end = src.index("PROFILE = bytes.fromhex"), src.index("\n\ndef packet_vector(")
    src = src[:start] + '''from policy import BLOCK_MAGIC as MAGIC, VERIFIER as PROFILE, TOKEN_SUPPLY, load

NETWORK, GENESIS, FOUNDING_ROW, GENESIS_HEADER = load(
    Path(__file__).resolve().parent, struct.pack("<BBBIQ", BITS, WINDOW, MAX_TX, UNDO, SUBSIDY), digest, canonical)
''' + src[end:]
    src = replace(src, 'genesis_header = ZERO+u32(0)+digest(b"dev-genesis-state",NETWORK)+digest(b"dev-genesis-body",NETWORK)+ZERO',
                  '''genesis_header = GENESIS_HEADER
        cm = backend.hashes.call(b"C" + FOUNDING_ROW[:80])
        need(cm == FOUNDING_ROW[80:], "typed founding commitment")
        genesis_front = Frontier(0, b"", backend.hashes)
        genesis_front.append(cm)
        need(genesis_front.root() == genesis_header[100:], "typed founding root")''')
    src = replace(src, 'genesis_header,0,0,b"",b""))', '''genesis_header,0,1,genesis_front.encode(),b""))
                    self.db.execute("INSERT INTO outs VALUES (0,?,0,NULL,NULL)", (cm,))''')
    src = replace(src, 'b"C"+ctx+pk+u64(reward)', 'b"C"+ctx+pk+u64(reward)+u64(0)')
    return replace(src, 'issued=head["h"]*SUBSIDY,', 'issued=head["h"]*SUBSIDY, token_issued=TOKEN_SUPPLY,')


def install_sources(dest):
    # Only the independently named deployment imports these modules.
    dev = dest / "devnet"
    dev.mkdir()
    for name in ("cli", "node", "history", "intents", "transport", "wallet", "wallet_sync"):
        shutil.copyfile(ROOT / f"devnet/{name}.py", dev / f"{name}.py")
    for name in ("runtime", "policy"):
        shutil.copyfile(HERE / f"{name}.py", dev / f"{name}.py")
    (dev / "chain.py").write_text(chain_source())
    ap = dest / "experiments/advancing-payments"
    ap.mkdir(parents=True)
    for name in ("wire", "run", "state", "ingress"):
        shutil.copyfile(BASE / f"{name}.py", ap / f"{name}.py")
    bridge = Path("experiments/wallet-created/wallet/bridge.py")
    (dest / bridge).parent.mkdir(parents=True)
    shutil.copyfile(ROOT / bridge, dest / bridge)
    wire = ap / "wire.py"
    wire.write_text(replace(wire.read_text(), 'b"APV2" and 1 <= raw[4] <= 4', 'b"TKN1" and raw[4] == 1'))
    rp = ap / "run.py"
    s = rp.read_text()
    start, end = s.index("def verify_keys("), s.index("def register(")
    rp.write_text(s[:start] + '''def verify_keys(keys, approved):
    from runtime import PROFILE, checked_keys
    need(approved == PROFILE, "selected TKN1 profile")
    checked_keys(keys)
    return {"suite": "TKN1", "profile": PROFILE}


''' + s[end:])
    spec = importlib.util.spec_from_file_location("stage_typed_wallet", HERE / "wallet/stage.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.stage_wallet(dev)
    return dev


def stage(home, build, approved):
    validate_build(build, approved)
    target = home / "deployment"
    if target.exists():
        raise ValueError("deployment already exists")
    # A failed bootstrap keeps the founding seed. Retry uses the identical public key.
    founder = home / "wallets/miner-a"
    founder.mkdir(mode=0o700, parents=True, exist_ok=True)
    if founder.is_symlink() or founder.stat().st_mode & 0o077:
        raise ValueError("founding wallet permissions")
    with tempfile.TemporaryDirectory(dir=home, prefix=".bootstrap-") as scratch:
        dest = Path(scratch) / "network"
        dest.mkdir()
        dev = install_sources(dest)
        (dest / "runtime").mkdir()
        shutil.copy2(build / "native", dest / "runtime/native")
        shutil.copytree(build / "registered", dest / "keys")
        (dev / "approved-native.sha256").write_text(approved + "\n")
        mode = "restore" if (founder / "seed").exists() else "create"
        actor = Role(build / "native", approved, ["wallet", "/keys", "/private/seed", mode],
                     dest / "keys", founder)
        try:
            address = actor.get()
            if len(address) != 1601:
                raise ValueError("founding wallet address")
            actor.close()
        finally:
            actor.abort()
        existing = founder / "address"
        if existing.exists() and existing.read_bytes() != address:
            raise ValueError("previous founding address mismatch")
        existing.write_bytes(address)
        hashes = Role(build / "native", approved, ["hash"])
        try:
            raw = founding_bytes(address[1:33], hashes)
            hashes.close()
        finally:
            hashes.abort()
        (dev / "genesis.bin").write_bytes(raw)
        (dev / "approved-genesis.sha256").write_text(sha256(raw).hexdigest() + "\n")
        dest.rename(target)
    return target
