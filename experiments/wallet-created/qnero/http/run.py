"""Measure actual wallet HTTP and serialize one canonical notification and block."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "pallet"))
from run import run

q, dest = [Path(arg).resolve() for arg in sys.argv[1:]]
dest.mkdir(parents=True, exist_ok=False)
public = dest / "public"
public.mkdir()
env = dict(os.environ, RAYON_NUM_THREADS="4")
run([sys.executable, HERE / "stage.py", q], q, dest/"stage", env)
tracked = subprocess.check_output(["git", "-C", q, "diff", "HEAD", "--name-only"], text=True)
assert not tracked
def hashes():
    return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in
            (q/"Cargo.lock", q/"crates/qnero-wallet/tests/metered_send.rs",
             q/"crates/qnero-wallet/tests/meter_support/mod.rs", HERE/"run.py", HERE/"stage.py")}
ids = hashes()
with tempfile.TemporaryDirectory(prefix="qnero-http-", dir="/dev/shm") as private:
    run(["rustup", "run", "1.93.0", "cargo", "test", "--locked", "--offline", "--release", "-j2",
         "-p", "qnero-wallet", "--features","parallel","--test", "metered_send", "--",
         "--exact","ordinary_wallet_payment"], q, dest/"wallet",
        dict(env, QNERO_PRIVATE=private, QNERO_PUBLIC=str(public)))
assert ids == hashes() and "1 passed; 0 failed" in (dest/"wallet.log").read_text()
data = json.loads((public/"wallet.json").read_text())
phases = ["funding_sync","prepare_reads","submit","receive_from_public_history","seed_only_recovery"]
for field, value in data["functional_traffic_all_roles"].items():
    assert sum(data[phase][field] for phase in phases) == value
ext = (public / "payment.scale").read_bytes()
notification = (public/"transaction-notification.scale").read_bytes()
assert notification == b"\x04" + ext and len(ext) == data["extrinsic_bytes"]
block = (public/"fixture-block.scale").read_bytes()
assert block[data["fixture_block_header_bytes"]:] == notification
result = {"git":subprocess.check_output(["git","-C",q,"rev-parse","HEAD"],text=True).strip(),
          "source_pins":{Path(k).name if Path(k).name != "mod.rs" else "meter_support/mod.rs":v for k,v in ids.items()},
          "public":{p.name:{"bytes":p.stat().st_size, "sha256":hashlib.sha256(p.read_bytes()).hexdigest()}
                    for p in sorted(public.iterdir())}, "wallet":data}
(dest/"measurement.json").write_text(json.dumps(result, indent=2) + "\n")
