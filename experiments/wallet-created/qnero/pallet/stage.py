"""Install two test-only overlays in a separate pinned Qnero checkout."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
upstream = Path(sys.argv[1]).resolve()
pin = "f04c91307837c0231668383bec76ba98d89d2652"
assert subprocess.check_output(["git", "-C", upstream, "rev-parse", "HEAD"], text=True).strip() == pin
wallet = (HERE.parent / "comparative_wallet.rs").read_text()
marker = '    fs::write(public.join("anchor.bin"), anchor)?;'
assert wallet.count(marker) == 1
export = '''    let raw = chain.header_at(&anchor)?;
    let mut fields = Vec::new();
    fields.extend(hex::decode(raw.parent_hash.trim_start_matches("0x"))?);
    fields.extend(raw.block_number()?.to_le_bytes());
    for value in [&raw.state_root, &raw.extrinsics_root, &raw.zk_tree_root] {
        fields.extend(hex::decode(value.trim_start_matches("0x"))?);
    }
    fields.extend(raw.digest_bytes()?);
    fs::write(public.join("anchor-fields.bin"), fields)?;
    fs::write(public.join("funding-inner.bin"), funding.inner().to_bytes())?;
    fs::write(public.join("funding-commitment.bin"), funding.commitment().to_bytes())?;
    fs::write(public.join("real-slot-nullifiers.bin"), payment.nullifiers.concat())?;'''
wallet = wallet.replace(marker, marker + "\n" + export)
dest = upstream / "crates/qnero-wallet/tests/dispatch_inputs.rs"
dest.write_text(wallet)
lib = "chain/pallets/shielded/src/lib.rs"
base = subprocess.check_output(["git", "-C", upstream, "show", f"HEAD:{lib}"])
edited = base + b"\n#[cfg(test)]\nmod anchored_wallet_replay;\n"
assert (upstream / lib).read_bytes() in (base, edited)
(upstream / lib).write_bytes(edited)
shutil.copyfile(HERE / "anchored_wallet_replay.rs", upstream / "chain/pallets/shielded/src/anchored_wallet_replay.rs")
for path in [dest, upstream / lib, upstream / "chain/pallets/shielded/src/anchored_wallet_replay.rs"]:
    print(hashlib.sha256(path.read_bytes()).hexdigest(), path.relative_to(upstream))
