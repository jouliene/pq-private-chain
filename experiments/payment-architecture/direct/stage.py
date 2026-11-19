"""Create an isolated experimental PoW network with DLF1 as its sole accepted payment suite."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from build import HERE, ROOT, REV, native_sources, replace_once, sha
from deployment import PROFILE, checked_keys

OLD = "af88a0ac0caa5f0aa27d38d687b6cc39495a0aa2659ed4a7e5e74653724cc1b1"
MODS = ["chain","cli","history","intents","node","transport","wallet","wallet_sync"]
AP = ROOT/"experiments/advancing-payments"
def stage(work, native_sha):
    record=json.loads((work/"BUILD.json").read_bytes())
    with tempfile.TemporaryDirectory() as tmp:
        p=Path(tmp)
        native_sources(p)
        sources={x.name:sha(x) for x in p.iterdir()}
    if (sources!=record["compiled_sources"] or record["upstream"]!=REV or
        record["lock_sha256"]!="ed076404a8d396ddda4acf9a42a915c54472bb70d3dc58300e262f7ecf152a20" or
        sha(work/"native")!=record["binary_sha256"] or sha(work/"native")!=native_sha):
        raise ValueError("local DLF1 build approval failed")
    new=work/"network"
    new.mkdir()
    dev=new/"devnet"; dev.mkdir()
    for name in MODS:
        shutil.copyfile(ROOT/"devnet"/(name+".py"),dev/(name+".py"))
    native=new/"runtime"; native.mkdir()
    shutil.copy2(work/"native",native/"native")
    shutil.copytree(checked_keys(HERE/"registry"),new/"keys")
    (dev/"approved-native.sha256").write_text(native_sha+"\n")
    shutil.copyfile(HERE/"deployment.py",dev/"runtime.py")
    d=new/"experiments"/"advancing-payments"; d.mkdir(parents=True)
    for name in ("run","state","wire","ingress"):
        shutil.copyfile(AP/(name+".py"),d/(name+".py"))
    bridge=Path("experiments/wallet-created/wallet/bridge.py")
    (new/bridge).parent.mkdir(parents=True)
    shutil.copyfile(ROOT/bridge,new/bridge)
    # The original PoW/state/wallet code pins one suite. Substitute the experimental
    # program identity and keep every chain, effect, ledger and receipt check.
    p=dev/"chain.py";p.write_text(replace_once(p.read_text(),OLD,PROFILE))
    p=dev/"wallet.py";s=p.read_text().replace('b"APV2"','b"DLF1"')
    s=replace_once(s,'PROFILE = "'+OLD+'"','from runtime import PROFILE, checked_keys')
    s=s[:s.index('def checked_keys(')]+s[s.index('def private_directory('):]
    p.write_text(s)
    p=d/"wire.py";s=replace_once(p.read_text(),'b"APV2" and 1 <= raw[4] <= 4','b"DLF1" and raw[4] == 1')
    p.write_text(s)
    p=d/"run.py";s=p.read_text()
    start=s.index('def verify_keys(');end=s.index('def register(',start)
    p.write_text(s[:start]+'''def verify_keys(keys, approved):
    from runtime import PROFILE, checked_keys
    need(approved == PROFILE, "approved direct proof profile")
    checked_keys(keys)
    return {"suite":"DLF1","profile":PROFILE}


'''+s[end:])
    print(new)

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("work",type=Path)
    p.add_argument("--approve-native-sha",required=True)
    args=p.parse_args()
    stage(args.work.resolve(),args.approve_native_sha)
