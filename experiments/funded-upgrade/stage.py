"""Install the scheduled rules in a fresh deployment copied from trusted local A software."""
import argparse
from hashlib import sha256
import json
import importlib.util
from pathlib import Path
import shutil
import tempfile

HERE = Path(__file__).resolve().parent


def replace(text, before, after):
    if text.count(before) != 1:
        raise ValueError("wrong baseline source for " + before)
    return text.replace(before, after)


def patch(dev):
    for name in ("managed_ops", "swap_wire"):
        (dev / (name + ".py")).rename(dev / (name + "_a.py"))
        shutil.copyfile(HERE / (name + ".py"), dev / (name + ".py"))
    original = (dev / "swap_wire_a.py").read_text()
    for old, new in (("SWF1", "SWF2"), ("SWB1", "SWB2"), ("SLG1", "SLG2"), ("SWP1", "SWP2")):
        original = original.replace(old, new)
    (dev / "swap_wire_b.py").write_text(original)
    shutil.copyfile(HERE / "upgrade_rules.py", dev / "upgrade_rules.py")

    path = dev / "chain.py"
    s = replace(path.read_text(), 'INELIGIBLE = {', 'INELIGIBLE = {"inactive proof suite",')
    s = replace(s, 'slot, = self.backend.verify(g[0])', 'slot, = self.verify_single(g[0],height)')
    s = replace(s, 'verify_pair(g,self.swap_verifier(),NETWORK,height)', 'self.verify_swap(g,height)')
    s = replace(s, 'slots = self.backend.verify(packet)', 'slots = self.verify_single(packet,head["h"]+1)')
    s = replace(s, 'packet.startswith(b"SWB1")', 'packet.startswith((b"SWB1",b"SWB2"))')
    s = replace(s, 'class Chain(SwapSupport,ManagedChain):', 'from upgrade_rules import UpgradeSupport\n\n'
                'class Chain(UpgradeSupport,SwapSupport,ManagedChain):')
    path.write_text(s)
    path = dev / "swap_ledger.py"
    s = replace(path.read_text(), 'verify_pair(group,self.swap_verifier(),NETWORK,head["h"]+1)',
                'self.verify_swap(group,head["h"]+1)')
    s = s.replace("from swap_wire import BUNDLE, FRAME,", "from swap_wire import BUNDLES, FRAMES,")
    s = s.replace("startswith(BUNDLE)", "startswith(BUNDLES)").replace("startswith(FRAME)", "startswith(FRAMES)")
    path.write_text(s)
    path = dev / "managed_ledger.py"
    s = replace(path.read_text(), 'verify_pair(packets[base:base+2],self.swap_verifier(),NETWORK,hit["h"])',
                'self.verify_swap(packets[base:base+2],hit["h"])')
    s = s.replace("from swap_wire import FRAME, read_frame", "from swap_wire import FRAMES, read_frame")
    s = s.replace("startswith(FRAME)", "startswith(FRAMES)")
    s = replace(s, 'slot, = self.backend.verify(packet)', 'slot, = self.verify_single(packet,hit["h"])')
    path.write_text(s)


def install(a, builds, dest):
    if dest.exists():
        raise ValueError("use a new upgrade destination")
    digest = lambda p: sha256(p.read_bytes()).hexdigest()
    expected = json.loads((HERE / "registry/sources.json").read_bytes())
    with tempfile.TemporaryDirectory(dir=dest.parent) as tmp:
        stage = Path(tmp) / "deployment"
        stage.mkdir()
        # Rebuild the public rules and wallet policy from the reviewed checkout;
        # existing operators supply only the explicitly approved A binary/key pairs.
        spec = importlib.util.spec_from_file_location("atomic_stage", HERE.parent / "atomic-swap/stage.py")
        legacy_stage = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(legacy_stage)
        dev = legacy_stage.install_sources(stage)
        for kind, prefix in (("managed", ""), ("swap", "swap-")):
            keyname = kind + ".vk"
            legacy = HERE.parent / ("managed-assets" if kind == "managed" else "atomic-swap") / "native/registry"
            a_key = a / (prefix + "keys") / keyname
            a_binary = a / (prefix + "runtime") / "native"
            if (legacy / keyname).read_bytes() != a_key.read_bytes() or (a / "devnet" / keyname).read_bytes() != a_key.read_bytes():
                raise ValueError("unapproved historical key " + kind)
            a_pin = a / "devnet" / ("approved-" + prefix + "native.sha256")
            if a_pin.read_text().strip() != digest(a_binary):
                raise ValueError("historical binary differs from its operator approval")
            for src in (a_key, a_binary):
                target = stage / src.relative_to(a)
                target.parent.mkdir()
                shutil.copy2(src, target)
            shutil.copyfile(a_pin, dev / a_pin.name)
            shutil.copyfile(a_key, dev / keyname)
            build = builds / kind
            record = json.loads((build / "BUILD.json").read_bytes())
            approved = record["binary_sha256"]
            if any(record[k] != v for k, v in expected[kind].items()) or digest(build / "native") != approved:
                raise ValueError("unapproved generated source or build " + kind)
            vk = HERE / "registry" / keyname
            if vk.read_bytes() != (build / "registered" / keyname).read_bytes():
                raise ValueError("unapproved B " + kind + " registration")
            label = "b-" + prefix
            runtime = stage / (label + "runtime")
            keys = stage / (label + "keys")
            runtime.mkdir()
            keys.mkdir()
            shutil.copy2(build / "native", runtime / "native")
            shutil.copyfile(vk, keys / keyname)
            shutil.copyfile(vk, dev / ("b-" + keyname))
            (dev / ("approved-" + label + "native.sha256")).write_text(approved + "\n")
        patch(dev)
        spec = importlib.util.spec_from_file_location("wallet_stage", HERE / "wallet_stage.py")
        wallet_stage = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(wallet_stage)
        wallet_stage.apply(dev)
        for source in stage.rglob("*.py"):
            compile(source.read_bytes(), str(source), "exec")
        stage.rename(dest)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("a", "builds", "dest"):
        p.add_argument(name, type=Path)
    args = p.parse_args()
    install(args.a.resolve(strict=True), args.builds.resolve(strict=True), args.dest.resolve())
