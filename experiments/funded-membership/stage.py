"""Stage audited A/B historical readers and separately registered prospective C verifiers."""
import argparse
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory

HERE = Path(__file__).resolve().parent


def update(path, edits, dest=None):
    src = path.read_text()
    for old,new in edits:
        if src.count(old) != 1:
            raise ValueError(f"wrong source for {path.name}: {old}")
        src = src.replace(old,new)
    (dest or path).write_text(src)


def patch(dev):
    for source,target in (("consensus.py","consensus.py"),("wallet_c.py","wallet_c.py")):
        shutil.copyfile(HERE/source,dev/target)
    (dev/"managed_ops.py").rename(dev/"managed_ops_ab.py")
    update(dev/"managed_ops_a.py", [('MAGIC = b"MSP1','MAGIC = b"MSP3'),
           ('INNER = b"MNG1','INNER = b"MNG3'),('MNG1/supply-auth','MNG3/supply-auth')],dev/"managed_ops_c.py")
    shutil.copyfile(HERE/"ops_c.py",dev/"managed_ops.py")
    source = (dev/"swap_wire_b.py").read_text()
    for tag in ("SWF","SWB","SLG","SWP"):
        if tag+"2" not in source:
            raise ValueError("swap source version")
        source = source.replace(tag+"2",tag+"3")
    (dev/"swap_wire_c.py").write_text(source)
    update(dev/"swap_wire.py", [("import swap_wire_b as b","import swap_wire_b as b\nimport swap_wire_c as c"),
           *((f"b.{tag})",f"b.{tag}, c.{tag})") for tag in ("LEG","FRAME","BUNDLE")),
           ("return b if data.startswith(tags[1]) else a","return (a,b,c)[tags.index(data[:5])]")])
    update(dev/"chain.py",[("from upgrade_rules import UpgradeSupport","from consensus import MembershipSupport"),
           ("class Chain(UpgradeSupport,","class Chain(MembershipSupport,"),
           ('(b"SWB1",b"SWB2")','(b"SWB1",b"SWB2",b"SWB3")')])
    update(dev/"swap_b_wallet.py", [('b"SLG2','b"SLG3'),
           *((f'b-swap-{x}',f'c-swap-{x}') for x in ("keys","runtime","native.sha256")),
           ('devnet/b-swap.vk','devnet/c-swap.vk'),
           ('    row = raw[1:]','    row = raw[1:-1]'),
           ('len(raw) == 1+172+2*CT+32 and','len(raw) == 1+172+2*CT+33 and 1 <= raw[-1] <= 20 and')],
           dev/"swap_c_wallet.py")
    update(dev/"intents.py",[(' and row["operation"] == "transfer":',':'),
           ('                is_b = attempt["packet"].startswith(b"MSP2")\n                obsolete = next_height < FIRST_B if is_b else next_height >= FIRST_B_ONLY',
            '''                from consensus import FIRST_C
                packet = attempt["packet"]
                if next_height >= FIRST_C or packet.startswith(b"MSP3"):
                    obsolete = packet.startswith(b"MSP3") != (next_height >= FIRST_C)
                elif row["operation"] == "transfer":
                    obsolete = next_height < FIRST_B if packet.startswith(b"MSP2") else next_height >= FIRST_B_ONLY''')])
    (dev/"upgrade_wallet.py").rename(dev/"upgrade_wallet_ab.py")
    shutil.copyfile(HERE/"wallet_entry.py",dev/"upgrade_wallet.py")


def install(a,b,c,dest):
    if dest.exists():
        raise ValueError("use a fresh destination")
    mod = importlib.util.spec_from_file_location("ab_stage",HERE.parent/"funded-upgrade/stage.py")
    ab = importlib.util.module_from_spec(mod)
    mod.loader.exec_module(ab)
    expected = json.loads((HERE/"registry/BUILD.json").read_bytes())
    with TemporaryDirectory(dir=dest.parent) as tmp:
        stage = Path(tmp)/"deployment"
        ab.install(a,b,stage)
        dev = stage/"devnet"
        for kind, label in (("managed","c-"),("swap","c-swap-")):
            build = c/kind
            observed = json.loads((build/"BUILD.json").read_bytes())
            for key in ("upstream","lock_sha256","generated_sources","hardening_patch_sha256","registration_bytes","registration_sha256","role"):
                if observed[key] != expected[kind][key]:
                    raise ValueError("C build pin mismatch: "+key)
            vk = HERE/"registry"/(kind+".vk")
            binary = build/"native"
            identity = sha256(binary.read_bytes()).hexdigest()
            if (identity != observed["binary_sha256"] or vk.read_bytes() != (build/"registered"/vk.name).read_bytes()
                    or sha256(vk.read_bytes()).hexdigest()!=observed["registration_sha256"]):
                raise ValueError("C registration or operator build mismatch")
            runtime,keys = stage/(label+"runtime"),stage/(label+"keys")
            runtime.mkdir()
            keys.mkdir()
            shutil.copy2(binary,runtime/"native")
            shutil.copyfile(vk,keys/vk.name)
            shutil.copyfile(vk,dev/("c-"+vk.name))
            (dev/("approved-"+label+"native.sha256")).write_text(identity+"\n")
        patch(dev)
        for src in stage.rglob("*.py"):
            compile(src.read_bytes(),str(src),"exec")
        stage.rename(dest)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("a","b_builds","c_builds","destination"):
        p.add_argument(name,type=Path)
    v = p.parse_args()
    install(v.a.resolve(strict=True),v.b_builds.resolve(strict=True),v.c_builds.resolve(strict=True),v.destination.resolve())
