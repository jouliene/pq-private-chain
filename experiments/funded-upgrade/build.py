"""Build the two research FRI-32 roles against the original funded note relation."""
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
SOURCES = {"managed": ("managed-assets", "MNG1", "MNG2"),
           "swap": ("atomic-swap", "SLG1", "SLG2")}


def build(work, upstream, target):
    for kind, (experiment, old, new) in SOURCES.items():
        spec = importlib.util.spec_from_file_location(kind + "_build", HERE.parent / experiment / "native/build.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)

        def configure(dest):
            registry = dest / "registry.rs"
            s = builder.direct.replace_once(registry.read_text(), "num_query_rounds = 26", "num_query_rounds = 32")
            registry.write_text(s.replace(old, new))
            codec = dest / "codec.rs"
            codec.write_text(codec.read_text().replace(old, new))
            main = dest / "main.rs"
            if kind == "managed":
                # B is dedicated to the registered transfer relation. The original node
                # separately verifies every historical AST1 and MNG1 issuance packet.
                s = main.read_text()
                start = s.index("                let (selected, magic)")
                end = s.index("                let p = packet(bytes, magic)?;", start)
                s = s[:start] + '                let (selected, magic) = (&verifier, b"MNG2");\n' + s[end:]
                s = s.replace('            let ast1 = legacy::registered()?;\n', '').replace('mod legacy;\n', '')
                main.write_text(s)
        root = work / kind
        builder.prepare(root, upstream, target, configure)
        subprocess.run([root / "native", "register", root / "registered"], check=True,
                       env=dict(os.environ, RAYON_NUM_THREADS="2"))
        vk = root / "registered" / (kind + ".vk")
        pin = HERE / "registry" / vk.name
        if pin.read_bytes() != vk.read_bytes():
            raise ValueError("regenerated key differs from registration " + kind)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("work", "upstream", "target"):
        p.add_argument(name, type=Path)
    a = p.parse_args()
    build(a.work.resolve(), a.upstream.resolve(), a.target.resolve())
