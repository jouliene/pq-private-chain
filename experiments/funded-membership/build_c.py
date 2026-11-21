"""Build and register the exact funded-depth MNG3 and SLG3 verifiers."""
import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROLES = {"managed": ("managed-assets", "MNG1", "MNG3", 31),
         "swap": ("atomic-swap", "SLG1", "SLG3", 34)}
BEFORE = {
    "circuit.rs": "ca9c8a2d98c7c3c3b4a78f7f3dc6c61df9cc21f6cd067a06efef0ac6c279251b",
    "merkle.rs": "9d194e29c812e191f5fd6a40a57a7150a329f76e281c7328c177ee3b4abd50d3",
}


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def replace(source, before, after):
    if source.count(before) != 1:
        raise ValueError("unexpected pinned source near " + before[:80])
    return source.replace(before, after)


def configure(dest, kind):
    _, old, new, words = ROLES[kind]
    tree = dest.parents[3]
    common = tree / "crates/qnero-circuit/src"
    if {name: digest(common / name) for name in BEFORE} != BEFORE:
        raise ValueError("unexpected upstream membership source")
    subprocess.run(["patch", "--batch", "--fuzz=0", "-p1", "-i", HERE / "hardening.patch"],
                   cwd=tree, check=True)
    profile = dest / "registry.rs"
    source = replace(profile.read_text(), "num_query_rounds = 26", "num_query_rounds = 32")
    source = replace(source, "    (\n        b,\n        Targets {",
                     "    b.register_public_input(base.depth);\n"
                     "    let empty_depth = b.is_equal(base.depth, zero);\n"
                     "    b.connect(empty_depth.target, zero);\n    (\n        b,\n        Targets {")
    for fragment in ("num_public_inputs == ", "public_inputs.len() == ", 'public_inputs\\":'):
        source = replace(source, fragment + str(words), fragment + str(words + 1))
    profile.write_text(source.replace(old, new))
    codec = dest / "codec.rs"
    source = replace(codec.read_text(), f"all.len() == {words}", f"all.len() == {words + 1}")
    source = replace(source, "    Ok(out)\n}\n\npub struct Meter",
                     f"    let depth = u8::try_from(all[{words}].to_canonical_u64())?;\n"
                     '    ensure!((1..=20).contains(&depth), "funded anchor depth");\n'
                     "    out.push(depth);\n    Ok(out)\n}\n\npub struct Meter")
    codec.write_text(source.replace(old, new))
    if kind == "managed":
        main = dest / "main.rs"
        source = main.read_text()
        start = source.index("                let (selected, magic)")
        end = source.index("                let p = packet(bytes, magic)?;", start)
        source = source[:start] + '                let (selected, magic) = (&verifier, b"MNG3");\n' + source[end:]
        source = replace(source, "            let ast1 = legacy::registered()?;\n", "")
        main.write_text(replace(source, "mod legacy;\n", ""))
    return {str((common / name).relative_to(tree)): digest(common / name) for name in BEFORE}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("work", "upstream", "target"):
        p.add_argument(name, type=Path)
    p.add_argument("--candidate", action="store_true",
                   help="emit new candidate registrations in the work directory for review")
    a = p.parse_args()
    work, upstream, target = (v.resolve() for v in (a.work, a.upstream, a.target))
    for kind, (experiment, _, _, _) in ROLES.items():
        spec = importlib.util.spec_from_file_location(kind, HERE.parent / experiment / "native/build.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        changes = {}

        def apply(dest):
            changes.update(configure(dest, kind))

        role = work / kind
        builder.prepare(role, upstream, target, apply)
        run = subprocess.run([role / "native", "register", role / "registered"], capture_output=True,
                             check=True, env=dict(os.environ, RAYON_NUM_THREADS="2"))
        record = json.loads(run.stdout)
        (role / "REGISTER.json").write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
        key = role / "registered" / (kind + ".vk")
        manifest = json.loads((role / "BUILD.json").read_bytes())
        manifest["generated_sources"].update(changes)
        manifest.update(hardening_patch_sha256=digest(HERE / "hardening.patch"),
                        registration_sha256=digest(key), registration_bytes=key.stat().st_size,
                        role=record["suite"])
        (role / "BUILD.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
        if not a.candidate and (HERE / "registry" / key.name).read_bytes() != key.read_bytes():
            raise ValueError("generated registration differs from reviewed pin: " + kind)
        print(json.dumps(record, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
