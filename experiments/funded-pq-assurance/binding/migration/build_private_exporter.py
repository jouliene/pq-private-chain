#!/usr/bin/env python3
"""Build a private-only C wallet opening exporter from the pinned Qnero source.

The resulting binary is not a consensus verifier and is never approved by a
hash in the public node.  It adds one wallet IPC command that returns a note
opening only to the process that already mounted the corresponding seed.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


managed = module("c2n7_managed_build", ROOT / "experiments/managed-assets/native/build.py")
funded = module("c2n7_funded_config", ROOT / "experiments/funded-membership/build_c.py")


def patch(dest):
    funded.configure(dest, "managed")
    wallet = dest / "wallet.rs"
    source = wallet.read_text()
    marker = "            b'K' => std::panic::catch_unwind"
    if source.count(marker) != 1:
        raise ValueError("unexpected pinned wallet dispatch")
    export = r'''            b'X' => open(&key, &cmd[1..]).map(|hit| match hit {
                None => b"MISS".to_vec(),
                Some((p, k)) => {
                    let mut b = b"OPN1".to_vec();
                    b.extend(p.note.pk.to_bytes());
                    b.extend(p.note.value.to_le_bytes());
                    b.extend(p.token.to_le_bytes());
                    b.extend(p.id.to_bytes());
                    b.extend(p.note.rho.to_bytes());
                    b.extend(p.raw.to_bytes());
                    b.push(k);
                    b
                }
            }),
'''
    wallet.write_text(source.replace(marker, export + marker))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("work", "upstream", "target"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    managed.prepare(args.work.resolve(), args.upstream.resolve(), args.target.resolve(), patch)
    registered = args.work.resolve() / "registered"
    subprocess.run([args.work.resolve() / "native", "register", registered], check=True)
    expected = ROOT / "experiments/funded-membership/registry/managed.vk"
    actual = registered / "managed.vk"
    if actual.read_bytes() != expected.read_bytes():
        raise ValueError("private exporter changed the registered C relation")
    manifest = json.loads((args.work.resolve() / "BUILD.json").read_bytes())
    manifest.update(
        role="MNG3-private-opening-exporter",
        consensus_approved=False,
        registered_key_matches_mng3=True,
        privacy_boundary="output may be written only to a disposable private directory",
    )
    (args.work.resolve() / "BUILD.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )


if __name__ == "__main__":
    main()
