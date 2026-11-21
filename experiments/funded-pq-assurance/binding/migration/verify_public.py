#!/usr/bin/env python3
"""Verify the released C-to-N7 evidence without wallet-private inputs."""

from __future__ import annotations

import argparse
import copy
from hashlib import sha256, sha3_384
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from bundle import BridgeBundle
from ledger import BranchContext, bridge_context, verify_bridge, verify_c
from run_genuine import import_deployment, n7_activation_id, parse_n7_packet


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def regular(path):
    path = Path(path)
    row = path.lstat()
    need(stat.S_ISREG(row.st_mode) and not path.is_symlink(), "non-regular evidence")
    return path.read_bytes()


def load(path):
    return json.loads(regular(path))


def verify_native(binary, statement, proof, folder, label):
    statement_path = folder / (label + ".json")
    proof_path = folder / (label + ".proof")
    statement_path.write_text(json.dumps(statement, sort_keys=True))
    proof_path.write_bytes(proof)
    run = subprocess.run(
        [str(binary), "verify", str(statement_path), str(proof_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env={**os.environ, "RAYON_NUM_THREADS": "2"},
    )
    need(run.returncode == 0 and json.loads(run.stdout).get("accepted") is True, label)
    return json.loads(run.stdout)


def rejected_native(binary, statement, proof, folder, label):
    try:
        verify_native(binary, statement, proof, folder, label)
    except (ValueError, json.JSONDecodeError):
        return True
    raise ValueError(label + " unexpectedly verified")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--bridge", type=Path, required=True)
    parser.add_argument("--n7", type=Path, required=True)
    parser.add_argument("--c-runtime", type=Path)
    parser.add_argument("--c-keys", type=Path)
    parser.add_argument("--deployment", type=Path)
    args = parser.parse_args()

    evidence = args.evidence.resolve(strict=True)
    manifest = load(evidence / "PUBLIC_MANIFEST.json")
    expected = set(manifest["files"])
    need(
        {path.name for path in evidence.iterdir()} == expected | {"PUBLIC_MANIFEST.json"},
        "evidence file set",
    )
    for name, record in manifest["files"].items():
        raw = regular(evidence / name)
        need(len(raw) == record["bytes"], "manifest size: " + name)
        need(sha256(raw).hexdigest() == record["sha256"], "manifest hash: " + name)

    run = load(evidence / "RUN.json")
    activation = load(evidence / "ACTIVATION.json")
    bundle_raw = regular(evidence / "bridge.bundle")
    bundle = BridgeBundle.decode(bundle_raw)
    need(bundle.encode() == bundle_raw, "noncanonical bridge bundle")
    need(bundle.component_sizes() == run["bridge"]["component_sizes"], "bundle components")
    need(len(bundle_raw) == run["bridge"]["bundle_bytes"], "bundle bytes")
    need(bundle.identity().hex() == run["bridge"]["bundle_sha3_384"], "bundle identity")
    need(sha256(bundle.c_packet).hexdigest() == run["fresh_c_packet"]["sha256"], "C packet identity")

    parent_tip = bytes.fromhex(activation["parent_tip"])
    anchor = bytes.fromhex(activation["activation_anchor"])
    c_network = bytes.fromhex(activation["c_network"])
    activation_id = n7_activation_id(
        c_network, activation["activation_height"], anchor, parent_tip
    )
    packet = regular(evidence / "onward.n7p2")
    n7_statement, n7_proof, n7_receipts = parse_n7_packet(packet, activation_id)
    need(n7_statement == load(evidence / "onward.statement.json"), "N7 statement")
    need(n7_proof == regular(evidence / "onward.proof"), "N7 proof copy")
    need(b"".join(n7_receipts) == regular(evidence / "onward.receipts"), "N7 receipts")
    need(len(packet) == run["recovery"]["ordinary_n7p2_packet_bytes"], "N7 packet bytes")
    need(
        sha3_384(packet).hexdigest() == run["recovery"]["ordinary_n7p2_packet_sha3_384"],
        "N7 packet identity",
    )

    with tempfile.TemporaryDirectory(prefix="funded-pq-public-") as name:
        folder = Path(name)
        bridge_statement = folder / "bridge.json"
        bridge_proof = folder / "bridge.proof"
        bridge_statement.write_text(json.dumps(bundle.statement, sort_keys=True))
        bridge_proof.write_bytes(bundle.equality_proof)
        bridge_result = verify_bridge(args.bridge, bridge_statement, bridge_proof)
        n7_result = verify_native(args.n7, n7_statement, n7_proof, folder, "N7 proof")

        changed = copy.deepcopy(bundle.statement)
        changed["bridge_context"][0] ^= 1
        changed_path = folder / "changed-bridge.json"
        changed_path.write_text(json.dumps(changed, sort_keys=True))
        try:
            verify_bridge(args.bridge, changed_path, bridge_proof)
        except ValueError:
            bridge_mutation = True
        else:
            raise ValueError("changed bridge statement verified")
        corrupted = bytearray(n7_proof)
        corrupted[len(corrupted) // 2] ^= 1
        n7_mutation = rejected_native(
            args.n7, n7_statement, bytes(corrupted), folder, "corrupted N7 proof"
        )

        c_result = None
        if args.c_runtime is not None or args.c_keys is not None:
            need(args.c_runtime is not None and args.c_keys is not None, "complete C verifier arguments")
            effect = verify_c(args.c_runtime, args.c_keys, bundle.c_packet)
            branch = BranchContext(
                c_network,
                parent_tip,
                activation["parent_height"],
                activation["activation_height"],
                ((anchor, activation["selected_height"], activation["selected_funded_depth"]),),
            )
            branch.check(effect)
            successors = tuple(map(tuple, bundle.statement["successor_outputs"]))
            need(
                tuple(bundle.statement["bridge_context"])
                == bridge_context(branch, bundle.c_packet, effect, successors, bundle.successor_receipts),
                "verifier-owned bridge context",
            )
            need(
                tuple(map(tuple, bundle.statement["c_input_nullifiers"])) == effect.nullifiers
                and tuple(map(tuple, bundle.statement["transient_c_outputs"])) == effect.outputs,
                "C public effects",
            )
            c_result = {"accepted": True, "depth": effect.depth, "fee": effect.fee}

        parent_result = None
        if args.deployment is not None:
            _, chain, _ = import_deployment(args.deployment)
            parent = regular(evidence / "bridge-parent-H26.bin")
            block = chain.decode_block(parent)
            need(chain.NETWORK == c_network, "C network")
            need(chain.block_id(parent) == parent_tip, "parent identity")
            need(
                block.height == activation["parent_height"]
                and block.parent.hex() == activation["selected_tip"]
                and not block.packets,
                "empty bridge parent",
            )
            parent_result = {"accepted": True, "height": block.height, "packets": 0}

    result = {
        "manifest_files": len(expected),
        "bridge": {
            "accepted": bridge_result["accepted"],
            "bytes": len(bundle.equality_proof),
            "changed_statement_rejected": bridge_mutation,
        },
        "n7": {
            "accepted": n7_result["accepted"],
            "packet_bytes": len(packet),
            "corrupted_proof_rejected": n7_mutation,
        },
        "c": c_result,
        "parent": parent_result,
        "private_inputs": 0,
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
