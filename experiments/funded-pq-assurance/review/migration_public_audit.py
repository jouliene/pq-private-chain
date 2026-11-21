#!/usr/bin/env python3
"""Audit the frozen C-to-N7 run from public artifacts only.

This script does not import the migration harness or its bundle/context
helpers.  It independently parses the canonical bundle, invokes the three
public verifiers, reconstructs the selected C branch, recomputes the bridge
context and N7 activation/tree/statement, and exercises public mutations.
It never accepts a seed, wallet database, opening, note plaintext or witness.
"""

from __future__ import annotations

import argparse
from hashlib import sha256, sha3_384
import importlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile


P = 2**64 - 2**32 + 1
BUNDLE_HEADER = struct.Struct("<8s5I")
BUNDLE_MAGIC = b"C2N7B1\0\0"
C_RECEIPT_BYTES = 1792
N7_RECEIPT_BYTES = 1744
N7_HEADER_BYTES = 3837
STATEMENT_KEYS = {
    "bridge_context",
    "c_input_nullifiers",
    "transient_c_outputs",
    "successor_outputs",
}
MIGRATION_MEMBERSHIP_ARCHIVE_SHA256 = (
    "50008712589106a8a934040dd4fa8465d1eb269f0ca7232f18ffbb2999662b6d"
)
MIGRATION_C_DEPLOYMENT_ARCHIVE_SHA256 = (
    "682ed92c510c0b73ddf21ed7c50c048c4430bb8b06c5e6fc28db1e63e8c5d942"
)


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def regular(path: Path) -> Path:
    row = path.lstat()
    need(stat.S_ISREG(row.st_mode) and not path.is_symlink(), f"regular file: {path}")
    return path


def digest_file(path: Path, constructor=sha256) -> str:
    digest = constructor()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def directory_manifest(root: Path) -> dict[str, tuple[int, str]]:
    result = {}
    for path in root.rglob("*"):
        need(not path.is_symlink(), "symlink in membership tree")
        if path.is_dir():
            continue
        regular(path)
        result[path.relative_to(root).as_posix()] = (path.stat().st_size, digest_file(path))
    need(result, "empty membership tree")
    return result


def archive_manifest(archive: Path) -> dict[str, tuple[int, str]]:
    result = {}
    directories = {"membership", "membership/blocks", "membership/controls", "membership/packets"}
    with tarfile.open(archive, "r:gz") as source:
        for member in source.getmembers():
            path = PurePosixPath(member.name)
            need(not path.is_absolute() and ".." not in path.parts, "unsafe membership archive path")
            normalized = path.as_posix().rstrip("/")
            if member.isdir():
                need(normalized in directories, "unexpected membership archive directory")
                continue
            need(member.isfile() and normalized.startswith("membership/"),
                 "non-regular membership archive entry")
            relative = normalized.removeprefix("membership/")
            need(relative and relative not in result, "duplicate membership archive entry")
            handle = source.extractfile(member)
            need(handle is not None, "unreadable membership archive entry")
            raw = handle.read()
            need(len(raw) == member.size, "membership archive size")
            result[relative] = (member.size, sha256(raw).hexdigest())
    need(result, "empty membership archive")
    return result


def rooted_archive_manifest(archive: Path, root: Path, root_name: str) -> dict[str, tuple[int, str]]:
    result = {}
    allowed_directories = {root_name}
    allowed_directories.update(
        f"{root_name}/{path.relative_to(root).as_posix()}"
        for path in root.rglob("*") if path.is_dir() and not path.is_symlink()
    )
    with tarfile.open(archive, "r:gz") as source:
        for member in source.getmembers():
            path = PurePosixPath(member.name)
            need(not path.is_absolute() and ".." not in path.parts, "unsafe rooted archive path")
            normalized = path.as_posix().rstrip("/")
            if member.isdir():
                need(normalized in allowed_directories, "unexpected rooted archive directory")
                continue
            need(member.isfile() and normalized.startswith(root_name + "/"),
                 "non-regular rooted archive entry")
            relative = normalized.removeprefix(root_name + "/")
            need(relative and relative not in result, "duplicate rooted archive entry")
            handle = source.extractfile(member)
            need(handle is not None, "unreadable rooted archive entry")
            raw = handle.read()
            need(len(raw) == member.size, "rooted archive size")
            result[relative] = (member.size, sha256(raw).hexdigest())
    need(result, "empty rooted archive")
    return result


def fields(raw: bytes, width: int) -> tuple[int, ...]:
    need(len(raw) == 8 * width, "field digest width")
    result = struct.unpack("<" + "Q" * width, raw)
    need(all(word < P for word in result), "noncanonical field digest")
    return result


def packed(words: tuple[int, ...] | list[int]) -> bytes:
    need(all(type(word) is int and 0 <= word < P for word in words), "field words")
    return struct.pack("<" + "Q" * len(words), *words)


def parse_bundle(raw: bytes) -> dict[str, object]:
    need(len(raw) >= BUNDLE_HEADER.size, "bridge bundle length")
    magic, *sizes = BUNDLE_HEADER.unpack_from(raw)
    need(magic == BUNDLE_MAGIC, "bridge bundle magic")
    need(sum(sizes) == len(raw) - BUNDLE_HEADER.size, "bridge bundle framing")
    offset = BUNDLE_HEADER.size
    pieces = []
    for size in sizes:
        pieces.append(raw[offset : offset + size])
        offset += size
    statement_raw, c_packet, proof, receipt0, receipt1 = pieces
    statement = json.loads(statement_raw)
    need(type(statement) is dict and set(statement) == STATEMENT_KEYS, "bridge statement keys")
    need(statement_raw == canonical_json(statement), "noncanonical bridge statement")
    need(len(receipt0) == len(receipt1) == N7_RECEIPT_BYTES, "N7 receipt length")
    return {
        "statement": statement,
        "statement_raw": statement_raw,
        "c_packet": c_packet,
        "proof": proof,
        "receipts": (receipt0, receipt1),
        "sizes": {
            "framing": BUNDLE_HEADER.size,
            "statement": sizes[0],
            "c_packet_including_c_receipts": sizes[1],
            "equality_proof": sizes[2],
            "successor_receipts": sizes[3] + sizes[4],
            "canonical_bundle": len(raw),
            "derived_c_receipt_index": 16,
        },
    }


def c_inner(packet: bytes) -> bytes:
    need(len(packet) > 15 and packet[:6] == b"MSP3\x01\x00", "C transfer envelope")
    inner = packet[6:]
    need(inner[:5] == b"MNG3\x01", "C inner suite")
    proof_size = int.from_bytes(inner[5:9], "little")
    need(proof_size > 0 and len(inner) == 9 + proof_size + 2 * C_RECEIPT_BYTES, "C inner length")
    return inner


def c_role(binary: Path, key_directory: Path, packet: bytes) -> bytes:
    inner = c_inner(packet)
    request = struct.pack("<I", len(inner)) + inner + struct.pack("<I", 0)
    run = subprocess.run(
        [str(binary), "verify", str(key_directory)],
        input=request,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    need(run.returncode == 0, "C verifier process")
    need(len(run.stdout) >= 4, "C verifier frame")
    size = struct.unpack_from("<I", run.stdout)[0]
    need(len(run.stdout) == 4 + size, "C verifier reply framing")
    return run.stdout[4:]


def parse_c_effect(reply: bytes) -> dict[str, object]:
    need(reply[:1] == b"1" and len(reply) == 1 + 172 + 2 * C_RECEIPT_BYTES + 40 + 1,
         "invalid C proof")
    row = reply[1:]
    effect = {
        "anchor": row[:32],
        "height": int.from_bytes(row[32:36], "little"),
        "nullifiers": (fields(row[36:68], 4), fields(row[68:100], 4)),
        "outputs": (fields(row[100:132], 4), fields(row[132:164], 4)),
        "fee": int.from_bytes(row[164:172], "little"),
        "receipts": (row[172 : 172 + C_RECEIPT_BYTES], row[172 + C_RECEIPT_BYTES : 172 + 2 * C_RECEIPT_BYTES]),
        "issue_id": fields(row[-41:-9], 4),
        "supply": int.from_bytes(row[-9:-1], "little"),
        "depth": row[-1],
    }
    need(effect["fee"] == 3 and effect["issue_id"] == (0, 0, 0, 0)
         and effect["supply"] == 0 and 1 <= effect["depth"] <= 20, "C transfer effect")
    return effect


def bridge_verify(binary: Path, statement: object, proof: bytes, folder: Path) -> bool:
    statement_path = folder / "bridge-statement.json"
    proof_path = folder / "bridge-proof.bin"
    statement_path.write_bytes(canonical_json(statement))
    proof_path.write_bytes(proof)
    run = subprocess.run(
        [str(binary), "verify", str(statement_path), str(proof_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if run.returncode != 0:
        return False
    try:
        return json.loads(run.stdout).get("accepted") is True
    except (json.JSONDecodeError, AttributeError):
        return False


def n7_verify(binary: Path, statement: object, proof: bytes, folder: Path) -> bool:
    statement_path = folder / "n7-statement.json"
    proof_path = folder / "n7-proof.bin"
    statement_path.write_bytes(canonical_json(statement))
    proof_path.write_bytes(proof)
    run = subprocess.run(
        [str(binary), "verify", str(statement_path), str(proof_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if run.returncode != 0:
        return False
    try:
        return json.loads(run.stdout).get("accepted") is True
    except (json.JSONDecodeError, AttributeError):
        return False


def verifier_report(binary: Path, statement: object, proof: bytes, folder: Path,
                    label: str) -> dict[str, object]:
    statement_path = folder / f"{label}-report-statement.json"
    proof_path = folder / f"{label}-report-proof.bin"
    statement_path.write_bytes(canonical_json(statement))
    proof_path.write_bytes(proof)
    run = subprocess.run(
        [str(binary), "verify", str(statement_path), str(proof_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    need(run.returncode == 0 and not run.stderr, f"{label} verifier process")
    report = json.loads(run.stdout)
    need(report.get("accepted") is True, f"{label} verifier verdict")
    return report


def generated_vk_digest(binary: Path, registered: Path, folder: Path, label: str) -> str:
    """Regenerate a verifier key and require byte identity with the registration."""
    generated = folder / f"{label}-generated.vk"
    run = subprocess.run(
        [str(binary), "generate-vk", str(generated)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    need(run.returncode == 0 and not run.stderr, f"{label} VK generation process")
    report = json.loads(run.stdout)
    raw = regular(generated).read_bytes()
    need(report.get("registered_bytes") == len(raw), f"{label} generated VK length")
    need(raw == registered.read_bytes(), f"{label} generated/registered VK mismatch")
    return sha3_384(raw).hexdigest()


def bridge_context(activation: dict[str, object], c_packet: bytes, effect: dict[str, object],
                   successors: tuple[tuple[int, ...], ...], receipts: tuple[bytes, bytes]) -> tuple[int, ...]:
    digest = sha3_384()
    digest.update(b"C2N7/bridge-context/v3\0")
    digest.update(bytes.fromhex(activation["c_network"]))
    digest.update(bytes.fromhex(activation["parent_tip"]))
    digest.update(struct.pack("<II", activation["parent_height"], activation["activation_height"]))
    digest.update(sha3_384(c_packet).digest())
    digest.update(effect["anchor"])
    digest.update(struct.pack("<IBQ", effect["height"], effect["depth"], effect["fee"]))
    for value in (*effect["nullifiers"], *effect["outputs"], *successors):
        digest.update(packed(value))
    for receipt in (*effect["receipts"], *receipts):
        digest.update(sha3_384(receipt).digest())
    return struct.unpack("<12I", digest.digest())


class N7Oracle:
    def __init__(self, binary: Path):
        self.process = subprocess.Popen(
            [str(binary), "eval-stream"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def call(self, op: str, **values: object) -> list[int]:
        self.process.stdin.write(json.dumps({"op": op, **values}, separators=(",", ":")) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        need(line.endswith("\n"), "N7 oracle reply")
        result = json.loads(line)
        need(len(result) == 7 and all(type(word) is int and 0 <= word < P for word in result),
             "N7 oracle digest")
        return result

    def close(self) -> None:
        self.process.stdin.close()
        self.process.wait(timeout=30)
        errors = self.process.stderr.read()
        self.process.stdout.close()
        self.process.stderr.close()
        need(self.process.returncode == 0 and not errors, "N7 oracle exit")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def two_leaf_root(oracle: N7Oracle, leaves: tuple[tuple[int, ...], ...]) -> list[int]:
    need(len(leaves) == 2, "two N7 leaves")
    empty = [oracle.call("empty")]
    for level in range(39):
        empty.append(oracle.call("parent", level=level, left=empty[-1], right=empty[-1]))
    root = oracle.call("parent", level=0, left=leaves[0], right=leaves[1])
    for level in range(1, 40):
        root = oracle.call("parent", level=level, left=root, right=empty[level])
    return root


def n7_statement(activation_id: bytes, header: bytes) -> dict[str, object]:
    need(len(activation_id) == 48 and len(header) == N7_HEADER_BYTES, "N7 context input")
    need(header[:5] == b"N7P2\0", "N7 transfer magic")
    count, fee = struct.unpack_from("<QQ", header, 109)
    positions = (53, 125, 181, 237, 293)
    values = [list(fields(header[position : position + 56], 7)) for position in positions]
    context = struct.unpack(
        "<12I", sha3_384(b"N7P2/proof-context\0" + activation_id + header).digest()
    )
    return {
        "root": values[0],
        "count": count,
        "fee": fee,
        "context": list(context),
        "nullifiers": values[1:3],
        "outputs": values[3:5],
    }


def import_public_deployment(deployment: Path):
    devnet = deployment / "devnet"
    sys.path.insert(0, str(devnet))
    try:
        return (
            importlib.import_module("wallet_c"),
            importlib.import_module("chain"),
            importlib.import_module("consensus"),
        )
    finally:
        sys.path.remove(str(devnet))


def selected_lineage(chain, blocks: Path, tip_hex: str) -> list[bytes]:
    current = bytes.fromhex(tip_hex)
    result = []
    while current != chain.GENESIS:
        raw = regular(blocks / f"{current.hex()}.bin").read_bytes()
        need(chain.block_id(raw) == current, "archived block identity")
        result.append(raw)
        current = chain.decode_block(raw).parent
        need(len(result) <= 2**16, "lineage bound")
    result.reverse()
    return result


def replay_public_branch(deployment_source: Path, archive: Path, activation: dict[str, object],
                         parent_raw: bytes, temporary: Path) -> dict[str, object]:
    deployment = temporary / "deployment"
    shutil.copytree(deployment_source, deployment, symlinks=False)
    os.chmod(temporary, 0o700)
    wallet_c, chain, consensus = import_public_deployment(deployment)
    need(chain.NETWORK.hex() == activation["c_network"], "C network identity")
    lineage = selected_lineage(chain, archive / "blocks", activation["selected_tip"])
    need(len(lineage) == activation["selected_height"], "selected lineage height")
    lab = wallet_c.FundedLab(temporary, "C")
    try:
        lab.initialize()
        lab.launch("a")
        lab.links("a", [])
        for raw in lineage:
            reply, body = lab.request("a", "publish", raw)
            need(not body and reply.get("id") == chain.block_id(raw).hex(), "selected replay")
        selected = lab.status("a")
        need(selected["tip"] == activation["selected_tip"], "selected replay tip")
        need(selected["height"] == activation["selected_height"], "selected replay height")
        need(selected["anchor"] == activation["activation_anchor"], "selected funded anchor")
        need(selected["notes"] == activation["selected_funded_count"], "selected funded count")
        need(consensus.funded_depth(selected["notes"]) == activation["selected_funded_depth"],
             "selected funded depth")

        need(chain.block_id(parent_raw).hex() == activation["parent_tip"], "parent block identity")
        parent = chain.decode_block(parent_raw)
        need(parent.parent.hex() == activation["selected_tip"], "parent lineage")
        need(parent.height == activation["parent_height"] and not parent.packets, "empty parent")
        reply, body = lab.request("a", "publish", parent_raw)
        need(not body and reply.get("id") == activation["parent_tip"], "parent replay")
        parent_status, pages = lab.snapshot("a")
        need(parent_status["tip"] == activation["parent_tip"], "selected parent tip")
        need(parent_status["height"] == activation["parent_height"], "selected parent height")
        spent_raw = pages[-1]
        need(len(spent_raw) % 32 == 0, "spent page width")
        spent = {spent_raw[offset : offset + 32] for offset in range(0, len(spent_raw), 32)}
        return {
            "lineage_blocks": len(lineage),
            "selected_anchor": selected["anchor"],
            "selected_count": selected["notes"],
            "selected_depth": consensus.funded_depth(selected["notes"]),
            "parent_tip": parent_status["tip"],
            "parent_height": parent_status["height"],
            "parent_empty": not parent.packets,
            "spent": spent,
        }
    finally:
        try:
            lab.stop()
        except Exception:
            pass


def public_mutations(bridge_binary: Path, n7_binary: Path, bridge_statement: dict[str, object],
                     bridge_proof: bytes, n7_public: dict[str, object], n7_proof: bytes,
                     folder: Path) -> dict[str, bool]:
    changed_context = json.loads(json.dumps(bridge_statement))
    changed_context["bridge_context"][0] ^= 1
    changed_c = json.loads(json.dumps(bridge_statement))
    changed_c["transient_c_outputs"][0][0] ^= 1
    changed_n7 = json.loads(json.dumps(bridge_statement))
    changed_n7["successor_outputs"][0][0] ^= 1
    corrupt_bridge = bytearray(bridge_proof)
    corrupt_bridge[len(corrupt_bridge) // 2] ^= 1

    changed_root = json.loads(json.dumps(n7_public))
    changed_root["root"][0] ^= 1
    changed_output = json.loads(json.dumps(n7_public))
    changed_output["outputs"][0][0] ^= 1
    corrupt_n7 = bytearray(n7_proof)
    corrupt_n7[len(corrupt_n7) // 2] ^= 1
    return {
        "bridge_changed_context_rejected": not bridge_verify(bridge_binary, changed_context, bridge_proof, folder),
        "bridge_changed_c_commitment_rejected": not bridge_verify(bridge_binary, changed_c, bridge_proof, folder),
        "bridge_changed_n7_commitment_rejected": not bridge_verify(bridge_binary, changed_n7, bridge_proof, folder),
        "bridge_corrupted_proof_rejected": not bridge_verify(bridge_binary, bridge_statement, bytes(corrupt_bridge), folder),
        "onward_changed_root_rejected": not n7_verify(n7_binary, changed_root, n7_proof, folder),
        "onward_changed_output_rejected": not n7_verify(n7_binary, changed_output, n7_proof, folder),
        "onward_corrupted_proof_rejected": not n7_verify(n7_binary, n7_public, bytes(corrupt_n7), folder),
    }


def exercise_author_ledger(bundle_raw: bytes, activation: dict[str, object],
                           c_binary: Path, c_keys: Path, bridge_binary: Path,
                           selected_spent: set[bytes], folder: Path) -> dict[str, object]:
    """Exercise the actual prototype ledger with genuine public verifier callbacks."""
    migration = Path(__file__).resolve().parent.parent / "binding" / "migration"
    sys.path.insert(0, str(migration))
    try:
        bundle_module = importlib.import_module("bundle")
        ledger_module = importlib.import_module("ledger")
    finally:
        sys.path.remove(str(migration))
    bundle = bundle_module.BridgeBundle.decode(bundle_raw)

    def verify_c_packet(packet: bytes):
        effect = parse_c_effect(c_role(c_binary, c_keys, packet))
        return ledger_module.CEffect(
            effect["anchor"], effect["height"], effect["nullifiers"], effect["outputs"],
            effect["fee"], effect["receipts"], effect["depth"],
        )

    def verify_equality(statement: object, proof: bytes):
        need(bridge_verify(bridge_binary, statement, proof, folder), "ledger bridge verifier")

    branch = ledger_module.BranchContext(
        bytes.fromhex(activation["c_network"]),
        bytes.fromhex(activation["parent_tip"]),
        activation["parent_height"],
        activation["activation_height"],
        ((bytes.fromhex(activation["activation_anchor"]), activation["selected_height"],
          activation["selected_funded_depth"]),),
    )
    selected_callback = lambda nf: packed(nf) in selected_spent
    ledger = ledger_module.Ledger(activation["activation_height"])
    before = ledger.snapshot()
    effect = ledger.admit(branch, bundle, verify_c_packet, verify_equality, selected_callback)
    admitted = ledger.snapshot()
    need(not any(ledger.contains_transient_c_output(cm) for cm in effect.outputs),
         "ledger inserted transient C output")
    try:
        ledger.admit(branch, bundle, verify_c_packet, verify_equality, selected_callback)
    except Exception:
        need(ledger.snapshot() == admitted, "ledger replay changed state")
    else:
        raise ValueError("ledger replay accepted")
    ledger.rollback(activation["activation_height"])
    need(ledger.snapshot() == before, "ledger rollback")
    ledger.admit(branch, bundle, verify_c_packet, verify_equality, selected_callback)
    need(ledger.snapshot() == admitted, "ledger reinclusion")
    try:
        ledger.ordinary_c_spend(activation["activation_height"], effect.nullifiers)
    except ValueError as error:
        need(str(error) == "standalone C retired at bridge activation", "standalone C reason")
    else:
        raise ValueError("post-activation standalone C accepted")
    need(ledger.snapshot() == admitted, "standalone C rejection changed state")

    ordinary_first = ledger_module.Ledger(activation["activation_height"])
    ordinary_first.ordinary_c_spend(activation["activation_height"] - 1, effect.nullifiers)
    ordinary_snapshot = ordinary_first.snapshot()
    try:
        ordinary_first.admit(
            branch, bundle, verify_c_packet, verify_equality,
            lambda nf: tuple(nf) in set(effect.nullifiers),
        )
    except ValueError as error:
        need(str(error) == "C input already spent on selected branch", "ordinary-first reason")
    else:
        raise ValueError("ordinary-first bridge accepted")
    need(ordinary_first.snapshot() == ordinary_snapshot, "ordinary-first rejection changed state")

    changed_receipt = bytearray(bundle.successor_receipts[0])
    changed_receipt[0] ^= 1
    bad_bundle = bundle_module.BridgeBundle(
        bundle.statement, bundle.c_packet, bundle.equality_proof,
        (bytes(changed_receipt), bundle.successor_receipts[1]),
    )
    receipt_ledger = ledger_module.Ledger(activation["activation_height"])
    try:
        receipt_ledger.admit(
            branch, bad_bundle, verify_c_packet, verify_equality, selected_callback,
        )
    except ValueError:
        need(receipt_ledger.snapshot() == before, "receipt rejection changed state")
    else:
        raise ValueError("changed successor receipt accepted")
    return {
        "before": before,
        "admitted": admitted,
        "replay_rejected_without_state_change": True,
        "rollback_and_byte_identical_reinclusion": True,
        "bridge_then_standalone_c_rejected": True,
        "ordinary_c_then_bridge_rejected": True,
        "changed_successor_receipt_rejected_atomically": True,
        "transient_c_outputs_inserted": False,
    }


def audit(args) -> dict[str, object]:
    evidence = args.evidence.resolve(strict=True)
    archive = args.archive.resolve(strict=True)
    membership_archive = regular(args.membership_archive.resolve(strict=True))
    deployment_archive = regular(args.c_deployment_archive.resolve(strict=True))
    deployment = args.c_deployment.resolve(strict=True)
    bridge_binary = regular(args.bridge_binary.resolve(strict=True))
    n7_binary = regular(args.n7_binary.resolve(strict=True))
    bridge_vk = regular(args.bridge_vk.resolve(strict=True))
    n7_vk = regular(args.n7_vk.resolve(strict=True))
    need(evidence.is_dir() and archive.is_dir() and deployment.is_dir(), "public directory input")
    need(digest_file(membership_archive) == MIGRATION_MEMBERSHIP_ARCHIVE_SHA256,
         "migration membership archive identity")
    membership_tree = directory_manifest(archive)
    need(archive_manifest(membership_archive) == membership_tree,
         "migration membership archive/tree mismatch")
    need(digest_file(deployment_archive) == MIGRATION_C_DEPLOYMENT_ARCHIVE_SHA256,
         "migration C deployment archive identity")
    deployment_tree = directory_manifest(deployment)
    need(rooted_archive_manifest(deployment_archive, deployment, "deployment") == deployment_tree,
         "migration C deployment archive/tree mismatch")
    need(set(path.name for path in evidence.iterdir()) == {
        "ACTIVATION.json", "PUBLIC_MANIFEST.json", "RUN.json", "bridge-parent-H26.bin", "bridge.bundle",
        "onward.n7p2", "onward.proof", "onward.receipts", "onward.statement.json",
    }, "public evidence file set")
    manifest = json.loads(regular(evidence / "PUBLIC_MANIFEST.json").read_bytes())
    need(manifest.get("schema") == 1 and manifest.get("private_inputs") == 0,
         "public manifest schema")
    need(set(manifest.get("files", {})) == {
        "ACTIVATION.json", "RUN.json", "bridge-parent-H26.bin", "bridge.bundle",
        "onward.n7p2", "onward.proof", "onward.receipts", "onward.statement.json",
    }, "public manifest entries")
    for name, row in manifest["files"].items():
        path = regular(evidence / name)
        need(path.stat().st_size == row["bytes"] and digest_file(path) == row["sha256"],
             f"public manifest identity: {name}")
    activation = json.loads(regular(evidence / "ACTIVATION.json").read_bytes())
    run = json.loads(regular(evidence / "RUN.json").read_bytes())
    bundle_raw = regular(evidence / "bridge.bundle").read_bytes()
    bundle = parse_bundle(bundle_raw)
    parent_raw = regular(evidence / "bridge-parent-H26.bin").read_bytes()

    c_binary = regular(deployment / "c-runtime/native")
    c_keys = deployment / "c-keys"
    c_key = regular(c_keys / "managed.vk")
    need(set(path.name for path in c_keys.iterdir()) == {"managed.vk"}, "C key directory")
    effect = parse_c_effect(c_role(c_binary, c_keys, bundle["c_packet"]))
    statement = bundle["statement"]
    successors = tuple(tuple(row) for row in statement["successor_outputs"])
    expected_context = bridge_context(
        activation, bundle["c_packet"], effect, successors, bundle["receipts"]
    )
    need(tuple(statement["bridge_context"]) == expected_context, "bridge context mismatch")
    need(tuple(tuple(row) for row in statement["c_input_nullifiers"]) == effect["nullifiers"],
         "bridge C nullifier mismatch")
    need(tuple(tuple(row) for row in statement["transient_c_outputs"]) == effect["outputs"],
         "bridge C output mismatch")
    need(effect["anchor"].hex() == activation["activation_anchor"], "C anchor")
    need(effect["height"] == activation["selected_height"], "C anchor height")
    need(effect["depth"] == activation["selected_funded_depth"], "C anchor depth")
    need(1 <= activation["activation_height"] - effect["height"] <= 8, "C anchor window")

    n7_network = sha3_384(
        b"C2N7/N7-network/v1\0" + bytes.fromhex(activation["c_network"])
        + struct.pack("<I", activation["activation_height"])
        + bytes.fromhex(activation["activation_anchor"])
    ).digest()
    n7_scope = sha3_384(
        b"C2N7/N7-key-scope/v1\0" + bytes.fromhex(activation["c_network"])
        + struct.pack("<I", activation["activation_height"])
        + bytes.fromhex(activation["activation_anchor"])
    ).digest()
    need(n7_network.hex() == activation["n7_network"] and n7_scope.hex() == activation["n7_scope"],
         "successor domains")
    activation_id = sha3_384(
        b"C2N7/N7-activation/v1\0" + bytes.fromhex(activation["c_network"])
        + struct.pack("<I", activation["activation_height"])
        + bytes.fromhex(activation["activation_anchor"])
        + bytes.fromhex(activation["parent_tip"])
    ).digest()

    onward_packet = regular(evidence / "onward.n7p2").read_bytes()
    onward_proof = regular(evidence / "onward.proof").read_bytes()
    onward_receipts = regular(evidence / "onward.receipts").read_bytes()
    need(len(onward_packet) > N7_HEADER_BYTES + 4, "onward packet length")
    header = onward_packet[:N7_HEADER_BYTES]
    proof_size = struct.unpack_from("<I", onward_packet, N7_HEADER_BYTES)[0]
    need(len(onward_packet) == N7_HEADER_BYTES + 4 + proof_size, "onward packet framing")
    need(onward_packet[N7_HEADER_BYTES + 4 :] == onward_proof, "onward proof copy")
    need(onward_receipts == header[349:] and len(onward_receipts) == 2 * N7_RECEIPT_BYTES,
         "onward receipt copy")
    need(header[5:53] == n7_network, "onward network")
    onward_public = n7_statement(activation_id, header)
    released_statement = json.loads(regular(evidence / "onward.statement.json").read_bytes())
    need(released_statement == onward_public, "onward public statement")
    with N7Oracle(n7_binary) as oracle:
        bridge_root = two_leaf_root(oracle, successors)
    need(onward_public["root"] == bridge_root and onward_public["count"] == 2,
         "onward bridge root/count")
    need(onward_public["fee"] == 3, "onward fee")

    archived_packets = {path.stem for path in (archive / "packets").iterdir() if path.suffix == ".bin"}
    c_packet_sha = sha256(bundle["c_packet"]).hexdigest()
    need(c_packet_sha not in archived_packets, "migration packet reused archived creator packet")

    with tempfile.TemporaryDirectory(prefix="funded-pq-public-review-") as raw_temporary:
        temporary = Path(raw_temporary)
        replay = replay_public_branch(deployment, archive, activation, parent_raw, temporary / "chain")
        need(all(packed(row) not in replay["spent"] for row in effect["nullifiers"]),
             "C input already spent at selected parent")
        bridge_report = verifier_report(
            bridge_binary, statement, bundle["proof"], temporary, "bridge"
        )
        n7_report = verifier_report(n7_binary, onward_public, onward_proof, temporary, "n7")
        bridge_generated_vk_digest = generated_vk_digest(
            bridge_binary, bridge_vk, temporary, "bridge"
        )
        n7_generated_vk_digest = generated_vk_digest(
            n7_binary, n7_vk, temporary, "n7"
        )
        mutations = public_mutations(
            bridge_binary, n7_binary, statement, bundle["proof"], onward_public,
            onward_proof, temporary,
        )
        need(all(mutations.values()), "public mutation accepted")
        corrupt_c = bytearray(bundle["c_packet"])
        corrupt_c[20] ^= 1
        invalid_c_reply = c_role(c_binary, c_keys, bytes(corrupt_c))
        need(not (invalid_c_reply[:1] == b"1" and len(invalid_c_reply) > 1),
             "corrupted C packet accepted")
        ledger_exercise = exercise_author_ledger(
            bundle_raw, activation, c_binary, c_keys, bridge_binary, replay["spent"], temporary,
        )

    component_sizes = bundle["sizes"]
    need(component_sizes == run["bridge"]["component_sizes"], "bridge component accounting")
    need(sum(component_sizes[name] for name in (
        "framing", "statement", "c_packet_including_c_receipts", "equality_proof",
        "successor_receipts",
    )) == component_sizes["canonical_bundle"], "bridge component sum")
    need(len(onward_packet) == N7_HEADER_BYTES + 4 + len(onward_proof), "onward byte accounting")
    need(sha3_384(b"C2N7/bundle-id/v1\0" + bundle_raw).hexdigest()
         == run["bridge"]["bundle_sha3_384"], "bundle identity")
    need(sha3_384(bundle["proof"]).hexdigest() == run["bridge"]["proof_sha3_384"],
         "bridge proof identity")
    need(sha3_384(onward_packet).hexdigest() == run["recovery"]["ordinary_n7p2_packet_sha3_384"],
         "onward packet identity")
    need(sha3_384(onward_proof).hexdigest() == run["recovery"]["onward_proof_sha3_384"],
         "onward proof identity")
    need(activation_id.hex() == run["recovery"]["activation_id_sha3_384"], "activation identity")
    bridge_vk_digest = digest_file(bridge_vk, sha3_384)
    n7_vk_digest = digest_file(n7_vk, sha3_384)
    need(bridge_vk_digest == run["source_and_binaries"]["bridge_vk_sha3_384"]
         == bridge_report["registered_vk_sha3_384"]
         == bridge_generated_vk_digest, "bridge generated/registered VK identity")
    need(n7_vk_digest == run["recovery"]["verify"]["registered_vk_sha3_384"]
         == n7_report["registered_vk_sha3_384"]
         == n7_generated_vk_digest, "N7 generated/registered VK identity")
    need(digest_file(c_key, sha3_384) == run["source_and_binaries"]["c_vk_sha3_384"],
         "C verifier key identity")

    return {
        "schema": "funded-pq-public-migration-review-v2",
        "input_boundary": {
            "private_inputs_read": 0,
            "membership_archive_sha256": digest_file(membership_archive),
            "membership_archive_bytes": membership_archive.stat().st_size,
            "membership_regular_files": len(membership_tree),
            "exact_membership_archive_tree": True,
            "c_deployment_archive_sha256": digest_file(deployment_archive),
            "c_deployment_archive_bytes": deployment_archive.stat().st_size,
            "c_deployment_regular_files": len(deployment_tree),
            "exact_c_deployment_archive_tree": True,
            "accepted_inputs": [
                "nine-file evidence-author05 public directory including its manifest",
                "public funded-membership replay tree matching the selected tip",
                "public C deployment/verifier and key",
                "public bridge and N7 verifier binaries plus exact registered VK files",
            ],
        },
        "artifact_identity": {
            "bundle_sha256": sha256(bundle_raw).hexdigest(),
            "bundle_id_sha3_384": sha3_384(b"C2N7/bundle-id/v1\0" + bundle_raw).hexdigest(),
            "c_packet_sha256": c_packet_sha,
            "bridge_proof_sha3_384": sha3_384(bundle["proof"]).hexdigest(),
            "onward_packet_sha3_384": sha3_384(onward_packet).hexdigest(),
            "onward_proof_sha3_384": sha3_384(onward_proof).hexdigest(),
            "activation_id_sha3_384": activation_id.hex(),
        },
        "verifier_registration": {
            "acceptance_rule": (
                "exact generated/registered VK identity plus successful public verification; "
                "rebuilt executable hashes are excluded because they are build-path dependent"
            ),
            "bridge": {
                "generated_matches_registered": True,
                "registered_vk_sha3_384": bridge_vk_digest,
                "proof_accepted": True,
            },
            "n7": {
                "generated_matches_registered": True,
                "registered_vk_sha3_384": n7_vk_digest,
                "proof_accepted": True,
            },
            "c": {
                "registered_vk_sha3_384": digest_file(c_key, sha3_384),
                "proof_accepted": True,
                "verifier_from_pinned_deployment_archive": True,
            },
            "author_run_binary_sha256_provenance_only": {
                "bridge": run["source_and_binaries"]["bridge_sha256"],
                "n7": run["source_and_binaries"]["n7_sha256"],
                "c_verifier": run["source_and_binaries"]["c_verifier_sha256"],
            },
        },
        "bridge": {
            "public_verification": True,
            "c_public_verification": True,
            "component_sizes": component_sizes,
            "context_recomputed": True,
            "legacy_input_nullifiers_preserved": True,
            "transient_c_outputs_bound_but_not_inserted": True,
            "successor_root": bridge_root,
            "selected_branch": {key: value for key, value in replay.items() if key != "spent"},
            "selected_parent_spent_entries": len(replay["spent"]),
            "input_nullifiers_unspent_at_parent": True,
            "fresh_c_packet_absent_from_selected_public_archive": True,
            "prototype_ledger_exercise": ledger_exercise,
        },
        "onward": {
            "public_verification": True,
            "network_recomputed": True,
            "activation_recomputed": True,
            "statement_recomputed_from_packet": True,
            "root_recomputed_from_bridge_outputs": True,
            "count": onward_public["count"],
            "fee": onward_public["fee"],
            "packet_bytes": len(onward_packet),
            "proof_bytes": len(onward_proof),
            "receipt_bytes_in_packet": len(onward_receipts),
        },
        "mutations": mutations,
        "limits": [
            "public verification does not establish proof-system knowledge or zero knowledge",
            "the public release cannot reproduce the private backup-only discovery claim",
            "recorded prover time and peak RSS are manifest observations, not rerun measurements",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--membership-archive", type=Path, required=True)
    parser.add_argument("--c-deployment", type=Path, required=True)
    parser.add_argument("--c-deployment-archive", type=Path, required=True)
    parser.add_argument("--bridge-binary", type=Path, required=True)
    parser.add_argument("--n7-binary", type=Path, required=True)
    parser.add_argument("--bridge-vk", type=Path, required=True)
    parser.add_argument("--n7-vk", type=Path, required=True)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(audit(args), indent=2, sort_keys=True) + "\n"
    if args.check:
        if args.check.read_text() != encoded:
            raise SystemExit(f"public migration review differs: {args.check}")
        print("Frozen public migration artifacts and mutations matched.")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
