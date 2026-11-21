#!/usr/bin/env python3
"""Genuine fresh-MNG3 to same-network N7 migration harness.

`preflight` is read-only and does not read seed contents. `run` and the
internal `recover-spend` phase are private/heavy and allocation-gated.
"""

from __future__ import annotations

import argparse
import copy
from hashlib import sha256, sha3_384, shake_256
import json
import os
from pathlib import Path
import resource
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(HERE))
from bundle import BridgeBundle, N7_RECEIPT_BYTES, statement_bytes
from ledger import BranchContext, Ledger, bridge_context, packed, verify_bridge, verify_c


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest_file(path, algorithm="sha256"):
    h = {"sha256": sha256, "sha3_384": sha3_384}[algorithm]()
    with Path(path).open("rb") as source:
        while block := source.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def checked_file(path, *, private=False, size=None):
    path = Path(path)
    row = path.lstat()
    need(stat.S_ISREG(row.st_mode) and not path.is_symlink(), "regular-file input required")
    if private:
        need(row.st_mode & 0o077 == 0, "private input permissions")
    if size is not None:
        need(row.st_size == size, "input size")
    return path


def require_tmp(path):
    path = Path(path).resolve()
    need(path != Path("/tmp") and Path("/tmp") in path.parents, "private run root must be below /tmp")
    return path


def write_private(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())


def write_json(path, value, private=False):
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    write_private(path, raw) if private else Path(path).write_bytes(raw)


def frame_write(stream, body):
    stream.write(struct.pack("<I", len(body)) + body)
    stream.flush()


def frame_read(stream, limit=2**20):
    header = stream.read(4)
    need(len(header) == 4, "framed role ended")
    size, = struct.unpack("<I", header)
    need(0 < size <= limit, "framed role reply bound")
    body = stream.read(size)
    need(len(body) == size, "truncated framed role reply")
    return body


class OpeningExporter:
    """Private-only wallet role. It never exports ask, nk or the seed."""

    def __init__(self, binary, keys, seed):
        self.proc = subprocess.Popen(
            [str(binary), "wallet", str(keys), str(seed), "restore"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        need(len(frame_read(self.proc.stdout, 2048)) == 1601, "private exporter address")

    def open(self, commitment, receipt):
        frame_write(self.proc.stdin, b"X" + commitment + receipt)
        raw = frame_read(self.proc.stdout, 512)
        need(raw[:4] == b"OPN1" and len(raw) == 149, "private exporter opening")
        words4 = lambda value: list(struct.unpack("<4Q", value))
        return {
            "pk": words4(raw[4:36]), "native": int.from_bytes(raw[36:44], "little"),
            "token": int.from_bytes(raw[44:52], "little"), "asset": words4(raw[52:84]),
            "rho": words4(raw[84:116]), "raw": words4(raw[116:148]),
            "receipt_kind": raw[148],
        }

    def close(self):
        if self.proc.poll() is None:
            self.proc.stdin.write(struct.pack("<I", 0)); self.proc.stdin.flush()
        self.proc.stdin.close(); self.proc.wait(timeout=30)
        errors = self.proc.stderr.read()
        self.proc.stdout.close(); self.proc.stderr.close()
        need(self.proc.returncode == 0 and not errors, "private exporter exit")

    def __enter__(self): return self
    def __exit__(self, *_): self.close()


class N7Oracle:
    def __init__(self, binary):
        self.proc = subprocess.Popen(
            [str(binary), "eval-stream"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )

    def call(self, op, **values):
        self.proc.stdin.write(json.dumps({"op": op, **values}, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline(4096)
        need(line.endswith("\n"), "N7 arithmetic role")
        result = json.loads(line)
        need(len(result) == 7 and all(type(word) is int for word in result), "N7 digest")
        return result

    def close(self):
        self.proc.stdin.close(); self.proc.wait(timeout=30)
        errors = self.proc.stderr.read()
        self.proc.stdout.close(); self.proc.stderr.close()
        need(self.proc.returncode == 0 and not errors, "N7 arithmetic exit")

    def __enter__(self): return self
    def __exit__(self, *_): self.close()


def pack7(words):
    need(len(words) == 7, "N7 digest width")
    return struct.pack("<7Q", *words)


def derive7(label, *pieces):
    raw = shake_256(label + b"\0" + b"".join(pieces)).digest(56)
    return [word & (2**63 - 1) for word, in struct.iter_unpack("<Q", raw)]


def successor_domains(c_network, activation_height, anchor):
    need(len(c_network) == len(anchor) == 32, "C network/anchor width")
    height = struct.pack("<I", activation_height)
    network = sha3_384(b"C2N7/N7-network/v1\0" + c_network + height + anchor).digest()
    scope = sha3_384(b"C2N7/N7-key-scope/v1\0" + c_network + height + anchor).digest()
    return network, scope


def successor_backup(c_seed, c_network, activation_height):
    need(len(c_seed) == len(c_network) == 32, "C seed/network width")
    return shake_256(
        b"C2N7/N7-backup/v1\0" + c_network + struct.pack("<I", activation_height) + c_seed
    ).digest(48)


def n7_crypto(node, script, operation, body):
    run = subprocess.run(
        [str(node), str(script), operation], input=body,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    need(run.returncode == 0 and not run.stderr, "N7 cryptographic role")
    return run.stdout


def note_bytes(note):
    return (pack7(note["owner"]) + struct.pack("<8I", *note["asset"])
            + pack7(note["salt"]) + struct.pack("<QQ", note["native"], note["token"]))


def decode_note(raw):
    need(len(raw) == 160, "N7 note plaintext")
    return {"owner": list(struct.unpack("<7Q", raw[:56])),
            "asset": list(struct.unpack("<8I", raw[56:88])),
            "salt": list(struct.unpack("<7Q", raw[88:144])),
            "native": int.from_bytes(raw[144:152], "little"),
            "token": int.from_bytes(raw[152:160], "little")}


def map_asset(words4):
    return list(struct.unpack("<8I", struct.pack("<4Q", *words4)))


def load_json(path):
    with Path(path).open("rb") as source:
        return json.load(source)


_IMPORTED_DEVNET = None


def import_deployment(deployment):
    """Import only from the copied disposable deployment."""
    import importlib
    global _IMPORTED_DEVNET

    devnet = Path(deployment).resolve() / "devnet"
    need(devnet.is_dir() and not devnet.is_symlink(), "deployment/devnet")
    if _IMPORTED_DEVNET is not None and _IMPORTED_DEVNET != devnet:
        for name, value in list(sys.modules.items()):
            origin = getattr(value, "__file__", None)
            if origin is not None and Path(origin).resolve().is_relative_to(_IMPORTED_DEVNET):
                del sys.modules[name]
        importlib.invalidate_caches()
    sys.path.insert(0, str(devnet))
    try:
        result = (
            importlib.import_module("wallet_c"),
            importlib.import_module("chain"),
            importlib.import_module("consensus"),
        )
        need(all(Path(value.__file__).resolve().is_relative_to(devnet) for value in result), "deployment import origin")
        _IMPORTED_DEVNET = devnet
        return result
    finally:
        sys.path.remove(str(devnet))


def selected_lineage(chain, archive, tip):
    blocks = Path(archive) / "blocks"
    need(len(tip) == 64, "selected tip")
    result = []
    current = bytes.fromhex(tip)
    while current != chain.GENESIS:
        path = checked_file(blocks / (current.hex() + ".bin"))
        raw = path.read_bytes()
        need(chain.block_id(raw) == current, "archived C block identity")
        block = chain.decode_block(raw)
        result.append(raw)
        current = block.parent
        need(len(result) <= 2**16, "C lineage bound")
    result.reverse()
    need(result and chain.decode_block(result[-1]).height > 0, "empty selected lineage")
    return result


def replay_selected(lab, chain, archive, tip, expected_height, node="a"):
    lab.initialize()
    lab.launch(node)
    lab.links(node, [])
    for raw in selected_lineage(chain, archive, tip):
        reply, body = lab.request(node, "publish", raw)
        need(not body and reply.get("id") == chain.block_id(raw).hex(), "C block replay")
    status = lab.status(node)
    need(status["tip"] == tip and status["height"] == expected_height, "selected C replay tip")
    return status


def spent_set(lab, node="a"):
    status, pages = lab.snapshot(node)
    raw = pages[-1]
    need(len(raw) % 32 == 0, "C spent page width")
    return status, {raw[i:i + 32] for i in range(0, len(raw), 32)}


def tree2(oracle, leaves):
    need(len(leaves) == 2, "two successor leaves")
    empty = [oracle.call("empty")]
    for level in range(39):
        empty.append(oracle.call("parent", level=level, left=empty[-1], right=empty[-1]))
    root = oracle.call("parent", level=0, left=leaves[0], right=leaves[1])
    for level in range(1, 40):
        root = oracle.call("parent", level=level, left=root, right=empty[level])
    paths = ([leaves[1], *empty[1:]], [leaves[0], *empty[1:]])
    need(all(len(path) == 40 for path in paths), "N7 path depth")
    return root, paths


def tree_root(oracle, leaves):
    need(len(leaves) in (2, 4), "bounded N7 tree leaf count")
    empty = [oracle.call("empty")]
    for level in range(39):
        empty.append(oracle.call("parent", level=level, left=empty[-1], right=empty[-1]))
    layer = list(leaves)
    level = 0
    while len(layer) > 1:
        layer = [
            oracle.call("parent", level=level, left=layer[i], right=layer[i + 1])
            for i in range(0, len(layer), 2)
        ]
        level += 1
    root = layer[0]
    for height in range(level, 40):
        root = oracle.call("parent", level=height, left=root, right=empty[height])
    return root


def n7_activation_id(c_network, activation, anchor, parent_tip):
    need(len(c_network) == len(anchor) == len(parent_tip) == 32, "N7 activation fields")
    return sha3_384(
        b"C2N7/N7-activation/v1\0"
        + c_network + struct.pack("<I", activation) + anchor + parent_tip
    ).digest()


def n7_header(network, root, count, fee, nfs, outputs, receipts):
    need(
        len(network) == 48 and len(root) == 7 and count > 0 and fee == 3
        and len(nfs) == len(outputs) == len(receipts) == 2
        and all(len(receipt) == N7_RECEIPT_BYTES for receipt in receipts),
        "N7P2 header shape",
    )
    return (
        b"N7P2" + b"\0" + network + pack7(root) + struct.pack("<QQ", count, fee)
        + b"".join(pack7(value) for value in (*nfs, *outputs))
        + b"".join(receipts)
    )


def n7_statement(activation_id, header):
    need(len(activation_id) == 48 and len(header) == 3837, "N7P2 context input")
    need(header[:5] == b"N7P2\0", "ordinary N7P2 transfer")
    count, fee = struct.unpack_from("<QQ", header, 109)
    digests = [list(struct.unpack("<7Q", header[pos:pos + 56])) for pos in (53, 125, 181, 237, 293)]
    context = struct.unpack(
        "<12I", sha3_384(b"N7P2/proof-context\0" + activation_id + header).digest()
    )
    return {
        "root": digests[0], "count": count, "fee": fee,
        "context": list(context), "nullifiers": digests[1:3], "outputs": digests[3:5],
    }


def n7_packet(header, proof):
    need(0 < len(proof) <= 1024 * 1024, "N7P2 proof length")
    return header + struct.pack("<I", len(proof)) + proof


def parse_n7_packet(raw, activation_id):
    need(len(raw) > 3841 and raw[:5] == b"N7P2\0", "N7P2 packet")
    header = raw[:3837]
    size, = struct.unpack_from("<I", raw, 3837)
    need(size > 0 and len(raw) == 3841 + size, "N7P2 packet framing")
    receipts = (header[349:2093], header[2093:3837])
    return n7_statement(activation_id, header), raw[3841:], receipts


class N7Ledger:
    """Minimal same-network ordinary N7 transfer admission state."""

    def __init__(self, root, count, activation_id, verify, current_outputs, append_outputs):
        self.root = tuple(root)
        self.count = count
        self.activation_id = activation_id
        self.verify = verify
        self.spent = set()
        self.outputs = {tuple(cm) for cm in current_outputs}
        need(len(self.outputs) == count, "N7 initial output state")
        self.append_outputs = append_outputs
        self.fees = 0
        self.packets = []
        self.history = []

    def snapshot(self):
        return (
            self.root, self.count, self.fees, frozenset(self.spent),
            frozenset(self.outputs), len(self.packets), len(self.history),
        )

    def admit(self, raw):
        before = self.snapshot()
        try:
            statement, proof, _ = parse_n7_packet(raw, self.activation_id)
            need(tuple(statement["root"]) == self.root and statement["count"] == self.count, "N7 current root/count")
            need(statement["fee"] == 3, "N7 exact fee")
            nfs = tuple(map(tuple, statement["nullifiers"]))
            cms = tuple(map(tuple, statement["outputs"]))
            need(len(set(nfs)) == len(set(cms)) == 2, "N7 duplicate effect")
            need(not any(nf in self.spent for nf in nfs), "N7 spent nullifier")
            need(not any(cm in self.outputs for cm in cms), "N7 duplicate output")
            self.verify(statement, proof)
            next_root = tuple(self.append_outputs(cms))
            need(len(next_root) == 7, "N7 appended root")
            self.history.append(
                (self.root, self.count, self.fees, set(self.spent), set(self.outputs), list(self.packets))
            )
            self.spent.update(nfs); self.outputs.update(cms); self.packets.append(raw)
            self.root = next_root
            self.count += len(cms)
            self.fees += statement["fee"]
            return statement
        except BaseException:
            need(self.snapshot() == before, "non-atomic N7 rejection")
            raise

    def rollback(self):
        need(self.history, "N7 rollback history")
        root, count, fees, spent, outputs, packets = self.history.pop()
        self.root, self.count, self.fees = root, count, fees
        self.spent, self.outputs, self.packets = spent, outputs, packets


def parse_time_v(path):
    aliases = {
        "User time (seconds)": "user_s",
        "System time (seconds)": "system_s",
        "Elapsed (wall clock) time (h:mm:ss or m:ss)": "wall_text",
        "Maximum resident set size (kbytes)": "max_rss_KiB",
    }
    result = {}
    for line in Path(path).read_text().splitlines():
        for label, key in aliases.items():
            prefix = "\t" + label + ": "
            if line.startswith(prefix):
                value = line[len(prefix):]
                result[key] = int(value) if key == "max_rss_KiB" else (
                    float(value) if key.endswith("_s") else value
                )
    need(set(result) == set(aliases.values()), "resource record")
    return result


def measured(command, stdin, time_path, *, expect_success=True, env=None):
    started = time.monotonic()
    run = subprocess.run(
        ["/usr/bin/time", "-v", "-o", str(time_path), *map(str, command)],
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
    )
    metric = parse_time_v(time_path)
    metric["observed_wall_s"] = time.monotonic() - started
    metric["exit_code"] = run.returncode
    need((run.returncode == 0) == expect_success, "measured role outcome")
    if expect_success:
        need(not run.stderr, "measured role wrote diagnostics")
    return run.stdout, metric


def prove(binary, statement, witness, folder, label, expect_success=True):
    statement_path = Path(folder) / (label + ".statement.json")
    proof_path = Path(folder) / (label + ".proof")
    time_path = Path(folder) / (label + ".time")
    write_json(statement_path, statement, private=True)
    output, metric = measured(
        [binary, "prove", statement_path, proof_path],
        json.dumps(witness, separators=(",", ":")).encode(),
        time_path,
        expect_success=expect_success,
        env={**os.environ, "RAYON_NUM_THREADS": "2"},
    )
    if not expect_success:
        need(not proof_path.exists(), "rejected assignment emitted proof")
        return None, metric
    role = json.loads(output)
    need(role.get("role") == "prove", "prover report")
    return proof_path.read_bytes(), {**metric, **role}


def verifier_callback(binary, private_dir):
    counter = iter(range(10_000))

    def verify(statement, proof):
        ident = next(counter)
        statement_path = Path(private_dir) / f"verify-{ident}.statement.json"
        proof_path = Path(private_dir) / f"verify-{ident}.proof"
        write_json(statement_path, statement, private=True)
        write_private(proof_path, proof)
        return verify_bridge(binary, statement_path, proof_path)

    return verify


def make_successors(oracle, node, crypto_script, network, scope, backup, openings, packet_id):
    sk = derive7(b"N7P2/spend", scope, backup)
    owner = oracle.call("owner", sk=sk)
    kem = n7_crypto(node, crypto_script, "address", scope + backup)
    need(len(kem) == 1568, "N7 KEM address")
    notes, cms, receipts = [], [], []
    for slot, opening in enumerate(openings):
        note = {
            "owner": owner,
            "asset": map_asset(opening["asset"]),
            "native": opening["native"],
            "token": opening["token"],
            "salt": derive7(b"C2N7/N7-successor-salt/v1", backup, packet_id, bytes([slot])),
        }
        cm = oracle.call("note", note=note)
        ad = network + bytes([slot]) + pack7(cm)
        receipt = n7_crypto(node, crypto_script, "seal", ad + kem + note_bytes(note))
        need(len(receipt) == N7_RECEIPT_BYTES, "N7 receipt")
        notes.append(note); cms.append(cm); receipts.append(receipt)
    return sk, owner, notes, cms, tuple(receipts)


def public_preflight(args):
    checked_file(args.manifest)
    checked_file(args.bridge)
    checked_file(args.n7)
    checked_file(args.node)
    checked_file(args.crypto)
    checked_file(args.exporter)
    need(
        all(os.access(path, os.X_OK) for path in (args.bridge, args.n7, args.node, args.exporter)),
        "executable role",
    )
    checked_file(args.c_seed, private=True, size=32)
    deployment = Path(args.deployment)
    archive = Path(args.archive)
    need(deployment.is_dir() and not deployment.is_symlink(), "deployment")
    need((deployment / "c-runtime/native").is_file(), "C verifier")
    need((deployment / "c-keys/managed.vk").is_file(), "C registration")
    manifest = load_json(args.manifest)
    need(args.activation_height == args.selected_height + 2, "H25/H26/H27 schedule")
    tip = args.selected_tip or manifest["tips"][args.tip_name]["tip"]
    wallet_c, chain, _ = import_deployment(deployment)
    lineage = selected_lineage(chain, archive, tip)
    need(chain.decode_block(lineage[-1]).height == args.selected_height, "preflight height")
    result = {
        "ready": True,
        "selected_tip": tip,
        "selected_height": args.selected_height,
        "activation_height": args.activation_height,
        "lineage_blocks": len(lineage),
        "bridge_sha256": digest_file(args.bridge),
        "n7_sha256": digest_file(args.n7),
        "exporter_sha256": digest_file(args.exporter),
        "private_inputs": [{"kind": "original-C-backup", "bytes": 32}],
        "private_bytes_read": False,
    }
    del wallet_c
    return result


def recover_and_spend(args):
    """Fresh process: original C backup plus authenticated public history only."""
    seed = checked_file(args.c_seed, private=True, size=32).read_bytes()
    activation = load_json(args.activation)
    bundle = BridgeBundle.decode(checked_file(args.bundle).read_bytes())
    parent_block = checked_file(args.parent_block).read_bytes()
    c_network = bytes.fromhex(activation["c_network"])
    anchor = bytes.fromhex(activation["activation_anchor"])
    parent_tip = bytes.fromhex(activation["parent_tip"])
    height = activation["activation_height"]
    network, scope = successor_domains(c_network, height, anchor)
    need(network.hex() == activation["n7_network"] and scope.hex() == activation["n7_scope"], "activation domains")
    backup = successor_backup(seed, c_network, height)
    with tempfile.TemporaryDirectory(prefix="recover-", dir=args.private_root) as raw_folder:
        folder = Path(raw_folder)
        c_home = folder / "c-home"
        c_home.mkdir(mode=0o700)
        shutil.copytree(Path(args.deployment).resolve(), c_home / "deployment", symlinks=False)
        wallet_c, chain, consensus = import_deployment(c_home / "deployment")
        need(chain.NETWORK == c_network, "recovery C network")
        lab = wallet_c.FundedLab(c_home, "C")
        try:
            status = replay_selected(
                lab, chain, args.archive, activation["selected_tip"], activation["selected_height"]
            )
            need(chain.block_id(parent_block) == parent_tip, "authenticated bridge parent identity")
            decoded_parent = chain.decode_block(parent_block)
            need(
                decoded_parent.parent.hex() == activation["selected_tip"]
                and decoded_parent.height == activation["parent_height"],
                "bridge parent lineage",
            )
            need(not decoded_parent.packets, "bridge parent must be empty")
            reply, body = lab.request("a", "publish", parent_block)
            need(not body and reply.get("id") == parent_tip.hex(), "bridge parent replay")
            parent_status, parent_spent = spent_set(lab)
            need(
                parent_status["tip"] == parent_tip.hex()
                and parent_status["height"] == activation["parent_height"],
                "authenticated bridge parent",
            )
            effect = verify_c(
                c_home / "deployment/c-runtime/native",
                c_home / "deployment/c-keys",
                bundle.c_packet,
            )
            branch = BranchContext(
                c_network, parent_tip, activation["parent_height"], height,
                ((anchor, activation["selected_height"], activation["selected_funded_depth"]),),
            )
            branch.check(effect)
            need(all(packed(nf) not in parent_spent for nf in effect.nullifiers), "bridge C inputs spent at parent")
            successors = tuple(map(tuple, bundle.statement["successor_outputs"]))
            expected_context = bridge_context(
                branch, bundle.c_packet, effect, successors, bundle.successor_receipts
            )
            need(
                tuple(bundle.statement["bridge_context"]) == expected_context
                and tuple(map(tuple, bundle.statement["c_input_nullifiers"])) == effect.nullifiers
                and tuple(map(tuple, bundle.statement["transient_c_outputs"])) == effect.outputs,
                "recovered bridge statement binding",
            )
            public_statement = folder / "bridge.statement.json"
            public_proof = folder / "bridge.proof"
            write_json(public_statement, bundle.statement, private=True)
            write_private(public_proof, bundle.equality_proof)
            verify_bridge(args.bridge, public_statement, public_proof)
        finally:
            try:
                lab.stop()
            except Exception:
                pass

        with N7Oracle(args.n7) as oracle:
            sk = derive7(b"N7P2/spend", scope, backup)
            owner = oracle.call("owner", sk=sk)
            found = []
            for slot, (cm, receipt) in enumerate(zip(bundle.statement["successor_outputs"], bundle.successor_receipts)):
                ad = network + bytes([slot]) + pack7(cm)
                raw = n7_crypto(args.node, args.crypto, "open", ad + scope + backup + receipt)
                if not raw:
                    continue
                note = decode_note(raw)
                need(note["owner"] == owner and oracle.call("note", note=note) == cm, "recovered N7 note")
                found.append((slot, note, cm))
            need(len(found) == 2, "backup-only receipt discovery")
            root, paths = tree2(oracle, bundle.statement["successor_outputs"])
            chosen = next((row for row in found if row[1]["native"] >= 3), None)
            need(chosen is not None, "recovered note cannot pay onward fee")
            index, note, cm = chosen
            real_nf = oracle.call("nf", sk=sk, index=index, commitment=cm)
            padding_nf = oracle.call("padding", sk=sk, nullifier=real_nf)
            outputs = [
                {**note, "native": note["native"] - 3,
                 "salt": derive7(b"C2N7/N7-onward-salt/v1", backup, bundle.identity(), b"\0")},
                {"owner": owner, "asset": [0] * 8, "native": 0, "token": 0,
                 "salt": derive7(b"C2N7/N7-onward-salt/v1", backup, bundle.identity(), b"\1")},
            ]
            out_cms = [oracle.call("note", note=value) for value in outputs]
            kem = n7_crypto(args.node, args.crypto, "address", scope + backup)
            receipts = tuple(
                n7_crypto(args.node, args.crypto, "seal", network + bytes([slot]) + pack7(out_cms[slot]) + kem + note_bytes(outputs[slot]))
                for slot in range(2)
            )
            header = n7_header(
                network, root, 2, 3, (real_nf, padding_nf), out_cms, receipts
            )
            activation_id = n7_activation_id(c_network, height, anchor, parent_tip)
            statement = n7_statement(activation_id, header)
            witness = {"inputs": [{"note": note, "sk": sk, "index": index, "path": paths[index]}], "outputs": outputs}
            proof, prove_metric = prove(args.n7, statement, witness, folder, "onward")
            packet = n7_packet(header, proof)
            statement_path = folder / "onward.public.json"
            proof_path = folder / "onward.public.proof"
            write_json(statement_path, statement, private=True); write_private(proof_path, proof)
            output, verify_metric = measured(
                [args.n7, "verify", statement_path, proof_path], b"", folder / "onward.verify.time",
                env={**os.environ, "RAYON_NUM_THREADS": "2"},
            )
            verdict = json.loads(output)
            need(verdict.get("accepted") is True, "fresh N7 verification")

            def n7_verify(public, body):
                serial = next(n7_verify.counter)
                sp = folder / f"n7-{serial}.statement.json"
                pp = folder / f"n7-{serial}.proof"
                write_json(sp, public, private=True); write_private(pp, body)
                run = subprocess.run(
                    [str(args.n7), "verify", str(sp), str(pp)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                )
                need(run.returncode == 0 and json.loads(run.stdout).get("accepted") is True, "N7 public verifier")
            n7_verify.counter = iter(range(1000))

            bridge_cms = tuple(map(tuple, bundle.statement["successor_outputs"]))

            def append_outputs(new):
                return tree_root(oracle, [*bridge_cms, *map(list, new)])

            n7_ledger = N7Ledger(
                root, 2, activation_id, n7_verify, bridge_cms, append_outputs
            )
            n7_ledger.admit(packet)
            admitted = n7_ledger.snapshot()
            need(
                n7_ledger.count == 4 and n7_ledger.fees == 3
                and len(n7_ledger.outputs) == 4,
                "complete N7 ledger transition",
            )
            try:
                n7_ledger.admit(packet)
            except ValueError:
                need(n7_ledger.snapshot() == admitted, "N7 replay")
            else:
                raise ValueError("N7 replay accepted")

            n7_ledger.rollback()
            need(
                n7_ledger.count == 2 and n7_ledger.fees == 0
                and n7_ledger.root == tuple(root) and n7_ledger.outputs == set(bridge_cms),
                "N7 rollback",
            )
            n7_ledger.admit(packet)
            need(n7_ledger.snapshot() == admitted, "N7 reinclusion")

            for label, changed in (
                ("corrupt-proof", packet[:-1] + bytes([packet[-1] ^ 1])),
                ("changed-statement", packet[:237] + bytes([packet[237] ^ 1]) + packet[238:]),
            ):
                fresh = N7Ledger(
                    root, 2, activation_id, n7_verify, bridge_cms, append_outputs
                )
                before = fresh.snapshot()
                try:
                    fresh.admit(changed)
                except ValueError:
                    need(fresh.snapshot() == before, label + " atomicity")
                else:
                    raise ValueError(label + " accepted")

            public_output = Path(args.public_output)
            need(public_output.is_dir(), "public recovery output")
            (public_output / "onward.n7p2").write_bytes(packet)
            (public_output / "onward.proof").write_bytes(proof)
            (public_output / "onward.receipts").write_bytes(b"".join(receipts))
            write_json(public_output / "onward.statement.json", statement)
            result = {
                "restored_from_original_seed_only": True,
                "reverified_c_and_bridge": True,
                "discovered_receipts": 2,
                "membership_count": 2,
                "activation_id_sha3_384": activation_id.hex(),
                "ordinary_n7p2_packet_bytes": len(packet),
                "ordinary_n7p2_packet_sha3_384": sha3_384(packet).hexdigest(),
                "onward_proof_bytes": len(proof),
                "onward_proof_sha3_384": sha3_384(proof).hexdigest(),
                "proof": prove_metric,
                "verify": {**verify_metric, **verdict},
                "public_statement": statement,
                "successor_receipt_bytes": sum(map(len, receipts)),
                "ledger_admitted": True,
                "ledger_count_after": 4,
                "ledger_fee_after": 3,
                "ledger_rollback_reinclusion": True,
                "replay_rejected": True,
                "corrupted_proof_rejected_atomically": True,
                "changed_statement_rejected_atomically": True,
            }
            write_json(args.result, result, private=True)
    return result


def genuine_run(args):
    os.umask(0o077)
    private_root = require_tmp(args.private_root)
    output = Path(args.public_output).resolve()
    need(private_root not in output.parents and output != private_root, "public output inside private root")
    need(not output.exists(), "public output already exists")
    preflight = public_preflight(args)
    output.mkdir(mode=0o755, parents=False)
    work = private_root / "genuine-run"
    need(not work.exists(), "private run already exists")
    work.mkdir(mode=0o700)
    home = work / "c-home"
    home.mkdir(mode=0o700)
    shutil.copytree(Path(args.deployment).resolve(), home / "deployment", symlinks=False)
    wallet_c, chain, consensus = import_deployment(home / "deployment")
    manifest = load_json(args.manifest)
    tip = args.selected_tip or manifest["tips"][args.tip_name]["tip"]
    lab = wallet_c.FundedLab(home, "C")
    try:
        status = replay_selected(lab, chain, args.archive, tip, args.selected_height, "a")
        clean_status = replay_selected(lab, chain, args.archive, tip, args.selected_height, "b")
        need(clean_status["tip"] == status["tip"], "independent C branch replay")
        c_network = chain.NETWORK
        need(bytes.fromhex(status["network"]) == c_network, "C network")
        before_status, before_spent = spent_set(lab)
        need(before_status["tip"] == tip, "spentness tip")
        depth = consensus.funded_depth(status["notes"])
        anchor = bytes.fromhex(status["anchor"])

        wallet_started = time.monotonic()
        balance = lab.restore("migration-owner", Path(args.c_seed), "a")
        assets = balance.get("assets", {})
        need(len(assets) <= 1 and balance["balance"] > 3, "funded owner inventory")
        asset, token = next(iter(assets.items()), ("00" * 32, 0))
        send_native = balance["balance"] - 3
        intent = "c2n7-migration-" + sha256(bytes.fromhex(tip)).hexdigest()[:20]
        payment = lab.send(
            "migration-owner", "migration-owner", send_native, asset, token, "a", intent
        )
        packet = lab.request("a", "tx", id=payment["tx"])[1]
        wallet_wall = time.monotonic() - wallet_started
        packet_sha = sha256(packet).hexdigest()
        archived_packets = {path.stem for path in (Path(args.archive) / "packets").glob("*.bin")}
        need(packet_sha not in archived_packets, "fresh C migration packet")
        effect = verify_c(home / "deployment/c-runtime/native", home / "deployment/c-keys", packet)
        need(effect.anchor == anchor and effect.height == status["height"] and effect.depth == depth, "C effect branch")
        need(all(packed(nf) not in before_spent for nf in effect.nullifiers), "fresh C inputs already spent")

        # The accepted bridge branch has a real, independently mined empty H26
        # parent. Node b never received the pending migration packet.
        clean_parent = lab.mine("b", 1)
        need(clean_parent["height"] == args.activation_height - 1, "bridge parent height")
        parent_status, parent_spent = spent_set(lab, "b")
        need(parent_status["tip"] == clean_parent["tip"], "bridge parent selected tip")
        need(all(packed(nf) not in parent_spent for nf in effect.nullifiers), "bridge parent spentness")
        parent_tip = bytes.fromhex(parent_status["tip"])
        parent_block = lab.request("b", "block", id=parent_status["tip"])[1]
        need(chain.block_id(parent_block) == parent_tip, "bridge parent block")
        need(not chain.decode_block(parent_block).packets, "bridge parent must be empty")
        branch = BranchContext(
            c_network, parent_tip, parent_status["height"], args.activation_height,
            ((anchor, status["height"], depth),),
        )

        openings = []
        with OpeningExporter(args.exporter, home / "deployment/c-keys", args.c_seed) as exporter:
            for cm, receipt in zip(effect.outputs, effect.receipts):
                opening = exporter.open(packed(cm), receipt)
                kind = opening.pop("receipt_kind")
                need(kind in (2, 3), "C receipt kind")
                openings.append(opening)

        packet_id = sha3_384(packet).digest()
        n7_network, n7_scope = successor_domains(c_network, args.activation_height, anchor)
        c_seed = checked_file(args.c_seed, private=True, size=32).read_bytes()
        backup = successor_backup(c_seed, c_network, args.activation_height)
        del c_seed
        with N7Oracle(args.n7) as oracle:
            _, _, successor_notes, successor_cms, successor_receipts = make_successors(
                oracle, args.node, args.crypto, n7_network, n7_scope, backup, openings, packet_id
            )
        del backup
        context = bridge_context(branch, packet, effect, successor_cms, successor_receipts)
        witness = {"transient_c_outputs": openings, "successor_outputs": successor_notes}
        derive_request = {
            "bridge_context": list(context),
            "c_input_nullifiers": list(map(list, effect.nullifiers)),
            "witness": witness,
        }
        derived = subprocess.run(
            [str(args.bridge), "derive"],
            input=json.dumps(derive_request, separators=(",", ":")).encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        need(derived.returncode == 0 and not derived.stderr, "bridge statement derivation")
        statement = json.loads(derived.stdout)
        expected_statement = {
            "bridge_context": list(context),
            "c_input_nullifiers": list(map(list, effect.nullifiers)),
            "transient_c_outputs": list(map(list, effect.outputs)),
            "successor_outputs": successor_cms,
        }
        need(statement == expected_statement, "independent bridge statement")
        proof, bridge_prove = prove(args.bridge, statement, witness, work, "bridge")

        statement_path = work / "bridge.verify.statement.json"
        proof_path = work / "bridge.verify.proof"
        write_json(statement_path, statement, private=True); write_private(proof_path, proof)
        verify_stdout, bridge_verify = measured(
            [args.bridge, "verify", statement_path, proof_path], b"", work / "bridge.verify.time",
            env={**os.environ, "RAYON_NUM_THREADS": "2"},
        )
        bridge_verdict = json.loads(verify_stdout)
        need(bridge_verdict.get("accepted") is True, "bridge public verification")
        c_verify = lambda raw: verify_c(
            home / "deployment/c-runtime/native", home / "deployment/c-keys", raw
        )

        negative_controls = {}
        for field in ("native", "token", "asset"):
            changed = copy.deepcopy(witness)
            if field == "asset":
                changed["transient_c_outputs"][0][field][0] ^= 1
            else:
                changed["transient_c_outputs"][0][field] += 1
            _, metric = prove(
                args.bridge, statement, changed, work, "changed-" + field,
                expect_success=False,
            )
            negative_controls["changed_" + field] = {
                "outcome": "unsatisfied-relation", "resources": metric,
            }

        def rejected_public(name, changed_statement, changed_proof=proof):
            public_path = work / (name + ".statement.json")
            public_proof = work / (name + ".proof")
            write_json(public_path, changed_statement, private=True)
            write_private(public_proof, changed_proof)
            try:
                verify_bridge(args.bridge, public_path, public_proof)
            except ValueError:
                negative_controls[name] = "rejected-by-public-verifier"
            else:
                raise ValueError(name + " accepted")

        for name, field in (
            ("changed_c_commitment", "transient_c_outputs"),
            ("changed_n7_commitment", "successor_outputs"),
            ("changed_bridge_context", "bridge_context"),
        ):
            changed = copy.deepcopy(statement)
            if field == "bridge_context":
                changed[field][0] ^= 1
            else:
                changed[field][0][0] ^= 1
            rejected_public(name, changed)
        corrupt_proof = bytearray(proof); corrupt_proof[len(corrupt_proof) // 2] ^= 1
        rejected_public("corrupted_equality_proof", statement, bytes(corrupt_proof))

        corrupt_c = bytearray(packet)
        corrupt_c[20] ^= 1
        try:
            c_verify(bytes(corrupt_c))
        except ValueError:
            negative_controls["invalid_c_proof"] = "rejected-by-approved-C-verifier"
        else:
            raise ValueError("corrupted C proof accepted")

        bridge_bundle = BridgeBundle(statement, packet, proof, successor_receipts)
        ledger = Ledger(args.activation_height)
        eq_verify = verifier_callback(args.bridge, work)
        before_snapshot = ledger.snapshot()
        ledger.admit(
            branch, bridge_bundle, c_verify, eq_verify,
            lambda nf: packed(nf) in parent_spent,
        )
        admitted_snapshot = ledger.snapshot()
        need(not any(ledger.contains_transient_c_output(cm) for cm in effect.outputs), "transient C output insertion")
        try:
            ledger.admit(
                branch, bridge_bundle, c_verify, eq_verify,
                lambda nf: packed(nf) in parent_spent,
            )
        except Exception:
            need(ledger.snapshot() == admitted_snapshot, "bridge replay atomicity")
            negative_controls["bridge_replay"] = "rejected-atomically"
        else:
            raise ValueError("bridge replay accepted")

        changed_receipt = bytearray(successor_receipts[0]); changed_receipt[0] ^= 1
        receipt_bundle = BridgeBundle(
            statement, packet, proof, (bytes(changed_receipt), successor_receipts[1])
        )
        receipt_ledger = Ledger(args.activation_height)
        try:
            receipt_ledger.admit(
                branch, receipt_bundle, c_verify, eq_verify,
                lambda nf: packed(nf) in parent_spent,
            )
        except ValueError:
            need(receipt_ledger.snapshot()["blocks"] == 0, "receipt rejection atomicity")
            negative_controls["changed_successor_receipt"] = "rejected-atomically"
        else:
            raise ValueError("changed successor receipt accepted")

        for name, wrong in (
            ("wrong_anchor", BranchContext(c_network, parent_tip, parent_status["height"], args.activation_height, ((b"x" * 32, status["height"], depth),))),
            ("wrong_depth", BranchContext(c_network, parent_tip, parent_status["height"], args.activation_height, ((anchor, status["height"], depth + 1),))),
        ):
            rejected = Ledger(args.activation_height)
            try:
                rejected.admit(
                    wrong, bridge_bundle, c_verify, eq_verify,
                    lambda nf: packed(nf) in parent_spent,
                )
            except ValueError:
                need(rejected.snapshot()["blocks"] == 0, name + " atomicity")
                negative_controls[name] = "rejected-atomically"
            else:
                raise ValueError(name + " accepted")
        with_rollback = ledger.snapshot()
        ledger.rollback(args.activation_height)
        need(ledger.snapshot() == before_snapshot, "bridge rollback")
        ledger.admit(
            branch, bridge_bundle, c_verify, eq_verify,
            lambda nf: packed(nf) in parent_spent,
        )
        need(ledger.snapshot() == with_rollback, "bridge reinclusion")

        # Bridge first: the exact, already verified C packet cannot be stripped
        # and admitted standalone once the bridge schedule is active.
        try:
            ledger.ordinary_c_spend(args.activation_height, effect.nullifiers)
        except ValueError as error:
            need(str(error) == "standalone C retired at bridge activation", "post-activation strip rejection")
        else:
            raise ValueError("post-activation stripped C packet accepted")

        # Ordinary first on the legacy branch: mine the same genuine packet at
        # H+1, authenticate the selected spent page, then reject a later bridge
        # via the verifier-owned callback before this ledger inserts anything.
        mined = lab.mine("a", 1)
        need(mined["height"] == args.selected_height + 1, "ordinary competing C inclusion")
        ordinary_status, ordinary_spent = spent_set(lab)
        need(all(packed(nf) in ordinary_spent for nf in effect.nullifiers), "ordinary C spent identities")
        conflicting = Ledger(args.activation_height)
        conflicting.ordinary_c_spend(args.activation_height - 1, effect.nullifiers)
        try:
            conflicting.admit(
                branch, bridge_bundle, c_verify, eq_verify,
                lambda nf: packed(nf) in ordinary_spent,
            )
        except ValueError as error:
            need(str(error) == "C input already spent on selected branch", "ordinary-first conflict reason")
        else:
            raise ValueError("ordinary-first bridge conflict accepted")
        need(conflicting.snapshot()["successor_outputs"] == 0, "ordinary-first atomicity")

        bundle_path = output / "bridge.bundle"
        bundle_path.write_bytes(bridge_bundle.encode())
        activation = {
            "version": 1,
            "c_network": c_network.hex(),
            "activation_height": args.activation_height,
            "activation_anchor": anchor.hex(),
            "n7_network": n7_network.hex(),
            "n7_scope": n7_scope.hex(),
            "selected_tip": tip,
            "selected_height": status["height"],
            "selected_funded_count": status["notes"],
            "selected_funded_depth": depth,
            "parent_tip": parent_status["tip"],
            "parent_height": parent_status["height"],
        }
        activation_path = output / "ACTIVATION.json"
        write_json(activation_path, activation)
        parent_path = output / "bridge-parent-H26.bin"
        parent_path.write_bytes(parent_block)

        recovery_result = work / "recovery-result.json"
        recovery_stdout, recovery_metric = measured(
            [
                sys.executable, "-IB", __file__, "recover-spend",
                "--private-root", private_root,
                "--c-seed", args.c_seed,
                "--activation", activation_path,
                "--bundle", bundle_path,
                "--parent-block", parent_path,
                "--deployment", args.deployment,
                "--archive", args.archive,
                "--bridge", args.bridge,
                "--n7", args.n7,
                "--node", args.node,
                "--crypto", args.crypto,
                "--result", recovery_result,
                "--public-output", output,
            ],
            b"", work / "recovery.time",
            env={**os.environ, "RAYON_NUM_THREADS": "2"},
        )
        need(not recovery_stdout, "recovery process leaked output")
        recovery = load_json(recovery_result)

        result = {
            "version": 1,
            "outcome": "genuine-fresh-C-to-N7-bridge-and-onward-spend",
            "preflight": preflight,
            "source_and_binaries": {
                "bridge_sha256": digest_file(args.bridge),
                "bridge_vk_sha3_384": digest_file(HERE / "bridge/registered.vk", "sha3_384"),
                "n7_sha256": digest_file(args.n7),
                "c_verifier_sha256": digest_file(home / "deployment/c-runtime/native"),
                "c_vk_sha3_384": digest_file(home / "deployment/c-keys/managed.vk", "sha3_384"),
                "exporter_sha256": digest_file(args.exporter),
            },
            "selected_branch": activation,
            "fresh_c_packet": {
                "sha256": packet_sha, "bytes": len(packet), "fee": effect.fee,
                "input_nullifiers": [packed(nf).hex() for nf in effect.nullifiers],
                "wallet_wall_s": wallet_wall,
                "prover_wall_s": payment["proving_wall_s"],
                "prover_cpu_s": payment["prover_cpu_s"],
                "prover_peak_rss_KiB": payment["prover_role_peak_rss_KiB"],
            },
            "bridge": {
                "proof_bytes": len(proof), "proof_sha3_384": sha3_384(proof).hexdigest(),
                "prove": bridge_prove,
                "verify": {**bridge_verify, **bridge_verdict},
                "bundle_bytes": len(bridge_bundle.encode()),
                "bundle_sha3_384": bridge_bundle.identity().hex(),
                "component_sizes": bridge_bundle.component_sizes(),
            },
            "ledger": {
                "before": before_snapshot, "admitted": admitted_snapshot,
                "rollback_reinclusion": True, "transient_c_outputs_inserted": False,
                "bridge_then_stripped_c": "rejected-by-version-schedule",
                "ordinary_c_then_bridge": "rejected-by-authenticated-selected-spentness",
                "ordinary_selected_tip": ordinary_status["tip"],
                "negative_controls": negative_controls,
            },
            "recovery": {**recovery, "fresh_process": recovery_metric},
            "private_dependency": False,
        }
        write_json(output / "RUN.json", result)
        return result
    finally:
        try:
            lab.stop()
        except Exception:
            pass


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    modes = value.add_subparsers(dest="mode", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--deployment", type=Path, required=True)
    common.add_argument("--archive", type=Path, required=True)
    common.add_argument("--manifest", type=Path, required=True)
    common.add_argument("--tip-name", default="paid")
    common.add_argument("--selected-tip")
    common.add_argument("--selected-height", type=int, default=25)
    common.add_argument("--activation-height", type=int, default=27)
    common.add_argument("--c-seed", type=Path, required=True)
    common.add_argument("--exporter", type=Path, required=True)
    common.add_argument("--bridge", type=Path, required=True)
    common.add_argument("--n7", type=Path, required=True)
    common.add_argument("--node", type=Path, required=True)
    common.add_argument("--crypto", type=Path, required=True)
    modes.add_parser("preflight", parents=[common])
    run = modes.add_parser("run", parents=[common])
    run.add_argument("--private-root", type=Path, required=True)
    run.add_argument("--public-output", type=Path, required=True)
    recover = modes.add_parser("recover-spend")
    recover.add_argument("--private-root", type=Path, required=True)
    recover.add_argument("--c-seed", type=Path, required=True)
    recover.add_argument("--activation", type=Path, required=True)
    recover.add_argument("--bundle", type=Path, required=True)
    recover.add_argument("--parent-block", type=Path, required=True)
    recover.add_argument("--deployment", type=Path, required=True)
    recover.add_argument("--archive", type=Path, required=True)
    recover.add_argument("--bridge", type=Path, required=True)
    recover.add_argument("--n7", type=Path, required=True)
    recover.add_argument("--node", type=Path, required=True)
    recover.add_argument("--crypto", type=Path, required=True)
    recover.add_argument("--result", type=Path, required=True)
    recover.add_argument("--public-output", type=Path, required=True)
    return value


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    args = parser().parse_args()
    if args.mode == "preflight":
        print(json.dumps(public_preflight(args), sort_keys=True))
    elif args.mode == "run":
        print(json.dumps(genuine_run(args), sort_keys=True))
    else:
        recover_and_spend(args)


if __name__ == "__main__":
    main()
