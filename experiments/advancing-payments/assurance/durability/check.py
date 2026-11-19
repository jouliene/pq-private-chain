"""Public-only process-death, branch retry and lost-ack tests for the APV2 state machine."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[2]))
from ingress import Endpoint, admit_queue, create_pool, recvexact, upload
from run import Resources, public_block, snapshot
from state import Ledger
from wire import check_genesis, need, packet_width, sha, split_block, u32


def fingerprint(node):
    """Hash all columns of all logical tables, including archived bodies and foreign keys."""
    h = hashlib.sha256()
    counts = {}
    for name, key in (("config", "id"), ("blocks", "h"), ("outs", "pos"), ("spent", "nf")):
        h.update(name.encode() + b"\0")
        counts[name] = 0
        for row in node.db.execute(f"SELECT * FROM {name} ORDER BY {key}"):
            counts[name] += 1
            for field in row:
                if isinstance(field, bytes):
                    tag, data = b"B", field
                elif isinstance(field, str):
                    tag, data = b"S", field.encode()
                elif isinstance(field, int):
                    tag, data = b"I", field.to_bytes(8, "little", signed=True)
                else:
                    need(field is None, "unexpected SQL type")
                    tag, data = b"N", b""
                h.update(tag + len(data).to_bytes(8, "little") + data)
    state = snapshot(node)
    return dict(table_rows=counts, logical_tables_sha256=h.hexdigest(),
                head=state["id"], height=state["height"], fees=state["fees"],
                ordered_commitments_sha256=state["ordered_commitments_sha256"],
                nullifier_set_sha256=state["nullifier_set_sha256"])


def prepared_block(args, trace, block_id):
    raw = public_block(args.evidence, trace["blocks"][block_id])
    need(sha(raw) == block_id, "block identity")
    return raw


def run_fork(args, node, trace):
    events = trace["events"]
    i = next(n for n, e in enumerate(events) if e["op"] == "switch" and len(e["blocks"]) >= 2)
    change = events[i]
    base = bytes.fromhex(change["base"])
    replacement = [prepared_block(args, trace, key) for key in change["blocks"]]
    first = split_block(replacement[0])[2]
    need(bool(first), "first replacement must contain an actual payment")
    if args.phase == "prepare":
        for e in events[:i]:
            if e["op"] == "extend":
                node.accept(prepared_block(args, trace, e["block"]))
            else:
                need(e["op"] in ("reject", "reject_switch"), "unexpected earlier switch")
            need(snapshot(node) == e["state"], "published pre-switch state")
        return fingerprint(node)
    if args.phase == "crash":
        # Reducing SQLite's cache encourages a disk-backed hot journal before SIGKILL.
        node.db.execute("PRAGMA cache_size=8")

        def pause_after_verified_prefix():
            yield replacement[0]
            need(node.db.in_transaction, "crash outside switch transaction")
            journal = Path(str(node.path) + "-journal")
            hdr, _, _ = split_block(replacement[0])
            need(node.head()["header"] == hdr, "replacement header not applied")
            need(node.db.execute("SELECT body FROM blocks ORDER BY h DESC LIMIT 1").fetchone()[0]
                 == replacement[0], "replacement body not applied")
            with journal.open("rb") as f:
                magic = f.read(8)
            state = dict(in_transaction=True, applied_prefix_block=change["blocks"][0],
                         applied_prefix_slots=packet_width(first), pending_blocks=len(replacement)-1,
                         journal_B=journal.stat().st_size, journal_magic=magic.hex(),
                         writer=fingerprint(node))
            print(json.dumps(state), flush=True)
            signal.pause()
            raise AssertionError("writer resumed unexpectedly")

        node.switch(base, pause_after_verified_prefix())
        raise AssertionError("crash did not interrupt switch")
    need(args.phase == "recover_retry", "unknown branch phase")
    recovered = fingerprint(node)
    need(snapshot(node) == events[i-1]["state"], "published old tip after recovery")
    integrity = node.db.execute("PRAGMA integrity_check").fetchall()
    need(len(integrity) == 1 and integrity[0][0] == "ok", "recovered SQLite state")
    need(not node.db.execute("PRAGMA foreign_key_check").fetchall(), "recovered foreign keys")
    node.switch(base, replacement)
    need(snapshot(node) == change["state"], "published retry state")
    return dict(recovered=recovered, retry=fingerprint(node), integrity="ok", foreign_keys="ok",
                retried_blocks=change["blocks"])


def pool_row(path):
    with sqlite3.connect(path) as reader:
        rows = reader.execute("SELECT seq,tx,arrival,direct,packet FROM pool ORDER BY seq").fetchall()
    need(len(rows) == 1, "expected exactly one durable offer")
    seq, tx, arrival, direct, packet = rows[0]
    need(sha(packet) == tx.hex(), "durable packet identity")
    return dict(seq=seq, tx=tx.hex(), arrival_ns=arrival, direct=direct)


def lost_ack(args, node, trace):
    event = next(e for e in trace["events"] if e["op"] == "extend")
    block = prepared_block(args, trace, event["block"])
    _, nonce, packet = split_block(block)
    need(packet_width(packet) == 1, "first payment must be a singleton")
    pool = args.work/"pool.sqlite"
    create_pool(pool)
    with tempfile.TemporaryDirectory(prefix="ap-ack-") as tmp:
        root = Path(tmp)
        primary = Endpoint(root/"primary", pool, False)
        direct = Endpoint(root/"direct", pool, True)
        try:
            with socket.socket(socket.AF_UNIX) as proxy, ThreadPoolExecutor(max_workers=1) as worker:
                proxy.bind(str(root/"drop-ack"))
                proxy.listen(1)
                proxy.settimeout(8)

                def drop_ack():
                    peer, _ = proxy.accept()
                    with peer, socket.socket(socket.AF_UNIX) as upstream:
                        peer.settimeout(5)
                        upstream.settimeout(5)
                        upstream.connect(primary.path)
                        head = recvexact(peer, 4)
                        need(head == u32(len(packet)), "proxy frame width")
                        body = recvexact(peer, len(packet))
                        need(body == packet, "proxy packet")
                        upstream.sendall(head+body)
                        ack = recvexact(upstream, 32)
                        need(ack.hex() == sha(packet), "ack dropped before durable admission")
                        observed = pool_row(pool)
                        need(observed["direct"] == 0, "first writer")
                        # Closing the wallet socket discards this genuine upstream acknowledgement.
                        return observed

                lost = worker.submit(drop_ack)
                attempts = upload([root/"drop-ack", direct.path], packet)
                old = lost.result(timeout=8)
            new = pool_row(pool)
            need([x["accepted"] for x in attempts] == [False, True], "uncertain-send retry")
            need(attempts[0]["out_bytes"] == attempts[1]["out_bytes"] == len(packet)+4, "double upload accounting")
            need({**old, "direct": 1} == new, "duplicate changed order, identity or age")
        finally:
            primary.stop()
            direct.stop()

        restarted = Endpoint(root/"direct", pool, True)
        try:
            upload([restarted.path], packet)
            need(pool_row(pool) == new, "pending retry after endpoint restart")
            produced, result = admit_queue(pool, node, {}, nonce)
            need(produced == block and result["count"] == 1, "real singleton admission")
            need(snapshot(node) == event["state"], "published first block")
            committed = fingerprint(node)
            upload([restarted.path], packet)
            b, discard = admit_queue(pool, node, {}, nonce)
            need(b is None and discard["rejected"] == ["spent nullifier"], "post-inclusion replay")
            need(committed == fingerprint(node), "repeat inclusion changed ledger")
            with sqlite3.connect(pool) as reader:
                need(reader.execute("SELECT count(*) FROM pool").fetchone()[0] == 0, "stale offer")
            return dict(packet_sha256=sha(packet), payment_B=len(packet), received_ack_dropped_B=32,
                        wallet_uploads=attempts, queue_identity_and_sequence_retained=True,
                        queue_arrival_retained=True, promoted_to_direct=True, restarted_endpoint=True,
                        original_public_block=event["block"], included_once=committed,
                        subsequent_retry_rejection=discard["rejected"][0], remaining_offers=0)
        finally:
            restarted.stop()


def worker(args):
    trace = json.loads((args.evidence/"TRACE.json").read_bytes())
    need(trace["profile_sha256"] == args.profile_sha and trace["genesis_sha256"] == args.genesis_sha
         and trace["binary_sha256"] == args.binary_sha, "approved trace registration")
    genesis = (args.evidence/"genesis.bin").read_bytes()
    check_genesis(genesis, args.genesis_sha)
    res = Resources(args)
    try:
        db = args.work/("ack.sqlite" if args.phase == "ack" else "fork.sqlite")
        node = Ledger(db, res.backend, genesis, args.genesis_sha, args.phase in ("prepare", "ack"))
        try:
            if args.phase == "ack":
                return lost_ack(args, node, trace)
            return run_fork(args, node, trace)
        finally:
            node.close()
    finally:
        res.close()


def run(args):
    args.work.mkdir(parents=True, exist_ok=False)

    def command(phase):
        return [sys.executable, "-I", "-B", str(HERE), *sys.argv[1:], "--phase", phase]

    def phase(name):
        out = subprocess.check_output(command(name), timeout=100)
        return json.loads(out)

    old = phase("prepare")
    with subprocess.Popen(command("crash"), stdout=subprocess.PIPE, text=True) as writer:
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(writer.stdout, selectors.EVENT_READ)
                need(ready.select(45), "crash-point timeout")
            partial = json.loads(writer.stdout.readline())
            need(partial["in_transaction"] and partial["writer"]["head"] != old["head"],
                 "replacement must differ before termination")
            os.kill(writer.pid, signal.SIGKILL)
            need(writer.wait(timeout=10) == -signal.SIGKILL, "writer survived SIGKILL")
        finally:
            if writer.poll() is None:
                writer.kill()
    after = phase("recover_retry")
    need(after["recovered"] == old and after["retry"]["head"] != old["head"], "recovery/retry")
    return dict(public_trace_sha256=sha((args.evidence/"TRACE.json").read_bytes()),
                profile_sha256=args.profile_sha, genesis_sha256=args.genesis_sha,
                binary_sha256=args.binary_sha, death_signal="SIGKILL",
                old=old, partial=partial, **after, ack=phase("ack"))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("binary", "keys", "evidence", "work"):
        p.add_argument("--"+key, type=Path, required=True)
    for key in ("binary-sha", "profile-sha", "genesis-sha"):
        p.add_argument("--"+key, required=True)
    p.add_argument("--phase", choices=("prepare", "crash", "recover_retry", "ack"))
    config = p.parse_args()
    result = worker(config) if config.phase else run(config)
    print(json.dumps(result, indent=2, sort_keys=True))
