"""Pruned-node regression checks using the prior released funded-upgrade public graph."""
import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import socket
import socketserver
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time

HERE = Path(__file__).resolve().parent


def need(ok, message):
    if not ok:
        raise ValueError(message)


def refused(call, expected):
    try:
        call()
    except ValueError as error:
        need(expected in str(error), f"unexpected refusal: {error}")
        return
    raise ValueError("expected refusal: " + expected)


def run(args, home):
    sys.path.insert(0, str(args.deployment / "devnet"))
    import chain
    from transport import frame, length, rpc, unpack
    graph = {}
    for path in (args.public / "blocks").glob("*.bin"):
        body = path.read_bytes()
        ident = chain.block_id(body).hex()
        need(ident == path.stem, "capture identity")
        graph[ident] = chain.decode_block(body), body
    first, second = sorted(bid for bid, (block, _) in graph.items() if block.height == 19)
    genesis = chain.GENESIS.hex()

    def ancestry(tip):
        path = []
        while tip != genesis:
            path.append(tip)
            tip = graph[tip][0].parent.hex()
        return [genesis, *reversed(path)]

    class Peer(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                query, body = unpack(self.rfile.read(length(self.rfile.read(4))))
                need(not body, "unexpected payload")
                op = query["op"]
                if op == "status":
                    answer = dict(tip=archive.path[-1], height=len(archive.path)-1, network=chain.NETWORK.hex())
                elif op == "selected":
                    start = query["start"]
                    answer = archive.path[start:start+query["limit"]]
                elif op == "block":
                    ident = query["id"]
                    need(ident != archive.missing, "unavailable body")
                    answer, body = {}, graph[ident][1]
                else:
                    raise ValueError("unknown operation")
                self.wfile.write(frame(dict(ok=True, result=answer), body))
            except ValueError as error:
                self.wfile.write(frame(dict(ok=False, error=str(error))))

    with socketserver.TCPServer(("127.0.0.1", 0), Peer) as archive:
        archive.path = ancestry(second)
        archive.missing = archive.path[5]
        threading.Thread(target=archive.serve_forever, daemon=True).start()
        control = home / "control.sock"
        wallet = home / "wallet.sock"
        store = home / "home.sqlite"
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            home_port = probe.getsockname()[1]
        command = [sys.executable, "-IB", str(HERE / "node.py"), "--deployment", str(args.deployment),
                   "--store", str(store), "--window", "3", "--port", str(home_port),
                   "--control", str(control), "--archives", str(archive.server_address[1])]

        @contextmanager
        def serving():
            process = subprocess.Popen(command, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline and process.poll() is None:
                    if control.exists():
                        try:
                            rpc(control, "status")
                            break
                        except OSError:
                            pass
                    time.sleep(.05)
                need(process.poll() is None and control.exists(), "node failed to start")
                yield process
            finally:
                if process.poll() is None:
                    rpc(control, "stop")
                _, stderr = process.communicate(timeout=15)
                need(process.returncode in (0, -9), "node process: " + stderr.decode(errors="replace"))

        try:
            with serving() as process:
                refused(lambda: rpc(wallet, "recover", tip=second), "invalid recovery control")
                refused(lambda: rpc(control, "recover"), "incomplete history")
                before = rpc(wallet, "status")[0]
                need(before["height"] == 4 and before["recovery"]["first_missing_height"] == 5,
                     "missing body did not preserve verified prefix")
                refused(lambda: rpc(wallet, "history_head", locator=[]), "incomplete history")
                process.kill()
                process.wait()
            archive.missing = None
            with serving():
                need(rpc(wallet, "status")[0]["height"] == 4, "crash lost verified prefix")
                archive.path = ancestry(second)[:8]
                refused(lambda: rpc(control, "recover"), "incomplete history")
                pending = rpc(wallet, "status")[0]["recovery"]
                need(pending["target"] == second and pending["target_height"] == 19, "unresolved frontier lost")
                archive.path = ancestry(second)
                resumed = rpc(control, "recover")[0]
                need(resumed["replay_start"] == 5 and resumed["verified_blocks"] == 15, "prefix replayed")
                # A subsequent RPC must reuse the same live B worker after the
                # recovery connection closes. The authentic old spend reaches
                # the current local monetary checks.
                prior_b = next(p for ident in archive.path[1:] for p in graph[ident][0].packets
                               if p.startswith(b"MSP2"))
                try:
                    rpc(wallet, "submit", prior_b)
                except ValueError as error:
                    need(str(error) in ("anchor age", "spent nullifier"), str(error))
                else:
                    raise ValueError("old B spend unexpectedly admitted")
                old = rpc(wallet, "status")[0]
                need(old["tip"] == second and old["storage"]["body_rows"] == 3, "retention count")
                refused(lambda: rpc(wallet, "block", id=archive.path[7]), "pruned")
                archive.path = ancestry(first)
                archive.missing = archive.path[10]
                refused(lambda: rpc(control, "recover", tip=first), "incomplete history")
                need(rpc(wallet, "status")[0]["tip"] == second, "incomplete fork replaced selected state")
            archive.missing = None
            with serving():
                switched = rpc(control, "recover", tip=first)[0]
                need(switched["replay_start"] == 10 and switched["deep"], "fork resume")
                need(rpc(wallet, "status")[0]["tip"] == first, "lower ID equal-work branch failed")
                archive.path = ancestry(second)
                losing = rpc(control, "recover", tip=second)[0]
                need(losing["status"] == "kept_selected", "higher ID equal-work branch wrongly selected")
                need(rpc(wallet, "status")[0]["tip"] == first, "fork choice changed")
            with sqlite3.connect(store) as db:
                # Simulate silent damage outside registered transition triggers.
                db.execute("UPDATE home_seal SET digest=zeroblob(32)")
            check = subprocess.run(command, capture_output=True, timeout=15)
            need(check.returncode != 0 and b"checksum mismatch" in check.stderr, "unsealed restart")
            print(json.dumps(dict(prefix_before_restart=4, resume_height=5, fork_resume_height=10,
                                  equal_work_height=19, retained_bodies=3, corruption_refused=True)))
        finally:
            archive.shutdown()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("deployment", type=Path)
    parser.add_argument("public", type=Path)
    args = parser.parse_args()
    args.deployment = args.deployment.resolve(strict=True)
    with tempfile.TemporaryDirectory() as temporary:
        run(args, Path(temporary))
