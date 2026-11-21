"""Funded validating home node with a bounded body window and archive-assisted replay."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager, nullcontext
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import signal
import socketserver
import sqlite3
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def load_deployment(directory):
    global chain, funded, transport, runtime, Resources, PrunedChain, prefers
    dev = directory / "devnet"
    sys.path.insert(0, str(dev))
    import chain
    import transport
    import runtime
    from run import Resources
    from store import PrunedChain, prefers
    spec = importlib.util.spec_from_file_location("funded_peer_node", dev / "node.py")
    funded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(funded)


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


class ArchiveReader:
    def __init__(self, ports):
        self.ports = ports
        self.traffic = {str(p): dict(requests=0, failures=0, request_B=0, reply_B=0,
                                    bodies=0, body_B=0) for p in ports}
        self.errors = {}

    def request(self, port, op, **params):
        meter = {}
        counts = self.traffic[str(port)]
        counts["requests"] += 1
        try:
            meta, body = transport.rpc(port, op, meter=meter, **params)
            if op == "block":
                counts["bodies"] += 1
                counts["body_B"] += len(body)
            return meta, body
        except (ValueError, OSError, TimeoutError) as error:
            counts["failures"] += 1
            self.errors[str(port)] = str(error)[:150]
            raise
        finally:
            for k in ("request_B", "reply_B"):
                counts[k] += meter.get(k, 0)

    def inventory(self, port, start, limit):
        ids, body = self.request(port, "selected", start=start, limit=limit)
        require(not body and type(ids) is list and len(ids) == limit, "incomplete archive inventory")
        return [funded.hexid(ident) for ident in ids]

    def body(self, ident, preferred):
        for port in dict.fromkeys((preferred, *self.ports)):
            try:
                _, body = self.request(port, "block", id=ident.hex())
                require(chain.block_id(body) == ident, "archive block identity mismatch")
                return body
            except (ValueError, OSError, TimeoutError) as error:
                self.errors[str(port)] = str(error)[:150]
        raise ValueError("required archive body unavailable")

    def targets(self, requested, unresolved, progress):
        available = []
        for port in self.ports:
            try:
                info, body = self.request(port, "status")
                require(not body and info["network"] == chain.NETWORK.hex(), "archive network mismatch")
                tip = funded.hexid(info["tip"]).hex()
                height = funded.integer(info["height"], 0, 2**32-1)
                available.append((height, tip, port))
            except (ValueError, TypeError, KeyError, OSError, TimeoutError) as error:
                self.errors[str(port)] = str(error)[:150]
        # Retain an unresolved frontier even if its announcing peer disappears.
        # A lower advertisement cannot silently turn an incomplete wallet ready.
        known = [(h, tip) for h, tip, _ in available]
        if unresolved:
            known.append(unresolved)
        if requested is None and known:
            _, requested = min(known, key=lambda row: (-row[0], row[1]))
        progress["target"] = requested
        heights = [h for h, tip in known if tip == requested]
        if heights:
            progress["target_height"] = max(heights)
        candidates = [(h, p) for h, tip, p in available if tip == requested]
        if not candidates and requested is not None and available:
            # The archive may already have extended a pinned target. Its original
            # body gives a height hint only; full replay still binds the endpoint.
            ident = funded.hexid(requested)
            if requested == chain.GENESIS.hex():
                height = 0
            elif heights:
                height = max(heights)
            else:
                height = chain.decode_block(self.body(ident, available[0][2])).height
            for head_height, _, port in available:
                if head_height < height:
                    continue
                try:
                    if self.inventory(port, height, 1) == [ident]:
                        candidates.append((height, port))
                except (ValueError, OSError, TimeoutError) as error:
                    self.errors[str(port)] = str(error)[:150]
        require(candidates, "required target unavailable from archives")
        return requested, candidates


class Home:
    def __init__(self, db, archives, stop, verifier_thread):
        self.db, self.archives, self.stop = db, archives, stop
        self.verifier_thread = verifier_thread
        self.recovery_lock = threading.Lock()
        self.name = "home"
        self.port = None

    def status(self):
        with self.db.lock:
            try:
                candidate_size = self.stage_path.stat().st_size
            except FileNotFoundError:
                candidate_size = 0
            return dict(self.db.status(), recovery=self.db.progress(), storage=self.db.storage(),
                        node=self.name, port=self.port, candidate_disk_B=candidate_size)

    @property
    def stage_path(self):
        return self.db.path.with_name(self.db.path.name + ".candidate")

    def clear_stage(self):
        for suffix in ("-journal", "-wal", "-shm", ""):
            Path(str(self.stage_path) + suffix).unlink(missing_ok=True)

    @contextmanager
    def branch_stage(self, reader, port, target, height):
        candidate = PrunedChain(self.stage_path, self.db.backend, self.db.window)
        try:
            staged = candidate.status()
            compatible = (candidate.progress().get("target") in (None, target) and staged["height"] <= height
                          and (not staged["height"] or reader.inventory(port, staged["height"], 1)
                               == [bytes.fromhex(staged["tip"])]))
            if not compatible:
                candidate.close()
                candidate = None
                self.clear_stage()
                candidate = PrunedChain(self.stage_path, self.db.backend, self.db.window)
            candidate.progress_update(dict(status="recovering", target=target))
            yield candidate
        finally:
            if candidate is not None:
                candidate.close()

    def replay(self, reader, candidate, port, target, height, progress):
        previous = self.db.status()
        initial = candidate.status()
        start = initial["height"] + 1
        progress.setdefault("replay_start", start)
        progress.setdefault("verified_blocks", 0)
        progress.setdefault("verified_frames", 0)
        progress.setdefault("scratch_peak_B", 0)
        progress.update(first_missing_height=start, installing_branch=candidate is not self.db)
        parent = bytes.fromhex(initial["tip"])
        for page in range(start, height + 1, 16):
            limit = min(16, height + 1 - page)
            ids = reader.inventory(port, page, limit)
            for position, ident in enumerate(ids, page):
                progress["first_missing_height"] = position
                raw = reader.body(ident, port)
                parsed = chain.decode_block(raw)
                require(parsed.height == position and parsed.parent == parent, "archive branch continuity")
                require(position != height or ident.hex() == target, "archive target changed")
                result = candidate.accept(raw)
                require(result["selected"] and result["id"] == ident.hex(), "candidate extension failed")
                parent = ident
                progress.update(verified_blocks=progress["verified_blocks"] + 1,
                                verified_frames=progress["verified_frames"] + len(parsed.packets),
                                first_missing_height=position + 1)
                if candidate is not self.db:
                    progress["scratch_peak_B"] = max(progress["scratch_peak_B"], self.stage_path.stat().st_size)
        selected = candidate.status()
        require(selected["tip"] == target and selected["height"] == height, "archive target mismatch")
        if candidate is self.db:
            return previous["height"]
        # Only local, verified selected-height indexes enter this comparison.
        low, high = 0, min(previous["height"], height)
        while low < high:
            mid = (low + high + 1) // 2
            if self.db.selected(mid, 1) == candidate.selected(mid, 1):
                low = mid
            else:
                high = mid - 1
        return low

    def recover(self, requested):
        if requested is not None:
            requested = funded.hexid(requested).hex()
        if not self.recovery_lock.acquire(blocking=False):
            raise ValueError("recovery already running")
        started = time.monotonic()
        reader = ArchiveReader(self.archives)
        try:
            with self.db.lock:
                prior = self.db.status()
                prior_progress = self.db.progress()
                if requested == prior["tip"] and prior_progress["status"] != "ready":
                    require(prior_progress.get("target") in (None, requested),
                            "requested target predates incomplete recovery")
                unresolved = None
                if (prior_progress["status"] != "ready" and prior_progress.get("target")
                    and type(prior_progress.get("target_height")) is int):
                    unresolved = (prior_progress["target_height"], prior_progress["target"])
                progress = dict(status="recovering", target=requested, first_missing_height=None,
                                archive_traffic=reader.traffic, archive_errors=reader.errors, error=None)
                if unresolved and requested in (None, unresolved[1]):
                    progress.update(target=unresolved[1], target_height=unresolved[0],
                                    first_missing_height=prior_progress.get("first_missing_height"))
                self.db.progress_update(progress)
            try:
                target, candidates = reader.targets(requested, unresolved, progress)
                progress["target"] = target
                self.db.progress_update(progress)
                if target == prior["tip"]:
                    if prior_progress["status"] != "ready" and prior_progress.get("target") not in (None, target):
                        progress["target"] = prior_progress["target"]
                        raise ValueError("requested target predates incomplete recovery")
                    progress.update(status="ready", first_missing_height=None, elapsed_s=time.monotonic()-started,
                                    common_height=prior["height"], verified_blocks=0, verified_frames=0)
                    self.db.progress_update(progress)
                    self.clear_stage()
                    return progress
                last_error = None
                for height, port in candidates:
                    try:
                        # A direct extension can make durable prefix progress. The
                        # wallet stays incomplete until the requested target arrives.
                        old = self.db.status()
                        append = height > old["height"] and (
                            old["height"] == 0 or reader.inventory(port, old["height"], 1) == [bytes.fromhex(old["tip"])])
                        scope = nullcontext(self.db) if append else self.branch_stage(reader, port, target, height)
                        with scope as candidate:
                            common = self.replay(reader, candidate, port, target, height, progress)
                            selected = candidate.status()
                            if append or prefers(selected["work"], selected["tip"], old["work"], old["tip"]):
                                deep = old["height"] - common > self.db.window
                                final = dict(progress, status="ready", deep=deep, first_missing_height=None,
                                             common_height=common, elapsed_s=time.monotonic()-started)
                                if append:
                                    self.db.progress_update(final)
                                else:
                                    self.db.install(candidate, final, common, deep)
                            else:
                                self.db.progress_update(prior_progress)
                                final = dict(progress, status="kept_selected", first_missing_height=None,
                                             elapsed_s=time.monotonic()-started)
                        self.clear_stage()
                        return final
                    except (ValueError, OSError, TimeoutError, KeyError, TypeError) as error:
                        last_error = error
                        reader.errors[str(port)] = str(error)[:150]
                raise ValueError(str(last_error) if last_error is not None else "archive recovery failed")
            except (ValueError, OSError, TimeoutError, KeyError, TypeError, RuntimeError) as error:
                progress.update(status="incomplete", error=str(error)[:180], elapsed_s=time.monotonic()-started)
                self.db.progress_update(progress)
                raise ValueError("incomplete history: " + progress["error"]) from error
        finally:
            self.recovery_lock.release()

    def dispatch(self, request, body, admin):
        op = request["op"]
        if op == "recover":
            require(admin and not body and set(request) <= {"op", "tip"}, "invalid recovery control")
            return self.recover(request.get("tip")), b""
        if op == "stop":
            require(admin and not body, "private control required")
            self.stop.set()
            return {}, b""
        if op == "status":
            require(not body, "unexpected body")
            return self.status(), b""
        if op == "storage":
            require(not body, "unexpected body")
            with self.db.lock:
                return self.db.storage(), b""
        # Hold the same lock across the readiness check and the complete
        # request. A stale verified prefix cannot serve a successful balance.
        with self.db.lock:
            progress = self.db.progress()
            if op in {"history_head", "history_range", "history_check", "page", "assets",
                      "supply-observation", "submit", "publish"}:
                require(progress["status"] == "ready", "incomplete history: missing height "
                        + str(progress.get("first_missing_height")) + ", target " + str(progress.get("target")))
            # Funded protocol parsing, bounds, and public operations; admin
            # mining/topology/stop of the full daemon are excluded here.
            return funded.Node.dispatch(self, request, body, False)


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(30)
        try:
            size = transport.length(self.rfile.read(4))
            payload = self.rfile.read(size)
            require(len(payload) == size, "incomplete request")
            meta, body = transport.unpack(payload)
            home = self.server.home
            if meta.get("op") in {"recover", "publish", "submit", "supply-observation"}:
                # Lazy registered roles are sandboxed with --die-with-parent.
                # Linux ties parent death to the *creating thread*. Never launch
                # a long-lived verifier from a per-connection handler thread.
                result, body = home.verifier_thread.submit(home.dispatch, meta, body, self.server.admin).result()
            else:
                result, body = home.dispatch(meta, body, self.server.admin)
            reply = transport.frame(dict(ok=True, result=result), body)
        except (ValueError, OSError, KeyError, TypeError, OverflowError, RuntimeError, sqlite3.Error) as error:
            reply = transport.frame(dict(ok=False, error=str(error)[:200]))
        try:
            self.wfile.write(reply)
        except OSError:
            pass


class TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = False


class Unix(socketserver.ThreadingUnixStreamServer):
    daemon_threads = False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--store", type=Path, required=True)
    parser.add_argument("--window", type=int, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--archives", nargs="+", type=int, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    load_deployment(args.deployment.resolve(strict=True))
    stop = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stop.set())
    with (args.store.parent / (args.store.name + ".lock")).open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        args.control.unlink(missing_ok=True)
        wallet_socket = args.control.with_name("wallet.sock")
        require(wallet_socket != args.control, "control and public socket must differ")
        wallet_socket.unlink(missing_ok=True)
        with closing(Resources(runtime.config(args.deployment / "runtime"))) as roles:
            with (ThreadPoolExecutor(max_workers=1, thread_name_prefix="funded-validator") as verifier_thread,
                  closing(PrunedChain(args.store, roles.backend, args.window)) as db):
                home = Home(db, args.archives, stop, verifier_thread)
                with (Unix(str(args.control), Handler) as local, Unix(str(wallet_socket), Handler) as wallet,
                      TCP(("127.0.0.1", args.port), Handler) as peer):
                    home.port = peer.server_address[1]
                    for server, admin in ((local, True), (wallet, False), (peer, False)):
                        server.home, server.admin = home, admin
                        threading.Thread(target=server.serve_forever, daemon=True).start()
                    try:
                        stop.wait()
                    finally:
                        peer.shutdown()
                        local.shutdown()
                        wallet.shutdown()
                        args.control.unlink(missing_ok=True)
                        wallet_socket.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
