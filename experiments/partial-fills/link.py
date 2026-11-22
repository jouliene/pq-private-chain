"""Loopback ciphertext meter with a one-shot lost-reply control for the partial-fill walkthrough."""
import os
import select
import socket
import socketserver
import threading
import time

THRESHOLD = 100_000
CHUNK = 65_536
COUNTS = ("client_received", "client_forwarded", "maker_received", "maker_forwarded", "maker_withheld")


def half_close(sock, direction):
    try:
        sock.shutdown(direction)
    except OSError:
        pass  # The peer may already have closed its half.


class CiphertextLink(socketserver.ThreadingTCPServer):
    """Use as a context manager. Both endpoints are restricted to IPv4 loopback."""

    def __init__(self, target_port):
        if type(target_port) is not int or not 1 <= target_port <= 65535:
            raise ValueError("expected a local target port")
        self.target = ("127.0.0.1", target_port)
        self._lock = threading.Lock()
        self._sessions = []
        self._armed_after = None
        self._stop = threading.Event()
        super().__init__(("127.0.0.1", 0), _Relay)
        self.port = self.server_address[1]

    def __enter__(self):
        self._thread = threading.Thread(target=self.serve_forever, kwargs={"poll_interval":.05}, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self.shutdown()
        self.server_close()
        self._thread.join()

    def arm(self):
        """Only new connections can consume the arm. Short connections leave it pending."""
        with self._lock:
            if self._armed_after is not None:
                raise ValueError("already armed")
            self._armed_after = len(self._sessions)

    def snapshot(self):
        with self._lock:
            sessions = [row.copy() for row in self._sessions]
            armed = self._armed_after is not None
        return dict(connections=len(sessions), armed=armed, drops=sum(row["dropped"] for row in sessions),
                    sessions=sessions, **{k: sum(row[k] for row in sessions) for k in COUNTS})

    def _new(self):
        with self._lock:
            row = dict(id=len(self._sessions)+1, claimed=False, dropped=False, closed=False, error=None,
                       **dict.fromkeys(COUNTS,0))
            self._sessions.append(row)
            return row

    def _count(self, row, field, n):
        with self._lock:
            row[field] += n
            if field == "client_forwarded" and self._armed_after is not None and row["id"] > self._armed_after:
                if row[field] > THRESHOLD:
                    row["claimed"] = True
                    self._armed_after = None
            if field == "maker_withheld":
                row["dropped"] = True


class _Relay(socketserver.BaseRequestHandler):
    def handle(self):
        link = self.server
        row = link._new()
        try:
            with socket.create_connection(link.target, timeout=4) as maker:
                self._relay(link, row, maker)
        except OSError as exc:
            with link._lock:
                row["error"] = type(exc).__name__
        finally:
            with link._lock:
                row["closed"] = True

    def _relay(self, link, row, maker):
        sockets = (self.request, maker)
        for sock in sockets:
            sock.setblocking(False)
        reading = [True, True]
        pending = [b"", b""]  # At most one transient chunk per direction.
        while not link._stop.is_set() and (any(reading) or any(pending)):
            reads = [sockets[i] for i in range(2) if reading[i] and not pending[i]]
            if pending[1] and row["claimed"]:
                # Retain the upstream connection through its normal reply and FIN.
                # An encrypted control record alone cannot truncate the buyer's upload.
                link._count(row, "maker_withheld", len(pending[1]))
                pending[1] = b""
                continue
            writes = [sockets[1-i] for i in range(2) if pending[i]]
            ready_r, ready_w, _ = select.select(reads, writes, [], .25)
            # Write client bytes first. A maker reply can be immediately readable on loopback.
            for i, field in enumerate(("client_forwarded", "maker_forwarded")):
                dest = sockets[1-i]
                if pending[i] and dest in ready_w:
                    if i == 1 and row["claimed"]:
                        continue
                    try:
                        n = dest.send(pending[i])
                    except BlockingIOError:
                        continue
                    if not n:
                        raise ConnectionError("closed while forwarding")
                    pending[i] = pending[i][n:]
                    link._count(row, field, n)
            for i, field in enumerate(("client_received", "maker_received")):
                if sockets[i] not in ready_r:
                    continue
                try:
                    data = sockets[i].recv(CHUNK)
                except BlockingIOError:
                    continue
                if data:
                    pending[i] = data
                    link._count(row, field, len(data))
                else:
                    reading[i] = False
                    half_close(sockets[1-i], socket.SHUT_WR)


def _self_test():
    """A small random-stream responder sends an opaque greeting, then waits for the full request."""
    import json
    import struct

    request = os.urandom(THRESHOLD+31)
    greeting, reply = os.urandom(277), os.urandom(120_003)

    def read_all(sock):
        result = bytearray()
        while part := sock.recv(CHUNK):
            result.extend(part)
        return bytes(result)

    def read_exact(sock, count):
        result = bytearray()
        while len(result) < count:
            part = sock.recv(count-len(result))
            if not part:
                raise EOFError("short self-test stream")
            result.extend(part)
        return bytes(result)

    class Responder(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.sendall(greeting)
            n, = struct.unpack(">I", read_exact(self.request,4))
            assert read_exact(self.request,n) == request[:n]
            self.request.sendall(reply)
            self.request.shutdown(socket.SHUT_WR)
            read_all(self.request)

    with socketserver.ThreadingTCPServer(("127.0.0.1",0), Responder) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with CiphertextLink(server.server_address[1]) as link:
                def exchange(n, expect):
                    with socket.create_connection(("127.0.0.1",link.port),timeout=3) as client:
                        assert read_exact(client,len(greeting)) == greeting
                        client.sendall(struct.pack(">I",n)+request[:n])
                        assert read_all(client) == expect

                exchange(len(request),reply)
                link.arm()
                exchange(THRESHOLD-4,reply)
                assert link.snapshot()["armed"]
                exchange(len(request),b"")
                exchange(len(request),reply)
                deadline=time.monotonic()+2
                while any(not s["closed"] for s in link.snapshot()["sessions"]) and time.monotonic()<deadline:
                    time.sleep(.01)
                st = link.snapshot()
                assert all(s["closed"] and not s["error"] for s in st["sessions"])
                assert st["drops"] == 1 and not st["armed"] and st["sessions"][2]["dropped"]
                assert st["client_forwarded"] == st["client_received"] == 3*(len(request)+4)+THRESHOLD
                assert st["maker_withheld"] == len(reply)
                assert st["maker_forwarded"] == 4*len(greeting)+3*len(reply)
                assert st["maker_forwarded"]+st["maker_withheld"] == st["maker_received"]
                print(json.dumps({k:v for k,v in st.items() if k!="sessions"},sort_keys=True))
        finally:
            server.shutdown()
            thread.join()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test",required=True,action="store_true")
    parser.parse_args()
    _self_test()
