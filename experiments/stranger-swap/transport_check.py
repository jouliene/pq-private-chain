"""Exercise the pinned hybrid TLS transport over actual loopback sockets without wallet material."""
from contextlib import contextmanager
import json
import multiprocessing as mp
from pathlib import Path
from queue import Queue
import select
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import market_transport as t


def endpoint():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return "127.0.0.1:" + str(s.getsockname()[1])


def address(text):
    host, port = text.split(":")
    return host, int(port)


def fields():
    now = int(time.time())
    return dict(version=1, service="token-for-native", network="01" * 32, issued=now, expires=now + 120)


@contextmanager
def tap(target):
    observed = Queue()

    class Copy(socketserver.BaseRequestHandler):
        def handle(self):
            streams = [bytearray(), bytearray()]
            with socket.create_connection(address(target), timeout=6) as dst:
                peers = (self.request, dst)
                live = list(peers)
                while live:
                    reads, _, _ = select.select(live, [], [], 8)
                    if not reads:
                        break
                    for source in reads:
                        idx = peers.index(source)
                        try:
                            data = source.recv(65536)
                            if data:
                                streams[idx].extend(data)
                                peers[1 - idx].sendall(data)
                            else:
                                live.remove(source)
                                peers[1 - idx].shutdown(socket.SHUT_WR)
                        except OSError:
                            if source in live:
                                live.remove(source)
            observed.put(tuple(bytes(buf) for buf in streams))

    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Copy) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield "127.0.0.1:" + str(server.server_address[1]), observed
        finally:
            server.shutdown()
            thread.join()


def group_in_server_hello(raw):
    """Read the first plaintext TLS ServerHello and its negotiated key_share named group."""
    assert raw[0] == 22 and raw[5] == 2
    end = 5 + int.from_bytes(raw[3:5], "big")
    hello = raw[9:end]
    assert int.from_bytes(raw[6:9], "big") == len(hello)
    pos = 35 + hello[34] + 3  # session ID vector, cipher, compression
    size = int.from_bytes(hello[pos:pos+2], "big")
    pos += 2
    assert pos + size == len(hello)
    while pos < len(hello):
        kind, n = struct.unpack_from(">HH", hello, pos)
        ext = hello[pos+4:pos+4+n]
        assert len(ext) == n
        if kind == 51:
            return int.from_bytes(ext[:2], "big")
        pos += 4 + n
    raise AssertionError("ServerHello omitted key_share")


def rejected(ad, body):
    meter = {}
    try:
        t.request(ad, body, meter=meter)
    except ValueError as error:
        assert not isinstance(error, t.MakerRejected)
        assert meter["request_B"] == 0 and meter["reply_B"] == 0 and not meter["authenticated"]
        return meter
    raise AssertionError("unexpected authenticated response")


@contextmanager
def classical_server(directory, ep):
    # Independent negative fixture uses the genuine advertised certificate and a TLS 1.3
    # server restricted to the classical X25519 group. It has no private wallet callback.
    script = """
const tls=require('node:tls'), fs=require('node:fs'), path=require('node:path');
const [dir,port]=process.argv.slice(1);
const s=tls.createServer({key:fs.readFileSync(path.join(dir,'tls.pem')),cert:fs.readFileSync(path.join(dir,'cert.pem')),
    minVersion:'TLSv1.3',maxVersion:'TLSv1.3',ecdhCurve:'X25519',ALPNProtocols:['pqd-stranger/1']},
    c=>c.end('unexpected handshake'));
s.listen(Number(port),'127.0.0.1',()=>process.stdout.write('ready\\n'));
"""
    with subprocess.Popen([t._command("request")[0], "-e", script, str(directory / "transport-identity"),
                           str(address(ep)[1])], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=t._env()) as proc:
        try:
            assert select.select([proc.stdout], [], [], 5)[0] and proc.stdout.readline() == b"ready\n"
            yield
        finally:
            proc.terminate()


def test():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        backend = endpoint()
        with tap(backend) as (remote, captures):
            ad = t.make_advert(root / "maker", remote, fields())
            other = t.make_advert(root / "other", remote, fields())
            assert t.verify_advert(ad) != t.verify_advert(other)
            checks = {}
            altered = dict(ad, endpoint=endpoint())
            checks["changed_signed_endpoint"] = rejected(altered, {"op": "test"})
            assert checks["changed_signed_endpoint"]["wire_request_B"] == 0
            got = mp.Value("i", 0)
            ready = mp.Event()

            def handle(q):
                with got.get_lock():
                    got.value += 1
                if q.get("op") == "reject":
                    raise ValueError("private-local-detail-never-returned")
                return q

            server = mp.Process(target=t.serve, args=(root / "maker", ad, handle),
                                kwargs=dict(listen=backend, ready=ready.set))
            server.start()
            try:
                assert ready.wait(6)
                m = {}
                marker = "only-inside-encrypted-private-request"
                q = {"op": marker, "padding": "x" * 200000}
                assert t.request(ad, q, meter=m) == q and got.value == 1
                outbound, inbound = captures.get(timeout=5)
                assert (len(outbound), len(inbound)) == (m["wire_request_B"], m["wire_reply_B"])
                assert marker.encode() not in outbound + inbound
                # IANA X25519MLKEM768 = 4588 (0x11ec), independently read from actual handshake bytes.
                group = group_in_server_hello(inbound)
                assert group == 0x11ec and m["group"] == "X25519MLKEM768" and m["authenticated"]
                checks["registered_channel"] = dict(m, independent_counts_match=True, server_hello_named_group=group)
                checks["wrong_certificate"] = rejected(other, {"op": marker})
                assert checks["wrong_certificate"]["failure"] == "certificate-pin"
                captures.get(timeout=5)
                # A second genuine ephemeral ML-DSA key signs an advert pinning the FIRST maker's
                # actual certificate. TLS and the cert pin pass, but the live exporter signature must fail.
                wrong = dict(other, cert_sha256=ad["cert_sha256"])
                unsigned = {k: v for k, v in wrong.items() if k != "signature"}
                wrong.update(t._call("sign", dict(directory=str(root / "other/transport-identity"),
                                                   payload=t._b64(t._json(unsigned)))))
                checks["wrong_live_exporter_signer"] = rejected(wrong, {"op": marker})
                assert checks["wrong_live_exporter_signer"]["cert_pinned"] and checks["wrong_live_exporter_signer"]["failure"] == "exporter-signature"
                captures.get(timeout=5)
                assert got.value == 1
                meter = {}
                try:
                    t.request(ad, {"op": "reject"}, meter=meter)
                except t.MakerRejected as e:
                    assert str(e) == "maker rejected request" and meter["authenticated"]
                else:
                    raise AssertionError("maker error leaked or was accepted")
                captures.get(timeout=5)
                assert got.value == 2
                checks["oversize_before_connect"] = rejected(ad, {"op": "z" * t.MAX_BODY})
                assert checks["oversize_before_connect"]["wire_request_B"] == 0
            finally:
                server.terminate()
                server.join(5)
        target = endpoint()
        classical = t.make_advert(root / "classical", target, fields())
        with classical_server(root / "classical", target):
            checks["classical_only_server"] = rejected(classical, {"op": "secret"})
            assert checks["classical_only_server"]["failure"] == "handshake" and checks["classical_only_server"]["wire_request_B"] > 1000
        return checks


if __name__ == "__main__":
    print(json.dumps(test(), sort_keys=True, indent=2))
