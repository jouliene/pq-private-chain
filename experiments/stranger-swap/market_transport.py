"""Bounded hybrid TLS and ML-DSA authenticated requests for ephemeral maker adverts."""
from base64 import b64decode, b64encode
from hashlib import sha256
import ipaddress
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
MAX_BODY = 1 << 20
LOCAL_MAX = MAX_BODY * 2
NODE_SHA256 = "e32e2d16081cf644f88392934288086e7662529d0d43277c34f7aad2207cfafb"
APP_FIELDS = {"version", "service", "network", "issued", "expires"}
AD_FIELDS = APP_FIELDS | {"endpoint", "signature", "identity", "cert_sha256"}


def _need(ok, message):
    if not ok:
        raise ValueError(message)


def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()


def _obj(pairs):
    answer = dict(pairs)
    _need(len(answer) == len(pairs), "duplicate JSON field")
    return answer


def _decode(raw):
    def invalid(_):
        raise ValueError("nonfinite JSON number")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_obj, parse_constant=invalid)
    _need(isinstance(value, dict), "expected JSON object")
    return value


def _b64(raw):
    return b64encode(raw).decode("ascii")


def _endpoint(value):
    _need(isinstance(value, str) and len(value) <= 21, "invalid IPv4 endpoint")
    host, port = value.split(":")
    _need(str(ipaddress.IPv4Address(host)) == host and str(int(port)) == port and 0 < int(port) <= 65535,
          "invalid IPv4 endpoint")


def _hex(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _frame(value):
    raw = _json(value)
    _need(0 < len(raw) <= LOCAL_MAX, "local frame too large")
    return struct.pack(">I", len(raw)) + raw


def _read(stream):
    size = stream.read(4)
    _need(len(size) == 4, "transport role ended")
    n, = struct.unpack(">I", size)
    _need(0 < n <= LOCAL_MAX, "invalid local transport frame")
    buf = stream.read(n)
    _need(len(buf) == n, "short local transport frame")
    return _decode(buf)


_node_cache = None


def _command(op):
    global _node_cache
    supplied = os.environ.get("STRANGER_NODE")
    local = HERE.parents[1] / ".tools/node-v24.22.1-linux-x64/bin/node"
    path = Path(supplied or (local if local.is_file() else shutil.which("node") or "node")).resolve(strict=True)
    st = path.stat()
    token = (path, st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    if token != _node_cache:
        with path.open("rb") as f:
            digest = sha256()
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(chunk)
            _need(digest.hexdigest() == NODE_SHA256,
                  "expected approved Node 24.22.1 Linux x64 binary (set STRANGER_NODE)")
        _node_cache = token
    return [str(path), str(HERE / "transport.mjs"), op]


def _env():
    # Provider configuration, key logging and inherited Node preloads are unnecessary for this pinned role.
    return {"PATH": os.defpath, "LANG": "C"}


def _call(op, data, timeout=12):
    import io
    result = subprocess.run(_command(op), input=_frame(data), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            env=_env(), timeout=timeout)
    _need(result.returncode == 0, "transport role rejected the operation")
    stream = io.BytesIO(result.stdout)
    row = _read(stream)
    _need(not stream.read(1), "multiple transport replies")
    return row


def _fields(q):
    _need(set(q) == APP_FIELDS and type(q["version"]) is int and q["version"] == 1 and
          q["service"] == "token-for-native" and _hex(q["network"]) and
          type(q["issued"]) is int and type(q["expires"]) is int and
          0 <= q["issued"] < q["expires"] < 2**53, "invalid public advert fields")


def make_advert(directory, endpoint, fields):
    """Create one disposable private identity and a signed immutable public advert."""
    _fields(fields)
    _endpoint(endpoint)
    path = Path(directory)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    _need(not path.is_symlink() and path.stat().st_uid == os.geteuid()
          and path.stat().st_mode & 0o077 == 0, "identity requires a private owner directory")
    keys = path / "transport-identity"
    keys.mkdir(mode=0o700)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-sha256", "-nodes", "-days", "2", "-subj", "/CN=ephemeral-swap",
                    "-keyout", str(keys / "tls.pem"), "-out", str(keys / "cert.pem")],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=_env(), check=True, timeout=12)
    row = _call("identity", {"directory": str(keys)})
    unsigned = dict(fields, endpoint=endpoint, **row)
    proof = _call("sign", {"directory": str(keys), "payload": _b64(_json(unsigned))})
    advert = dict(unsigned, **proof)
    verify_advert(advert)
    return advert


def verify_advert(ad):
    """Verify the canonical immutable envelope. The caller applies discovery policy and TTL."""
    _need(isinstance(ad, dict) and set(ad) == AD_FIELDS, "invalid public advert schema")
    _fields({k: ad[k] for k in APP_FIELDS})
    _endpoint(ad["endpoint"])
    _need(_hex(ad["cert_sha256"]) and isinstance(ad["identity"], str) and len(ad["identity"]) == 2632 and
          isinstance(ad["signature"], str) and len(ad["signature"]) == 4412, "invalid advert key, pin or signature")
    unsigned = {k: v for k, v in ad.items() if k != "signature"}
    verdict = _call("verify", {"payload": _b64(_json(unsigned)), "identity": ad["identity"],
                               "signature": ad["signature"]})
    _need(verdict == {"valid": True}, "invalid advert signature")
    return sha256(_json(ad)).hexdigest()


def _channel(ad):
    ident = verify_advert(ad)
    _need(ad["issued"] <= time.time() < ad["expires"], "advert is not currently live")
    return dict(ad_id=ident, identity=ad["identity"], cert_sha256=ad["cert_sha256"])


class MakerRejected(ValueError):
    """A well-formed, authenticated negative maker reply."""


def request(ad, body, *, meter=None):
    """Return one private maker response. A failed server pin/auth check transmits zero request bytes."""
    if meter is not None:
        meter.update(wire_request_B=0, wire_reply_B=0, request_B=0, reply_B=0, authenticated=False,
                     cert_pinned=False, failure="before-connect", group=None, protocol=None, cipher=None)
    _need(isinstance(body, dict), "private request must be a JSON object")
    raw = _json(body)
    _need(0 < len(raw) <= MAX_BODY, "private request too large")
    channel = _channel(ad)
    result = _call("request", dict(channel, body=_b64(raw), endpoint=ad["endpoint"], expires=ad["expires"]), timeout=160)
    if meter is not None:
        meter.update(result["meter"])
    _need(result["ok"], "private channel authentication or exchange failed")
    reply = _decode(b64decode(result["body"], validate=True))
    if (set(reply) == {"ok", "error"} and reply["ok"] is False and
            reply["error"] in ("rejected", "busy", "unavailable")):
        raise MakerRejected("maker rejected request")
    _need(set(reply) == {"ok", "result"} and reply["ok"] is True and isinstance(reply["result"], dict),
          "malformed maker reply")
    return reply["result"]


def serve(directory, ad, handler, *, listen=None, ready=None):
    """Serve requests serially to one maker handler. The optional no-argument callback runs after bind."""
    address = listen or ad["endpoint"]
    _endpoint(address)
    channel = _channel(ad)
    keys = Path(directory) / "transport-identity"
    with subprocess.Popen(_command("serve"), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, env=_env()) as worker:
        try:
            worker.stdin.write(_frame(dict(channel, directory=str(keys), listen=address, expires=ad["expires"])))
            worker.stdin.flush()
            _need(_read(worker.stdout) == {"ready": True}, "maker failed to bind")
            if ready is not None:
                ready()
            while True:
                row = _read(worker.stdout)
                try:
                    raw = b64decode(row["body"], validate=True)
                    _need(0 < len(raw) <= MAX_BODY, "invalid private request size")
                    response = handler(_decode(raw))
                    _need(isinstance(response, dict), "invalid maker response")
                    body = _json({"ok": True, "result": response})
                    _need(len(body) <= MAX_BODY, "private response too large")
                except (ValueError, KeyError, TypeError, RecursionError):
                    body = b'{"ok":false,"error":"rejected"}'
                except Exception as error:
                    # Keep local role failures observable without exposing messages, paths or the request.
                    print("maker handler failed (" + type(error).__name__ + ")", file=sys.stderr, flush=True)
                    body = b'{"ok":false,"error":"unavailable"}'
                worker.stdin.write(_frame(dict(token=row["token"], body=_b64(body))))
                worker.stdin.flush()
        finally:
            worker.terminate()
