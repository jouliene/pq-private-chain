"""One bounded loopback request/reply per connection. Binary bodies are never JSON encoded."""
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import struct

MAX_FRAME = 2**21
MAX_META = 16384
TIMEOUT = 30


def frame(metadata, body=b""):
    encoded = json.dumps(metadata, separators=(",", ":"), allow_nan=False).encode()
    size = 4 + len(encoded) + len(body)
    if size > MAX_FRAME or len(encoded) > MAX_META:
        raise ValueError("oversized frame")
    return struct.pack("!II", size, len(encoded)) + encoded + body


def unpack(payload):
    if len(payload) < 4:
        raise ValueError("short message")
    n, = struct.unpack_from("!I", payload)
    if not 1 <= n <= min(MAX_META, len(payload)-4):
        raise ValueError("metadata size")
    meta = json.loads(payload[4:4+n])
    if not isinstance(meta, dict):
        raise ValueError("metadata type")
    return meta, payload[4+n:]


def length(header):
    n, = struct.unpack("!I", header)
    if not 5 <= n <= MAX_FRAME:
        raise ValueError("frame length")
    return n


def control(home, node):
    base = Path("/tmp") / ("pqdev-control-" + str(os.getuid()))
    base.mkdir(mode=0o700, exist_ok=True)
    info = base.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("unsafe control directory")
    ident = hashlib.sha256(os.fsencode(Path(home).resolve())).hexdigest()[:32]
    if node not in ("a","b","c","d"):
        raise ValueError("node name")
    return base / (ident + "-" + node + ".sock")


def rpc(address, op, body=b"", *, meter=None, **params):
    family = socket.AF_INET if type(address) is int else socket.AF_UNIX
    endpoint = ("127.0.0.1", address) if family == socket.AF_INET else str(address)
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(TIMEOUT)
        sock.connect(endpoint)
        outgoing=frame(dict(op=op, **params), body)
        sock.sendall(outgoing)
        with sock.makefile("rb") as stream:
            hdr = stream.read(4)
            if len(hdr) != 4:
                raise ConnectionError("peer closed before reply")
            size = length(hdr)
            buf = stream.read(size)
            if len(buf) != size:
                raise ConnectionError("partial frame")
    if meter is not None:
        meter.update(request_B=len(outgoing),reply_B=4+len(buf))
    meta, response = unpack(buf)
    if meta.get("ok") is not True:
        raise ValueError(meta.get("error","peer rejected request"))
    return meta["result"], response
