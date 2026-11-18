"""Canonical public formats, bounded local process frames and source-selected runtime roles."""
from __future__ import annotations

import importlib.util
import hashlib
import os
from pathlib import Path
import re
import resource
import struct
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
bridge_spec=importlib.util.spec_from_file_location("wallet_bridge", HERE.parent/"wallet-created/wallet/bridge.py")
bridge=importlib.util.module_from_spec(bridge_spec)
bridge_spec.loader.exec_module(bridge)
libraries=bridge.libraries

LIMIT = 8 * 1024 * 1024
P = 2**64 - 2**32 + 1
CT = 1792
ZERO = bytes(32)


def need(ok, label):
    if not ok:
        raise ValueError(label)


def u32(n):
    return struct.pack("<I", n)


def u64(n):
    return struct.pack("<Q", n)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(word):
    return len(word) == 32 and all(x < P for x in struct.unpack("<4Q", word))


def digest(domain, *parts):
    prefix = b"advancing-payments/1/" + domain + b"\x00"
    seed = prefix + b"".join(u64(len(part)) + part for part in parts)
    for i in range(2**32):
        word = hashlib.sha3_256(seed + u32(i)).digest()
        if canonical(word):
            return word
    raise ValueError("hash rejection counter exhausted")


def pieces(data, size):
    need(len(data) % size == 0, "alignment")
    return [data[i:i+size] for i in range(0, len(data), size)]


def check_genesis(data, approved):
    need(sha(data) == approved and data[:8] == b"APGEN001" and len(data) >= 12, "authorized genesis")
    words = pieces(data[12:], 32)
    need(1 <= len(words) <= 16384 and u32(len(words)) == data[8:12], "genesis count")
    need(len(set(words)) == len(words) and all(canonical(v) and v != ZERO for v in words), "genesis leaves")
    return words


def packet_width(raw):
    need(len(raw) >= 9 and raw[:4] == b"APV2" and 1 <= raw[4] <= 4, "payment packet")
    width = raw[4]
    n, = struct.unpack_from("<I", raw, 5)
    need(0 < n and len(raw) == 9+n+width*2*CT and len(raw) <= LIMIT, "payment length")
    return width


def header_parts(header):
    need(len(header) == 132, "header width")
    words = (header[:32], header[36:68], header[68:100], header[100:132])
    need(all(canonical(w) for w in words), "header canonicality")
    return words[0], int.from_bytes(header[32:36], "little"), *words[1:]


def split_block(raw):
    need(len(raw) >= 152 and len(raw) <= LIMIT+152 and raw[:8] == b"APBLOCK1", "block framing")
    nonce, n = struct.unpack_from("<QI", raw, 140)
    need(len(raw) == 152+n, "block length")
    hdr = raw[8:140]
    header_parts(hdr)
    return hdr, nonce, raw[152:]


class Role:
    """One binary in its own network/mount/PID namespace; only a wallet sees its private backup directory."""
    def __init__(self, binary, identity, args, keys=None, private=None, keys_writable=False):
        binary = Path(binary).resolve(strict=True)
        need(sha(binary.read_bytes()) == identity, "approved executable")
        cmd = ["bwrap","--unshare-all","--die-with-parent","--new-session","--cap-drop","ALL",
               "--clearenv","--setenv","LANG","C","--setenv","RAYON_NUM_THREADS","2",
               "--dev","/dev","--proc","/proc","--ro-bind",str(binary),"/native"]
        for lib in libraries(binary):
            cmd += ["--ro-bind", str(lib.resolve()), str(lib)]
        if keys is not None:
            cmd += ["--bind" if keys_writable else "--ro-bind", str(Path(keys).resolve(strict=True)), "/keys"]
        if private is not None:
            need(args[0] == "wallet", "private mount owner")
            cmd += ["--bind",str(Path(private).resolve(strict=True)),"/private"]
        cmd += ["--remount-ro","/","--chdir","/","--","/native",*args]
        self.errors = tempfile.TemporaryFile()
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.errors)
        self.name = args[0]
        self.sizes = [0, 0]
        self.times = []
        self.closed = False

    def send(self, payload):
        need(len(payload) <= LIMIT, "local frame size")
        self.proc.stdin.write(u32(len(payload)) + payload)
        self.proc.stdin.flush()
        self.sizes[0] += 4 + len(payload)

    def get(self):
        hdr = self.proc.stdout.read(4)
        need(len(hdr) == 4, "failed public frame from " + self.name)
        n, = struct.unpack("<I",hdr)
        need(n <= LIMIT, "local output limit")
        data = self.proc.stdout.read(n)
        need(len(data) == n, "short " + self.name)
        self.sizes[1] += n+4
        return data

    def call(self, *frames):
        start = time.monotonic()
        for frame in frames:
            self.send(frame)
        response = self.get()
        self.times.append(time.monotonic()-start)
        return response

    def close(self, graceful=True):
        if self.closed:
            return []
        self.closed=True
        try:
            if graceful and self.proc.poll() is None:
                self.send(b"")
            self.proc.stdin.close()
            self.proc.wait(timeout=30)
            need(self.proc.returncode == 0, "role exit " + self.name)
            self.errors.seek(0)
            meters = []
            for line in self.errors.read(1<<20).splitlines():
                m = re.fullmatch(rb"METER ([a-z0-9_]+) ([\d.]+) ([\d.]+) (\d+)", line)
                need(m is not None, "unrecognized role diagnostic " + self.name)
                meters.append(dict(operation=m[1].decode(),elapsed_s=float(m[2]),cpu_s=float(m[3]),peak_rss_kib=int(m[4])))
            return meters
        finally:
            if self.proc.poll() is None:
                self.proc.kill()
                self.proc.wait()
            self.errors.close()
            self.proc.stdout.close()

    def abort(self):
        if not self.closed:
            self.proc.kill()
            self.proc.wait()
            self.proc.stdin.close()
            self.proc.stdout.close()
            self.errors.close()
            self.closed=True
