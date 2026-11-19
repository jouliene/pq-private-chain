"""Operator-pinned, public-only recursive certificate roles with no wallet mount or network."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
spec=importlib.util.spec_from_file_location("eight_pipe",ROOT/"experiments/advancing-payments/wire.py")
wire=importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)
STRIDE=3756
INNER="5d6cfc6ccff5792e4899799124b2fb1e7dac50f727825c4886485dc01a564ce8"


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def checked_keys(directory):
    directory=Path(directory).resolve(strict=True)
    pins=json.loads((HERE/"registry.json").read_bytes())["key_sha256"]
    if set(pins)!={"direct.vk","eight.vk"} or pins["direct.vk"]!=INNER:
        raise ValueError("incorrect operator registry schema")
    keys={p.name:sha(p) for p in directory.iterdir() if p.is_file() and not p.is_symlink()}
    if not keys==pins or {p.name for p in directory.iterdir()}!=set(pins):
        raise ValueError("unapproved certificate verifier material")
    return directory


class _Role:
    mode=None

    def __init__(self,binary,binary_sha,keys):
        self.meters=[]
        self.role=wire.Role(binary,binary_sha,[self.mode,"/keys"],checked_keys(keys))
        try:
            if self.role.get()!=b"READY":
                raise ValueError("certificate role initialization")
        except BaseException:
            self.role.abort()
            raise

    def __enter__(self):
        return self

    def __exit__(self,*_):
        self.meters=self.role.close()


class CertificateVerifier(_Role):
    mode="verify"

    def verify(self,raw):
        if len(raw)<9 or raw[:4]!=b"D8C1" or not 1<=raw[4]<=8:
            raise ValueError("certificate packet framing")
        result=self.role.call(raw)
        if len(result)!=1+raw[4]*STRIDE or result[0:1]!=b"1":
            raise ValueError("invalid recursive certificate")
        return [result[i:i+STRIDE] for i in range(1,len(result),STRIDE)]


class CertificateBuilder(_Role):
    mode="builder"

    def prove(self,packets):
        items=list(packets)
        if not 1<=len(items)<=8 or any(not p.startswith(b"DLF1\x01") for p in items):
            raise ValueError("expected one to eight direct packets")
        result=self.role.call(bytes([len(items)]),*items)
        if len(result)<9 or result[:5]!=b"D8C1"+bytes([len(items)]):
            raise ValueError("rejected direct source packets")
        return result
