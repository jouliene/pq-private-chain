"""Isolated devnet wallet interface. Wallet inventory and payment details stay on the local client."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct


ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT = ROOT / "experiments/advancing-payments"
PROFILE = "af88a0ac0caa5f0aa27d38d687b6cc39495a0aa2659ed4a7e5e74653724cc1b1"
MAX_VALUE = 2**62-1
FEE = 3

_spec = importlib.util.spec_from_file_location("pqdev_public_pipe", EXPERIMENT/"wire.py")
_wire = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_wire)


def checked_keys(keys):
    """Check every byte the wallet can load before mounting the directory read-only."""
    keys = Path(keys).resolve(strict=True)
    raw = (keys/"profile.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE:
        raise ValueError("incorrect APV2 registry")
    expected = {"profile.json"}
    for record,name in zip(json.loads(raw)["layers"],["leaf","wallet","outer2","outer3","outer4"],strict=True):
        if record["name"] != name:
            raise ValueError("unexpected APV2 circuit")
        for ext in ("common","vk","only"):
            p = keys/f"{name}.{ext}"
            if p.is_symlink() or hashlib.blake2b(p.read_bytes()).hexdigest() != record[ext+"_blake2b512"]:
                raise ValueError("incorrect APV2 circuit bytes")
            expected.add(p.name)
    if (keys/"profile.json").is_symlink() or {p.name for p in keys.iterdir()} != expected:
        raise ValueError("unexpected files in verifier registry")
    return keys


def private_directory(path, create=False):
    p = Path(path)
    if create:
        p.mkdir(mode=0o700, parents=True, exist_ok=True)
    m = p.lstat()
    if not stat.S_ISDIR(m.st_mode) or m.st_uid != os.geteuid() or m.st_mode & 0o077:
        raise ValueError("wallet directory must be owned by this user and mode 0700")
    return p.resolve(strict=True)


def _pages(blob, stride):
    if len(blob)%stride:
        raise ValueError("incomplete selected history record")
    step = 192*1024//stride*stride
    for i in range(0,len(blob),step):
        yield blob[i:i+step]
    yield b""


class Wallet:
    def __init__(self, binary, binary_sha, keys, private_dir, mode="restore"):
        if mode not in ("restore","create"):
            raise ValueError("expected create or restore")
        private = private_directory(private_dir,create=mode=="create")
        self.metrics = []
        self.history = []
        self.last_payment = None
        self.scanned = False
        self.role = _wire.Role(binary,binary_sha,["wallet","/keys","/private/seed",mode],
                               checked_keys(keys),private=private)
        try:
            self.address = self.role.get()
            if len(self.address)!=1601:
                raise ValueError("wallet address initialization failed")
            self.spend_pk = self.address[1:33]
        except BaseException:
            self.role.abort()
            raise

    def scan(self, header, leaves, rewards, receipts, nfs):
        """Replace local inventory with the full authenticated selected-tip view from the trusted node."""
        self.scanned = False
        self.history = []
        self.last_payment = None
        if len(header)!=132:
            raise ValueError("expected a 132-byte anchor header")
        streams = ((leaves,32),(rewards,104),(receipts,1824),(nfs,32))
        if any(len(blob)%stride for blob,stride in streams):
            raise ValueError("incomplete selected history")
        self.role.send(b"S"+header)
        for blob,stride in streams:
            for page in _pages(blob,stride):
                self.role.send(page)
        b = self.role.get()
        if not b.startswith(b"SCAN") or (len(b)-4)%42:
            raise ValueError("invalid selected history")
        kinds = {1:"reward",2:"incoming",3:"change"}
        for i in range(4,len(b),42):
            value,kind,spent = struct.unpack_from("<QBB",b,i+32)
            if kind not in kinds or spent not in (0,1):
                raise ValueError("invalid wallet inventory")
            self.history.append(dict(commitment=b[i:i+32].hex(),amount=value,
                                     source=kinds[kind],spent=bool(spent)))
        self.scanned = True
        live = [row for row in self.history if not row["spent"] and row["amount"]>0]
        return dict(balance=sum(row["amount"] for row in live), notes=len(live),
                    reward_notes=sum(x["source"]=="reward" for x in live),
                    receipt_notes=sum(x["source"] in ("incoming","change") for x in live),
                    incoming_notes=sum(x["source"]=="incoming" for x in live),
                    change_notes=sum(x["source"]=="change" for x in live))

    def pay(self, amount, to):
        self.last_payment = None
        if not self.scanned:
            raise ValueError("scan selected history first")
        if type(amount) is not int or not 0<amount<=MAX_VALUE:
            raise ValueError("amount must be an integer in the positive 62-bit range")
        if len(to)!=1601:
            raise ValueError("invalid address")
        raw = self.role.call(b"P"+struct.pack("<Q",amount),to)
        if not raw.startswith(b"PAY1"):
            known = (b"invalid amount",b"invalid address",b"insufficient funds within two inputs",b"scan selected history first")
            raise ValueError(raw.decode() if raw in known else "wallet proving failed")
        total, count = struct.unpack_from("<QB",raw,4)
        packet = raw[13:]
        _wire.need(_wire.packet_width(packet)==1 and 1<=count<=2 and total>=amount+FEE,
                   "invalid local payment response")
        self.last_payment = dict(amount=amount,fee=FEE,input_total=total,change=total-amount-FEE,real_inputs=count)
        return packet

    def close(self):
        if not self.role.closed:
            self.metrics = self.role.close()
        return self.metrics

    def __enter__(self):
        return self

    def __exit__(self,*_):
        self.close()
