"""Canonical MSP1 transaction wrapper and managed issuance authorization message."""
from dataclasses import dataclass
from hashlib import sha256
import struct

MAGIC = b"MSP1\x01"
INNER = b"MNG1\x01"
ZERO = bytes(32)
BURN = 1 << 62
LIMIT = BURN - 1
SIGNATURE_BYTES = 17088
OPERATIONS = ("transfer", "fixed", "register", "mint", "burn")
SIGNED = ("register", "mint")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def tag(digest):
    return struct.pack("<4Q", *(x & ((1 << 63)-1) for x in struct.unpack("<4Q",digest)))


def managed_id(network, public_key, nf0):
    require(len(network)==len(public_key)==len(nf0)==32, "managed ID inputs")
    return tag(sha256(b"MNG1/managed-id/v1\0"+network+public_key+nf0).digest())


def authorization_digest(inner, operation, network, public_key, sequence, previous):
    require(operation in SIGNED and len(network)==len(public_key)==len(previous)==32
            and 0 <= sequence < 2**63, "issuer statement")
    return sha256(b"MNG1/supply-auth/v1\0"+network+bytes([OPERATIONS.index(operation)])+
                  public_key+struct.pack("<Q",sequence)+previous+sha256(inner).digest()).digest()


def check_inner(inner):
    require(len(inner)>=9 and inner[:5]==INNER, "inner payment frame")
    proof_size = int.from_bytes(inner[5:9],"little")
    require(proof_size>0 and len(inner)==9+proof_size+3584, "inner payment size")


def wrap(inner, operation, network, *, public_key=b"", sequence=0, previous=ZERO, sign=None):
    check_inner(inner)
    require(operation in OPERATIONS, "unknown supply operation")
    head = MAGIC+bytes([OPERATIONS.index(operation)])
    if operation in SIGNED:
        signature = sign(authorization_digest(inner,operation,network,public_key,sequence,previous))
        require(len(signature)==SIGNATURE_BYTES, "issuer signature width")
        head += public_key+struct.pack("<Q",sequence)+previous+signature
    else:
        require(not public_key and not sequence and previous==ZERO and sign is None, "unexpected authority")
    return head+inner


@dataclass(frozen=True)
class Envelope:
    operation: str
    public_key: bytes
    sequence: int
    previous: bytes
    signature: bytes
    inner: bytes


def parse(packet):
    require(6 < len(packet) <= 262144 and packet.startswith(MAGIC) and packet[5]<len(OPERATIONS),
            "managed packet")
    op = OPERATIONS[packet[5]]
    if op in SIGNED:
        offset = 78+SIGNATURE_BYTES
        require(len(packet)>offset, "issuer envelope length")
        pk,seq,prev,sig = packet[6:38],int.from_bytes(packet[38:46],"little"),packet[46:78],packet[78:offset]
        require(seq<2**63,"issuer revision bounds")
    else:
        offset,pk,seq,prev,sig = 6,b"",0,ZERO,b""
    inner = packet[offset:]
    check_inner(inner)
    return Envelope(op,pk,seq,prev,sig,inner)


def packet_width(raw):
    if raw.startswith(b"AST1\x01"):
        size = int.from_bytes(raw[5:9],"little")
        require(size>0 and len(raw)==9+size+3584 and len(raw)<=262144, "historical AST1 frame")
    else:
        parse(raw)
    return 1
