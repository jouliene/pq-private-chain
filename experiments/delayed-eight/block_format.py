"""D8 PoW identities. Direct proof encodings are transport attachments to the ordered core."""
from hashlib import sha3_256
import struct

CT = 1792
EFFECT_SIZE = 172 + 2 * CT
COMPACT = b"D8E1"
MAGIC = b"D8POW001"


def effects(packet):
    # Parsing the public statement for identity never authorizes it. The node verifies
    # the complete DLF1 proof or a registered certificate before applying any effect.
    if packet[:4] == COMPACT and len(packet) == 4 + EFFECT_SIZE:
        return packet[4:]
    if len(packet) < 9 or packet[:5] != b"DLF1\x01":
        raise ValueError("DLF1 singleton framing")
    size = int.from_bytes(packet[5:9], "little")
    if size < 208 or len(packet) != 9 + size + 2 * CT:
        raise ValueError("DLF1 proof or receipt length")
    pi = packet[9+size-208:9+size]
    height = int.from_bytes(pi[32:40], "little")
    if height >= 2**32:
        raise ValueError("DLF1 height")
    return pi[:32] + struct.pack("<I", height) + pi[40:176] + packet[-2*CT:]


def identity(network, packet):
    return sha3_256(b"D8/payment/v1\0" + network + effects(packet)).digest()


def id_vector(network, vector):
    if not vector or vector[0] > 4:
        raise ValueError("D8 core count")
    ids = []
    offset = 1
    for _ in range(vector[0]):
        if offset + 4 > len(vector):
            raise ValueError("truncated D8 attachment")
        size = int.from_bytes(vector[offset:offset+4], "little")
        offset += 4
        if size > 262144 or offset + size > len(vector):
            raise ValueError("D8 attachment length")
        ids.append(identity(network, vector[offset:offset+size]))
        offset += size
    if offset != len(vector):
        raise ValueError("trailing D8 attachments")
    return vector[:1] + b"".join(ids)


def core(network, raw):
    if not 222 <= len(raw) <= 1048814 or raw[:8] != MAGIC or raw[8:40] != network:
        raise ValueError("D8 block format")
    return raw[:213] + id_vector(network, raw[213:-8]) + raw[-8:]
