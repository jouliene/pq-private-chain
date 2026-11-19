"""Read a complete live TKN1 packet; verify it with local operator code and independent receipt primitives."""
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT / 'experiments/payment-architecture/review'),
                str(ROOT / 'experiments/advancing-payments/review'),
                str(ROOT / 'experiments/advancing-payments')]
from direct_wire import dimensions, parse_packet
from public_chain import reference
from wire import Role

VK = 'f4b865c6c2aaa9afdd6a7a7ecb94fe9b76ffdc75d25d5a570cf595d315576c2b'


@dataclass(frozen=True)
class Effect:
    txid: str
    anchor: bytes
    height: int
    nullifiers: tuple
    commitments: tuple
    fee: int
    receipt_digest: bytes
    receipt_pair: bytes

    def transition(self):
        return b''.join((*self.nullifiers, *self.commitments, struct.pack('<Q', self.fee)))


class PublicVerifier:
    def __init__(self, binary, binary_sha, keys, roots):
        key = (keys / 'token.vk').read_bytes()
        assert sha256(key).hexdigest() == VK
        self.layout = dimensions(key)
        self.roots = roots
        self.role = Role(binary, binary_sha, ['verify', '/keys'], keys)
        self.checked = {}

    def read(self, raw):
        txid = sha256(raw).hexdigest()
        if txid in self.checked:
            return self.checked[txid]
        assert raw[:5] == b'TKN1\x01'
        # TKN1 has the identical FRI wire grammar. Its actual tag and VK go into the independent native call.
        parsed = parse_packet(b'DLF1' + raw[4:], self.layout)
        proof_bytes = parsed['proof_B']
        end = 9 + proof_bytes
        pi = raw[end-208:end]
        receipt = raw[end:]
        assert len(receipt) == 3584 and raw[end-216:end-208] == struct.pack('<Q', 26)
        assert reference(self.roots, ['--ciphertext-digests'], receipt) == [pi[-32:].hex()]
        assert self.role.call(raw) == b'1' + pi[:36] + pi[40:176] + receipt
        effect = Effect(txid, pi[:32], int.from_bytes(pi[32:40], 'little'),
                        (pi[40:72], pi[72:104]), (pi[104:136], pi[136:168]),
                        int.from_bytes(pi[168:176], 'little'), pi[-32:], receipt)
        assert effect.fee == 3 and len(set(effect.nullifiers)) == len(set(effect.commitments)) == 2
        self.checked[txid] = effect
        return effect

    def __enter__(self):
        return self

    def __exit__(self, exc_type, *ignored):
        try:
            if exc_type is None:
                self.role.close()
        finally:
            self.role.abort()


def compare(a, b):
    shared = set(a.nullifiers) & set(b.nullifiers)
    return dict(same_packet=a.txid == b.txid, same_anchor=a.anchor == b.anchor,
                first_height=a.height, second_height=b.height, shared_nf=len(shared),
                same_nf_positions=[i for i in (0, 1) if a.nullifiers[i] == b.nullifiers[i]],
                shared_outputs=len(set(a.commitments) & set(b.commitments)),
                same_receipt_digest=a.receipt_digest == b.receipt_digest)
