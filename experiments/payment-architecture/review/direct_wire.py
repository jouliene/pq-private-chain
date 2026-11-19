"""Read the trusted DLF1 verifier dimensions and independently walk the public proof words."""
import argparse
import hashlib
import io
import json
import struct
from pathlib import Path

P = 2**64 - 2**32 + 1


class Wire(io.BytesIO):
    def take(self, size):
        data = self.read(size)
        if len(data) != size:
            raise ValueError('truncated field or vector')
        return data

    def integer(self, size=8):
        return int.from_bytes(self.take(size), 'little')

    def words(self, count):
        values = struct.unpack(f'<{count}Q', self.take(8 * count))
        if any(v >= P for v in values):
            raise ValueError('noncanonical field word')
        return values

    def path(self, height):
        if self.integer(1) != height:
            raise ValueError('unexpected Merkle path depth')
        self.words(4 * height)


def fri(rd):
    return [rd.integer(w) for w in (8, 8, 8, 4, 1, 8, 8)]


def dimensions(raw):
    rd = Wire(raw)
    assert rd.integer() == 4
    rd.words(4 * 17)
    assert [rd.integer() for _ in range(6)] == [135, 60, 2, 128, 2, 8]
    assert rd.take(2) == b'\x01\x01'
    assert fri(rd) == [5, 4, 26, 0, 1, 2, 3]
    trace = rd.integer()
    assert fri(rd) == [5, 4, 26, 0, 1, 2, 3]
    count = rd.integer()
    assert 0 < count < 32
    folds = [rd.integer() for _ in range(count)]
    degree = rd.integer()
    assert rd.integer(1) == 1 and rd.integer() == degree and trace == degree
    assert folds == [2] * ((degree - 3 + 1) // 2)
    rd.take(8 * rd.integer())
    rd.take(16 * rd.integer())
    quotient, constraints, constants, public_inputs = [rd.integer() for _ in range(4)]
    assert public_inputs == 26 and rd.integer() == 60
    rd.words(60)
    partial, lookup = rd.integer(), rd.integer()
    assert lookup == rd.integer() == rd.integer() == 0
    final_len = 1 << (degree - sum(folds))
    hidden_openings = 26 * (1 + 2 * (sum((1 << f) - 1 for f in folds) + final_len))
    rows = (hidden_openings + 2) + 2 * (hidden_openings + 4)
    return dict(verifier_sha256=hashlib.sha256(raw).hexdigest(), verifier_B=len(raw),
                degree_bits=degree, lde_points=1 << (degree + 5), folds=folds, final_len=final_len,
                regular_mask_rows=hidden_openings + 2, paired_product_rows=hidden_openings + 4,
                total_mask_rows=rows, quotient=quotient, constraints=constraints, constants=constants,
                partial=partial, public_inputs=public_inputs)


def parse_packet(data, params):
    packet = Wire(data)
    assert packet.take(5) == b'DLF1\x01'
    proof_size = packet.integer(4)
    raw = packet.take(proof_size)
    assert len(packet.read()) == 2 * 1792
    rd = Wire(raw)
    folds = params['folds']
    oracles = [params['constants'] + 60, 135, 2 * (1 + params['partial']), 2 * params['quotient']]
    rd.words(3 * 16 * 4)
    # Each registered oracle polynomial is opened as one quadratic-extension value.
    # Two product polynomials have a second opening at g*zeta.
    rd.words(2 * (sum(oracles) + 2))
    rd.words(16 * 4 * len(folds))
    salts = set()
    for _ in range(26):
        depth = params['degree_bits'] + 5 - 4
        for index, width in enumerate(oracles):
            rd.words(width)
            if index:
                salt = rd.words(4)
                if not any(salt):
                    raise ValueError('all-zero observed salt')
                salts.add(salt)
            rd.path(depth)
        for fold in folds:
            rd.words(2 * (1 << fold))
            depth -= fold
            rd.path(depth)
    rd.words(2 * params['final_len'] + 1)
    assert rd.integer() == 26
    pi = rd.words(26)
    assert not rd.read() and pi[21] == 3
    return dict(packet_sha256=hashlib.sha256(data).hexdigest(), proof_B=proof_size, packet_B=len(data),
                anchor_height=pi[4], fee=pi[21], merkle_paths=26 * (4 + len(folds)),
                observed_nonzero_salt_tuples=26 * 3, distinct_salt_tuples=len(salts))


def declared_size(p):
    # Model every fixed-width primitive including the one-byte Merkle path lengths.
    oracle_words = p['constants'] + 60 + 135 + 2 * (1 + p['partial']) + 2 * p['quotient']
    depth = p['degree_bits'] + 5 - 4
    initial = 8 * (oracle_words + 3 * 4) + 4 * (1 + 32 * depth)
    reduction = 0
    for f in p['folds']:
        depth -= f
        reduction += 16 * (1 << f) + 1 + 32 * depth
    return (3 + len(p['folds'])) * 512 + 16 * (oracle_words + 2) + 26 * (initial + reduction) + 16 * p['final_len'] + 8 + 8 + 26 * 8


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('verifier', type=Path)
    ap.add_argument('packets', nargs='*', type=Path)
    args = ap.parse_args()
    profile = dimensions(args.verifier.read_bytes())
    payments = [parse_packet(path.read_bytes(), profile) for path in args.packets]
    expected = declared_size(profile)
    assert all(row['proof_B'] == expected for row in payments)
    print(json.dumps(dict(profile=profile, fixed_proof_B=expected, payments=payments), sort_keys=True, indent=2))
