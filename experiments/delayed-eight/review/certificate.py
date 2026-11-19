"""Read registered outer FRI dimensions and match a public D8C1 envelope to its DLF1 sources."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[2] / 'experiments/payment-architecture/review'))
from direct_wire import Wire, fri
from ledger import effect, sid, public_packet, reference


def layout(verifier):
    rd = Wire(verifier)
    assert rd.integer() == 4
    rd.words(4 * 17)
    assert [rd.integer() for _ in range(6)] == [135, 60, 2, 128, 2, 8]
    assert rd.take(2) == b'\x01\x00' and fri(rd) == [5, 4, 26, 0, 1, 2, 3]
    trace = rd.integer()
    assert fri(rd) == [5, 4, 26, 0, 1, 2, 3]
    n = rd.integer()
    assert 0 < n <= 16
    folds = [rd.integer() for _ in range(n)]
    degree = rd.integer()
    assert rd.integer(1) == 0 and rd.integer() == degree == trace
    assert folds == [2] * ((degree - 2) // 2)
    rd.take(8 * rd.integer()); rd.take(16 * rd.integer())
    quotient, constraints, constants, pi = [rd.integer() for _ in range(4)]
    assert pi == 210 and rd.integer() == 60
    rd.words(60)
    partial = rd.integer()
    assert rd.integer() == rd.integer() == rd.integer() == 0
    return dict(vk_sha256=sha256(verifier).hexdigest(), degree_bits=degree, lde_points=1 << (5 + degree),
                folds=folds, final_len=1 << (degree - sum(folds)), constraints=constraints,
                initial_oracle_words=[60 + constants, 135, 2 * (1 + partial), 2 * quotient], public_words=pi)


def size(params):
    folds = params['folds']
    words = sum(params['initial_oracle_words'])
    depth = params['degree_bits'] + 5 - 4
    query = 8 * words + 4 * (1 + 32 * depth)
    for fold in folds:
        depth -= fold
        query += 16 * (1 << fold) + 1 + 32 * depth
    return (3 + len(folds)) * 512 + 16 * (words + 2) + 26 * query + 16 * params['final_len'] + 16 + 8 * params['public_words']


def read_certificate(cert, params, roots=None):
    rd = Wire(cert)
    assert rd.take(4) == b'D8C1'
    k = rd.integer(1)
    assert 1 <= k <= 8 and rd.integer(4) == size(params)
    proof = Wire(rd.take(size(params)))
    receipt = [rd.take(3584) for _ in range(k)]
    assert rd.read() == b''
    depth = params['degree_bits'] + 5 - 4
    folds = params['folds']
    proof.words(3 * 16 * 4 + 2 * (sum(params['initial_oracle_words']) + 2) + 16 * 4 * len(folds))
    for _ in range(26):
        for w in params['initial_oracle_words']:
            proof.words(w)
            proof.path(depth)
        child = depth
        for f in folds:
            proof.words(2 * (1 << f)); child -= f; proof.path(child)
    proof.words(2 * params['final_len'] + 1)
    assert proof.integer() == 210 and proof.integer() == 0x443843310001 and proof.integer() == k
    rows = [struct.pack('<26Q', *proof.words(26)) for _ in range(8)]
    assert not proof.read() and all(p == rows[k - 1] for p in rows[k:])
    if roots is not None:
        assert reference(roots, ['--ciphertext-digests'], b''.join(receipt)) == [p[-32:].hex() for p in rows[:k]]
    values = [effect(p, ct) for p, ct in zip(rows[:k], receipt, strict=True)]
    return values


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('vk', type=Path)
    p.add_argument('--cert', type=Path)
    p.add_argument('--roots', type=Path)
    p.add_argument('--packets', nargs='+', type=Path)
    a = p.parse_args()
    params = layout(a.vk.read_bytes())
    result = dict(profile=params, proof_B=size(params))
    if a.cert:
        assert a.roots, 'require independent receipt primitive when decoding actual bytes'
        cert = a.cert.read_bytes()
        rows = read_certificate(cert, params, a.roots.resolve())
        if a.packets:
            assert [public_packet(f.read_bytes())[0] for f in a.packets] == rows
        result.update(certificate_B=len(cert), sha256=sha256(cert).hexdigest(), real=len(rows),
                      public_ids=[sid(row).hex() for row in rows], matched_source_packets=len(a.packets or []))
    print(json.dumps(result, sort_keys=True, indent=2))
