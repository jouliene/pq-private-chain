"""Reconstruct the old public block grammar and price 100M inclusions independently."""
from __future__ import annotations

import hashlib
import json
from fractions import Fraction
from pathlib import Path

BASE = Path(__file__).resolve().parents[3]
REFERENCE = BASE / 'devnet/evidence/author'
INCLUSIONS = 100_000_000
SECONDS = 365 * 24 * 3600
LIMITS = (10_000, 50_000)
RECEIPTS = 2 * 1792


def read_selected():
    result = json.loads((REFERENCE / 'RESULT.json').read_bytes())
    occupancy = [0] * 5
    proof_sizes = set()
    total_bytes = 0
    for height, label in enumerate(result['winning'], 1):
        raw = (REFERENCE / 'blocks' / (label + '.bin')).read_bytes()
        seed = hashlib.sha256(b'PQDEV1/template\x00' + raw[:-8]).digest()
        assert hashlib.sha256(b'PQDEV1/work\x00' + seed + raw[-8:]).hexdigest() == label
        assert raw[:8] == b'PQDEVBL1' and int.from_bytes(raw[73:77], 'little') == height
        count = raw[213]
        occupancy[count] += 1
        index = 214
        for _ in range(count):
            length = int.from_bytes(raw[index:index + 4], 'little')
            packet = raw[index + 4:index + 4 + length]
            assert packet[:5] == b'APV2\x01' and len(packet) == length
            proof = int.from_bytes(packet[5:9], 'little')
            assert proof + RECEIPTS + 9 == length
            proof_sizes.add(proof)
            index += 4 + length
        assert index + 8 == len(raw)
        total_bytes += len(raw)
    assert len(proof_sizes) == 1
    return occupancy, total_bytes, proof_sizes.pop()


def occupancy_cost(counts, proof):
    blocks = sum(counts)
    payments = sum(width * count for width, count in enumerate(counts))
    paid = blocks - counts[0]
    overhead = Fraction(222 * blocks, payments) + 4 + 9 + RECEIPTS
    archive = overhead + proof
    interval = Fraction(SECONDS * payments, INCLUSIONS * blocks)
    return dict(block_mix_0_to_4=counts, payments_per_paid_block=str(Fraction(payments, paid)),
                payments_per_block=str(Fraction(payments, blocks)),
                full_singleton_archive_TB=round(float(archive * INCLUSIONS / 10**12), 9),
                allowable_singleton_proof_B_floor=[int(limit - overhead) for limit in LIMITS],
                opportunity_interval_s_for_100M=round(float(interval), 9),
                mean_eight_opportunity_window_s=round(float(8 * interval), 9))


def result():
    observed, size, proof = read_selected()
    cases = dict(singleton=[0, 1, 0, 0, 0], all_full=[0, 0, 0, 0, 1],
                 sparse=[100, 85, 10, 4, 1], busy=[100, 45, 90, 135, 630], observed=observed)
    return dict(measured_selected_B=size, measured_singleton_proof_B=proof,
                submitted_B=proof + RECEIPTS + 9, maximum_direct_per_year_at_2s=SECONDS * 4 // 2,
                synthetic_four_payment_one_packet_proof_budget_B=[4 * (n - RECEIPTS) - 9 - 4 - 222 for n in LIMITS],
                scenarios={name: occupancy_cost(counts, proof) for name, counts in cases.items()})


if __name__ == '__main__':
    print(json.dumps(result(), sort_keys=True, indent=2))
